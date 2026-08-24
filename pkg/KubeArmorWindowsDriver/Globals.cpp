// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor


#include "Globals.h"

// ============================================
// Helper: allocate and initialize a hash table
// ============================================

static PRULE_HASH_TABLE AllocateHashTable() {
    PRULE_HASH_TABLE table = (PRULE_HASH_TABLE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(RULE_HASH_TABLE), RULE_TABLE_TAG);
    if (!table)
        return NULL;
    for (int i = 0; i < NUM_BUCKETS; ++i) {
        InitializeListHead(&table->Buckets[i]);
    }
    return table;
}

// Helper: destroy all entries in a hash table and free it
static VOID DestroyHashTable(PRULE_HASH_TABLE table) {
    if (!table)
        return;
    for (int i = 0; i < NUM_BUCKETS; ++i) {
        PLIST_ENTRY head = &table->Buckets[i];
        while (!IsListEmpty(head)) {
            PRULE_ENTRY rule = CONTAINING_RECORD(
                RemoveHeadList(head), RULE_ENTRY, ListEntry);
            FreeRuleEntry(rule);
        }
    }
    ExFreePoolWithTag(table, RULE_TABLE_TAG);
}

// Helper: clear all entries from a hash table (without freeing the table itself)
static VOID ClearHashTable(PRULE_HASH_TABLE table) {
    if (!table)
        return;
    for (int i = 0; i < NUM_BUCKETS; ++i) {
        PLIST_ENTRY head = &table->Buckets[i];
        while (!IsListEmpty(head)) {
            FreeRuleEntry(CONTAINING_RECORD(
                RemoveHeadList(head), RULE_ENTRY, ListEntry));
        }
    }
}

// Helper: look up a rule by suffix in a hash table (for process enforcement).
//
// Instead of scanning all NUM_BUCKETS, we walk the path right-to-left and at
// each backslash boundary extract the suffix as a UNICODE_STRING, compute its
// hash, and probe exactly one bucket. This reduces the search from
// O(NUM_BUCKETS × chain) to O(path_depth × chain).
//
// Boundary semantics: the character immediately before the matched suffix must
// be '\' (or we are at the start of the path). This prevents 'bad_notepad.exe'
// from matching a rule stored as 'notepad.exe'.
static PRULE_ENTRY LookupRuleBySuffix(PRULE_HASH_TABLE table, PUNICODE_STRING Path) {
    if (!Path || Path->Length == 0)
        return NULL;

    USHORT totalChars = Path->Length / sizeof(WCHAR);

    // Walk from right to left.  At each position that is either the start
    // of the string or immediately after a '\', probe the hash table with
    // the suffix starting at that position.
    for (USHORT i = totalChars; ; ) {
        // Find the next '\' scanning leftward (or reach start).
        while (i > 0 && Path->Buffer[i - 1] != L'\\')
            i--;

        // Suffix: Path->Buffer[i .. totalChars-1]
        UNICODE_STRING suffix;
        suffix.Buffer        = Path->Buffer + i;
        suffix.Length        = (totalChars - i) * sizeof(WCHAR);
        suffix.MaximumLength = suffix.Length;

        if (suffix.Length > 0) {
            ULONG hash  = HashPath(&suffix);
            ULONG index = hash % NUM_BUCKETS;

            PLIST_ENTRY head = &table->Buckets[index];
            for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
                PRULE_ENTRY rule = CONTAINING_RECORD(e, RULE_ENTRY, ListEntry);
                if (RtlEqualUnicodeString(&rule->Path, &suffix, TRUE))
                    return rule;
            }
        }

        if (i == 0)
            break;
        i--; // skip the '\' itself for the next iteration
    }
    return NULL;
}

// Helper: look up a rule in a hash table by path
static PRULE_ENTRY LookupRuleInTable(PRULE_HASH_TABLE table, PUNICODE_STRING Path) {
    ULONG hash = HashPath(Path);
    ULONG index = hash % NUM_BUCKETS;

    PLIST_ENTRY head = &table->Buckets[index];
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        PRULE_ENTRY rule = CONTAINING_RECORD(e, RULE_ENTRY, ListEntry);
        if (MatchPath(rule, Path)) {
            return rule;
        }
    }
    return NULL;
}

// ============================================
// Globals implementation
// ============================================

NTSTATUS Globals::Init() {
    // Initialize process rule table
    m_Table = AllocateHashTable();
    if (!m_Table) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    m_Lock.Init();
    m_ProcessWhitelist = 0;

    // Initialize file rule table
    m_FileRuleTable = AllocateHashTable();
    if (!m_FileRuleTable) {
        ExFreePoolWithTag(m_Table, RULE_TABLE_TAG);
        m_Table = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    m_FileRuleLock.Init();

    return STATUS_SUCCESS;
}

// ============================
// Process rule operations
// ============================

VOID Globals::DestroyRuleHashTable() {
    // Acquire lock so any concurrent LookupRule / InsertRule that squeezed
    // in before FltUnregisterFilter returned will finish before we free.
    // ExAcquireFastMutex requires IRQL <= APC_LEVEL; assert here so any
    // future caller that violates this is caught immediately in debug builds.
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> locker(m_Lock);
    DestroyHashTable(m_Table);
    m_Table = NULL;
}


BOOLEAN Globals::InsertRule(_In_ PUNICODE_STRING Path, _In_ RuleAction Action) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> locker(m_Lock);
    PRULE_ENTRY entry = AllocateRuleEntry(Path, Action, RULE_TYPE_PROCESS, MATCH_PATH, 0);
    if (!entry) 
    {
        return FALSE;
    }
    ULONG hash = HashPath(Path);
    ULONG index = hash % NUM_BUCKETS;
    if (Action == RuleAction::Allow) {
        m_ProcessWhitelist++;
    }

    InsertTailList(&m_Table->Buckets[index], &entry->ListEntry);
    return TRUE;
}

PRULE_ENTRY Globals::LookupRule(_In_ PUNICODE_STRING Path) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> locker(m_Lock);  // hold lock for entire lookup
    return LookupRuleBySuffix(m_Table, Path);
}

// LookupRuleAction — returns the action for a process rule path.
// Returns RuleAction::Audit if no rule is found (safe default).
// Holds m_Lock for the entire lookup so the entry cannot be freed
// concurrently by ClearAllRules.
RuleAction Globals::LookupRuleAction(_In_ PUNICODE_STRING Path) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> locker(m_Lock);
    PRULE_ENTRY entry = LookupRuleBySuffix(m_Table, Path);
    if (entry == nullptr)
        return RuleAction::Audit;  // no match → not blocked
    return entry->Action;
}

BOOLEAN Globals::RemoveRule(_In_ PUNICODE_STRING Path) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> lock(m_Lock);
    PRULE_ENTRY rule = LookupRuleInTable(m_Table, Path);
    if (!rule) 
        return FALSE;
    // Save action before freeing (fixes use-after-free bug)
    RuleAction savedAction = rule->Action;
    RemoveEntryList(&rule->ListEntry);
    FreeRuleEntry(rule);
    if (savedAction == RuleAction::Allow && m_ProcessWhitelist) {
        m_ProcessWhitelist--;
    }
    return TRUE;
}

// ============================
// File rule operations (new)
// ============================

BOOLEAN Globals::InsertFileRule(
    _In_ PUNICODE_STRING Path,
    _In_ RuleAction Action,
    _In_ MATCH_TYPE MatchType,
    _In_ USHORT Flags)
{
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> locker(m_FileRuleLock);

    // For directory rules, ensure the path ends with a backslash
    // so prefix matching works correctly.
    UNICODE_STRING normalizedPath;
    WCHAR normalizedBuffer[MAX_PATH_LENGTH];
    RtlInitEmptyUnicodeString(&normalizedPath, normalizedBuffer, sizeof(normalizedBuffer));
    RtlCopyUnicodeString(&normalizedPath, Path);

    if (MatchType == MATCH_DIRECTORY && normalizedPath.Length >= sizeof(WCHAR)) {
        WCHAR lastChar = normalizedPath.Buffer[(normalizedPath.Length / sizeof(WCHAR)) - 1];
        if (lastChar != L'\\') {
            // Append trailing backslash
            if (normalizedPath.Length + sizeof(WCHAR) <= normalizedPath.MaximumLength) {
                normalizedPath.Buffer[normalizedPath.Length / sizeof(WCHAR)] = L'\\';
                normalizedPath.Length += sizeof(WCHAR);
            }
        }
    }

    PRULE_ENTRY entry = AllocateRuleEntry(&normalizedPath, Action, RULE_TYPE_FILE, MatchType, Flags);
    if (!entry) {
        return FALSE;
    }
    ULONG hash = HashPath(&normalizedPath);
    ULONG index = hash % NUM_BUCKETS;

    InsertTailList(&m_FileRuleTable->Buckets[index], &entry->ListEntry);
    return TRUE;
}

PRULE_ENTRY Globals::LookupFileRule(_In_ PUNICODE_STRING Path) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> locker(m_FileRuleLock);

    // Phase 1: Exact-path hash lookup (fast path for MATCH_PATH rules)
    PRULE_ENTRY exactMatch = LookupRuleInTable(m_FileRuleTable, Path);
    if (exactMatch)
        return exactMatch;

    // Phase 2a: Hash-walk for MATCH_DIRECTORY rules.
    //
    // Walk the path left-to-right. At each backslash, extract the prefix
    // up to and including that backslash, hash it, and probe one bucket.
    // Iterating from shortest to longest means the last successful match
    // is automatically the most specific (longest) directory prefix.
    //
    // Example path:  \Device\HarddiskVolume3\Windows\Temp\debug.log
    // Prefixes tried: \  \Device\  \Device\HarddiskVolume3\  \Device\...\Windows\  ...
    //
    // O(path_depth × chain) vs. O(NUM_BUCKETS × chain) for the old full scan.
    PRULE_ENTRY bestDirMatch = NULL;

    if (Path->Length > 0) {
        USHORT totalChars = Path->Length / sizeof(WCHAR);

        // prefixBuf holds incrementally-built directory prefixes that are hashed
        // and probed against stored directory rules.  Rules are inserted via IOCTL
        // with paths capped at MAX_PATH_LENGTH WCHARs, so any prefix longer than
        // that can never match a stored rule — stop accumulating as soon as the
        // buffer is full.
        //
        // Without this guard a normalized NT path longer than MAX_PATH_LENGTH/2
        // chars (common for UWP / long-user-profile paths on Windows 11) writes
        // past the end of the stack array, clobbers the /GS cookie, and causes
        // KERNEL_SECURITY_CHECK_FAILURE (0x139).
        constexpr USHORT kPrefixBufChars =
            static_cast<USHORT>(MAX_PATH_LENGTH / sizeof(WCHAR));

        WCHAR  prefixBuf[kPrefixBufChars];
        USHORT prefixChars = 0;

        for (USHORT i = 0; i < totalChars; i++) {
            // Stop building prefixes once the buffer is full.  Any directory rule
            // in the driver is shorter than MAX_PATH_LENGTH (enforced by the IOCTL
            // handler), so no prefix at or beyond this length can ever match.
            if (prefixChars >= kPrefixBufChars)
                break;

            prefixBuf[prefixChars++] = Path->Buffer[i];

            if (Path->Buffer[i] == L'\\') {
                // prefixBuf[0..prefixChars-1] is a '\\'-terminated prefix.
                UNICODE_STRING prefix;
                prefix.Buffer        = prefixBuf;
                prefix.Length        = prefixChars * sizeof(WCHAR);
                prefix.MaximumLength = prefix.Length;

                ULONG hash  = HashPath(&prefix);
                ULONG index = hash % NUM_BUCKETS;

                PLIST_ENTRY head = &m_FileRuleTable->Buckets[index];
                for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
                    PRULE_ENTRY rule = CONTAINING_RECORD(e, RULE_ENTRY, ListEntry);
                    if (rule->MatchType == MATCH_DIRECTORY &&
                        MatchFileRule(rule, Path)) {
                        // A later (longer) match overwrites an earlier one,
                        // so bestDirMatch is always the most specific.
                        bestDirMatch = rule;
                    }
                }
            }
        }
    }

    // Phase 2b: Full bucket scan for MATCH_PATTERN rules only.
    //
    // Pattern strings contain wildcards (* ? **) so we cannot hash the
    // stored pattern against the target path — we must call GlobMatch.
    // In practice there are very few pattern rules, so this scan is cheap.
    for (int i = 0; i < NUM_BUCKETS; i++) {
        PLIST_ENTRY head = &m_FileRuleTable->Buckets[i];
        for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
            PRULE_ENTRY rule = CONTAINING_RECORD(e, RULE_ENTRY, ListEntry);
            if (rule->MatchType == MATCH_PATTERN && MatchFileRule(rule, Path)) {
                // Pattern rules don't have a meaningful "length" for
                // specificity ordering; return the first match found.
                // If a more-specific directory rule was already found, it
                // takes precedence over a pattern rule (exact > dir > pattern).
                if (!bestDirMatch)
                    bestDirMatch = rule;
            }
        }
    }

    return bestDirMatch;
}

BOOLEAN Globals::RemoveFileRule(_In_ PUNICODE_STRING Path) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> locker(m_FileRuleLock);
    PRULE_ENTRY rule = LookupRuleInTable(m_FileRuleTable, Path);
    if (!rule)
        return FALSE;
    RemoveEntryList(&rule->ListEntry);
    FreeRuleEntry(rule);
    return TRUE;
}

VOID Globals::ClearAllFileRules() {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> locker(m_FileRuleLock);
    ClearHashTable(m_FileRuleTable);
}

VOID Globals::DestroyFileRuleHashTable() {
    // Acquire lock so any concurrent LookupFileRule / InsertFileRule that
    // squeezed in before FltUnregisterFilter returned will finish first.
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Locker<FastMutex> locker(m_FileRuleLock);
    DestroyHashTable(m_FileRuleTable);
    m_FileRuleTable = NULL;
}

// ============================
// Combined operations
// ============================

VOID Globals::ClearAllRules() {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    {
        Locker<FastMutex> locker(m_Lock);
        ClearHashTable(m_Table);
        m_ProcessWhitelist = 0;
    }
    {
        Locker<FastMutex> locker(m_FileRuleLock);
        ClearHashTable(m_FileRuleTable);
    }
}
