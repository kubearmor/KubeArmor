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
    KdPrint(("destroying rule table...\n"));
    for (int i = 0; i < NUM_BUCKETS; ++i) {
        PLIST_ENTRY head = &table->Buckets[i];
        while (!IsListEmpty(head)) {
            PRULE_ENTRY rule = CONTAINING_RECORD(
                RemoveHeadList(head), RULE_ENTRY, ListEntry);
            KdPrint(("removed a rule with path: %wZ\n", &rule->Path));
            FreeRuleEntry(rule);
        }
    }
    ExFreePoolWithTag(table, RULE_TABLE_TAG);
    KdPrint(("destroyed all rules\n"));
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

// Helper: look up a rule by suffix in all buckets (for process enforcement).
// Requires that the match occurs at a path boundary (i.e. the char before the
// match is '\') to prevent false positives like 'bad_notepad.exe' matching 'notepad.exe'.
static PRULE_ENTRY LookupRuleBySuffix(PRULE_HASH_TABLE table, PUNICODE_STRING Path) {
    for (ULONG i = 0; i < NUM_BUCKETS; i++) {
        PLIST_ENTRY head = &table->Buckets[i];
        for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
            PRULE_ENTRY rule = CONTAINING_RECORD(e, RULE_ENTRY, ListEntry);
            if (rule->Path.Length == 0)
                continue;
            if (Path->Length >= rule->Path.Length) {
                USHORT suffixByteOffset = Path->Length - rule->Path.Length;
                UNICODE_STRING suffix;
                suffix.Length        = rule->Path.Length;
                suffix.MaximumLength = rule->Path.Length;
                suffix.Buffer        = (PWCH)((PUCHAR)Path->Buffer + suffixByteOffset);

                // Boundary check: the character immediately before the suffix
                // must be '\', or we must be matching from the very start.
                BOOLEAN boundaryOk = (suffixByteOffset == 0) ||
                    (Path->Buffer[(suffixByteOffset / sizeof(WCHAR)) - 1] == L'\\');

                if (boundaryOk && RtlEqualUnicodeString(&rule->Path, &suffix, TRUE)) {
                    return rule;
                }
            }
        }
    }
    return NULL;
}

// ============================================
// Globals implementation
// ============================================

extern void WriteLogFile(PCSTR format, ...);
NTSTATUS Globals::Init() {
    WriteLogFile("  -> Globals::Init started\r\n");

    // Initialize process rule table
    m_Table = AllocateHashTable();
    if (!m_Table) {
        WriteLogFile("  -> AllocateHashTable for m_Table failed\r\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    m_Lock.Init();
    m_ProcessWhitelist = 0;

    // Initialize file rule table
    m_FileRuleTable = AllocateHashTable();
    if (!m_FileRuleTable) {
        WriteLogFile("  -> AllocateHashTable for m_FileRuleTable failed\r\n");
        ExFreePoolWithTag(m_Table, RULE_TABLE_TAG);
        m_Table = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    m_FileRuleLock.Init();

    WriteLogFile("  -> Globals::Init finished\r\n");
    return STATUS_SUCCESS;
}

// ============================
// Process rule operations
// ============================

VOID Globals::DestroyRuleHashTable() {
    // Acquire lock so any concurrent LookupRule / InsertRule that squeezed
    // in before FltUnregisterFilter returned will finish before we free.
    Locker<FastMutex> locker(m_Lock);
    DestroyHashTable(m_Table);
    m_Table = NULL;
}


BOOLEAN Globals::InsertRule(_In_ PUNICODE_STRING Path, _In_ RuleAction Action) {
    Locker<FastMutex> locker(m_Lock);
    PRULE_ENTRY entry = AllocateRuleEntry(Path, Action, RULE_TYPE_PROCESS, MATCH_PATH, 0);
    if (!entry) 
    {
        KdPrint(("cannot allocate rule entry..."));
        return FALSE;
    }
    ULONG hash = HashPath(Path);
    ULONG index = hash % NUM_BUCKETS;
    if (Action == RuleAction::Allow) {
        m_ProcessWhitelist++;
    }
    KdPrint(("inserting process rule with path: %wZ and action: %s at index: %lu",
        Path, Action == RuleAction::Block ? "Block" : "Audit", index));
    InsertTailList(&m_Table->Buckets[index], &entry->ListEntry);
    KdPrint(("inserted process rule successfully..."));
    return TRUE;
}

PRULE_ENTRY Globals::LookupRule(_In_ PUNICODE_STRING Path) {
    KdPrint(("looking up process rule...\n"));
    Locker<FastMutex> locker(m_Lock);  // hold lock for entire lookup
    return LookupRuleBySuffix(m_Table, Path);
}

// LookupRuleAction — returns the action for a process rule path.
// Returns RuleAction::Audit if no rule is found (safe default).
// Holds m_Lock for the entire lookup so the entry cannot be freed
// concurrently by ClearAllRules.
RuleAction Globals::LookupRuleAction(_In_ PUNICODE_STRING Path) {
    Locker<FastMutex> locker(m_Lock);
    PRULE_ENTRY entry = LookupRuleBySuffix(m_Table, Path);
    if (entry == nullptr)
        return RuleAction::Audit;  // no match → not blocked
    return entry->Action;
}

BOOLEAN Globals::RemoveRule(_In_ PUNICODE_STRING Path) {
    Locker<FastMutex> lock(m_Lock);
    KdPrint(("removing process rule..."));
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
    KdPrint(("removed process rule successfully..."));
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
        KdPrint(("cannot allocate file rule entry..."));
        return FALSE;
    }
    ULONG hash = HashPath(&normalizedPath);
    ULONG index = hash % NUM_BUCKETS;
    KdPrint(("inserting file rule with path: %wZ, matchType: %u, action: %s, flags: 0x%04X at index: %lu",
        &normalizedPath, MatchType,
        Action == RuleAction::Block ? "Block" : (Action == RuleAction::Audit ? "Audit" : "Allow"),
        Flags, index));
    InsertTailList(&m_FileRuleTable->Buckets[index], &entry->ListEntry);
    KdPrint(("inserted file rule successfully..."));
    return TRUE;
}

PRULE_ENTRY Globals::LookupFileRule(_In_ PUNICODE_STRING Path) {
    Locker<FastMutex> locker(m_FileRuleLock);

    // Phase 1: Exact-path hash lookup (fast path for MATCH_PATH rules)
    PRULE_ENTRY exactMatch = LookupRuleInTable(m_FileRuleTable, Path);
    if (exactMatch)
        return exactMatch;

    // Phase 2: Full-table scan for MATCH_DIRECTORY rules (prefix matching)
    // Returns the most specific (longest prefix) directory match.
    PRULE_ENTRY bestDirMatch = NULL;
    USHORT bestDirLen = 0;

    for (int i = 0; i < NUM_BUCKETS; i++) {
        PLIST_ENTRY head = &m_FileRuleTable->Buckets[i];
        for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
            PRULE_ENTRY rule = CONTAINING_RECORD(e, RULE_ENTRY, ListEntry);
            if (rule->MatchType == MATCH_DIRECTORY && MatchFileRule(rule, Path)) {
                // Keep the most specific (longest) directory match
                if (rule->Path.Length > bestDirLen) {
                    bestDirMatch = rule;
                    bestDirLen = rule->Path.Length;
                }
            }
        }
    }

    return bestDirMatch;
}

BOOLEAN Globals::RemoveFileRule(_In_ PUNICODE_STRING Path) {
    Locker<FastMutex> locker(m_FileRuleLock);
    KdPrint(("removing file rule..."));
    PRULE_ENTRY rule = LookupRuleInTable(m_FileRuleTable, Path);
    if (!rule)
        return FALSE;
    RemoveEntryList(&rule->ListEntry);
    FreeRuleEntry(rule);
    KdPrint(("removed file rule successfully..."));
    return TRUE;
}

VOID Globals::ClearAllFileRules() {
    Locker<FastMutex> locker(m_FileRuleLock);
    KdPrint(("clearing all file rules..."));
    ClearHashTable(m_FileRuleTable);
    KdPrint(("cleared all file rules."));
}

VOID Globals::DestroyFileRuleHashTable() {
    // Acquire lock so any concurrent LookupFileRule / InsertFileRule that
    // squeezed in before FltUnregisterFilter returned will finish first.
    Locker<FastMutex> locker(m_FileRuleLock);
    DestroyHashTable(m_FileRuleTable);
    m_FileRuleTable = NULL;
}

// ============================
// Combined operations
// ============================

VOID Globals::ClearAllRules() {
    KdPrint(("clearing all rules (process + file)..."));
    {
        Locker<FastMutex> locker(m_Lock);
        ClearHashTable(m_Table);
        m_ProcessWhitelist = 0;
    }
    {
        Locker<FastMutex> locker(m_FileRuleLock);
        ClearHashTable(m_FileRuleTable);
    }
    KdPrint(("cleared all rules."));
}
