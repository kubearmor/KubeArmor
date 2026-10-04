// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor


#include "Rule.h"

PRULE_ENTRY AllocateRuleEntry(
    PUNICODE_STRING Path,
    RuleAction Action,
    RULE_TYPE RuleType,
    MATCH_TYPE MatchType,
    USHORT Flags)
{
    PRULE_ENTRY entry = (PRULE_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RULE_ENTRY), RULE_ENTRY_TAG);
    if (!entry)
        return NULL;

    RtlZeroMemory(entry, sizeof(RULE_ENTRY));

    USHORT size = Path->Length + (USHORT)sizeof(WCHAR); // +2 for null terminator
    entry->Path.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, RULE_PATH_TAG);
    if (!entry->Path.Buffer) {
        ExFreePoolWithTag(entry, RULE_ENTRY_TAG);
        return NULL;
    }
    entry->Path.Length = 0;
    entry->Path.MaximumLength = size;
    entry->Action = Action;
    entry->RuleType = RuleType;
    entry->MatchType = MatchType;
    entry->Flags = Flags;
    RtlCopyUnicodeString(&entry->Path, Path);

    return entry;
}

VOID FreeRuleEntry(PRULE_ENTRY Entry) {
    if (Entry) {
        if (Entry->Path.Buffer)
            ExFreePoolWithTag(Entry->Path.Buffer, RULE_PATH_TAG);
        ExFreePoolWithTag(Entry, RULE_ENTRY_TAG);
    }
}

ULONG HashPath(PUNICODE_STRING Path) {
    ULONG hash = 0;
    RtlHashUnicodeString(Path, TRUE, HASH_STRING_ALGORITHM_X65599, &hash);
    return hash;
}

BOOLEAN MatchPath(PRULE_ENTRY Entry, PUNICODE_STRING Path) {
    return RtlEqualUnicodeString(&Entry->Path, Path, TRUE);
}

// ============================================================================
//  GlobMatch — iterative, kernel-safe glob matcher (zero-allocation, O(1) stack)
//
//  Semantics mirror KubeArmor Linux (AppArmor / fnmatch style):
//    ?    matches exactly one character that is NOT a path separator (\ or /).
//    *    matches zero or more characters that are NOT path separators.
//    **   matches zero or more characters INCLUDING path separators (crosses dirs).
//    Any other character matches itself (case-insensitively).
//
//  Algorithm: iterative backtracking with two bookmark levels.
//    - starPi/starSi:  bookmark for the most recent single-star (bounded by separators)
//    - dstarPi/dstarSi: bookmark for the most recent double-star (unbounded)
//  On mismatch, try extending the single-star first; if it hits a separator,
//  fall back to the double-star and re-scan (which re-discovers any single-stars).
//
//  Time: O(n*m) worst case, O(n+m) typical.  Stack: O(1).  No allocations.
// ============================================================================

#define GLOB_NONE MAXUSHORT

static BOOLEAN GlobMatch(
    _In_reads_(patLen) const WCHAR* pat,
    _In_ USHORT patLen,
    _In_reads_(strLen) const WCHAR* str,
    _In_ USHORT strLen)
{
    USHORT pi = 0, si = 0;

    // Backtracking bookmarks.
    USHORT starPi  = GLOB_NONE, starSi  = 0;   // single-star *
    USHORT dstarPi = GLOB_NONE, dstarSi = 0;   // double-star **

    while (si < strLen || pi < patLen) {

        if (pi < patLen) {
            WCHAR pc = pat[pi];

            // ------ Wildcard: * or ** ------
            if (pc == L'*') {
                BOOLEAN dstar = (pi + 1 < patLen && pat[pi + 1] == L'*');
                pi += dstar ? 2 : 1;

                // Consume consecutive stars (*** == **)
                while (pi < patLen && pat[pi] == L'*') pi++;

                if (dstar) {
                    dstarPi  = pi;
                    dstarSi  = si;
                    starPi   = GLOB_NONE; // ** subsumes any active *
                } else {
                    starPi  = pi;
                    starSi  = si;
                }
                continue;
            }

            // ------ One-char match attempt ------
            if (si < strLen) {
                if (pc == L'?') {
                    if (str[si] != L'\\' && str[si] != L'/') {
                        pi++; si++;
                        continue;
                    }
                    // '?' does not match a separator — fall through to backtrack
                } else {
                    if (RtlUpcaseUnicodeChar(pc) == RtlUpcaseUnicodeChar(str[si])) {
                        pi++; si++;
                        continue;
                    }
                }
            }
        }

        // ------ Mismatch: try backtracking ------

        // Single-star: extend by one char, must not cross a separator.
        if (starPi != GLOB_NONE && starSi < strLen &&
            str[starSi] != L'\\' && str[starSi] != L'/') {
            starSi++;
            pi = starPi;
            si = starSi;
            continue;
        }

        // Double-star: extend by one char (crosses separators freely).
        // Reset single-star so it is re-discovered by re-scanning the pattern.
        if (dstarPi != GLOB_NONE && dstarSi < strLen) {
            dstarSi++;
            pi  = dstarPi;
            si  = dstarSi;
            starPi = GLOB_NONE;
            continue;
        }

        return FALSE;
    }

    return TRUE;
}

// ============================================================================
//  MatchFileRule — match a file path against a rule entry, respecting MatchType.
//
//    MATCH_PATH:       exact (case-insensitive) string comparison.
//    MATCH_DIRECTORY:  prefix match; if RULE_FLAG_RECURSIVE is NOT set,
//                      only immediate children match (no extra separators
//                      after the directory prefix).
//    MATCH_PATTERN:    glob pattern match (see GlobMatch above).
//                      Examples (KubeArmor Linux parity):
//                        \Windows\Temp\*.log     — any .log directly in Temp
//                        \Users\**\*.exe         — any .exe anywhere under Users
//                        \Temp\tmp?????.tmp      — 6-char temp file names
// ============================================================================
BOOLEAN MatchFileRule(PRULE_ENTRY Entry, PUNICODE_STRING Path) {
    if (!Entry || !Path || !Entry->Path.Buffer || !Path->Buffer)
        return FALSE;

    switch (Entry->MatchType) {
    case MATCH_PATH:
        return RtlEqualUnicodeString(&Entry->Path, Path, TRUE);

    case MATCH_DIRECTORY: {
        USHORT dirLen = Entry->Path.Length;  // bytes
        if (Path->Length <= dirLen)
            return FALSE;

        // Compare the prefix (case-insensitive)
        UNICODE_STRING pathPrefix;
        pathPrefix.Buffer = Path->Buffer;
        pathPrefix.Length = dirLen;
        pathPrefix.MaximumLength = dirLen;

        if (!RtlEqualUnicodeString(&Entry->Path, &pathPrefix, TRUE))
            return FALSE;

        // Recursive: any descendant matches
        if (Entry->Flags & RULE_FLAG_RECURSIVE)
            return TRUE;

        // Non-recursive: only immediate children (no backslash in remainder)
        USHORT remainingChars = (Path->Length - dirLen) / sizeof(WCHAR);
        PWCH   remainingBuf = (PWCH)((PUCHAR)Path->Buffer + dirLen);

        for (USHORT i = 0; i < remainingChars; i++) {
            if (remainingBuf[i] == L'\\')
                return FALSE;
        }
        return TRUE;
    }

    case MATCH_PATTERN: {
        USHORT patChars = Entry->Path.Length / sizeof(WCHAR);
        USHORT strChars = Path->Length / sizeof(WCHAR);
        return GlobMatch(Entry->Path.Buffer, patChars, Path->Buffer, strChars);
    }

    default:
        return FALSE;
    }
}
