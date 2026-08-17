#include "Rule.h"

PRULE_ENTRY AllocateRuleEntry(
    PUNICODE_STRING Path,
    RuleAction Action,
    RULE_TYPE RuleType,
    MATCH_TYPE MatchType,
    USHORT Flags)
{
    KdPrint(("IOCTL: ADDING RULE"));
    PRULE_ENTRY entry = (PRULE_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RULE_ENTRY), RULE_ENTRY_TAG);
    if (!entry) 
    {
        KdPrint(("failed to allocate rule entry..."));
        return NULL;
    }
    RtlZeroMemory(entry, sizeof(RULE_ENTRY));

    USHORT size = Path->Length + (USHORT)sizeof(WCHAR); // +2 for null terminator
    entry->Path.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, RULE_PATH_TAG);
    if (!entry->Path.Buffer) {
        KdPrint(("failed to allocate rule path buffer...\n"));
        ExFreePoolWithTag(entry, RULE_ENTRY_TAG);
        return NULL;
    }
    entry->Path.Length = 0;
    entry->Path.MaximumLength = size;  // exactly covers Length + null terminator
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

// MatchFileRule — match a file path against a rule entry, respecting MatchType.
//   MATCH_PATH:      exact (case-insensitive) string comparison
//   MATCH_DIRECTORY:  prefix match; if RULE_FLAG_RECURSIVE is NOT set,
//                     only immediate children match (no extra backslashes
//                     after the directory prefix).
//   MATCH_PATTERN:    reserved for Phase 3 (always returns FALSE)
BOOLEAN MatchFileRule(PRULE_ENTRY Entry, PUNICODE_STRING Path) {
    if (!Entry || !Path || !Entry->Path.Buffer || !Path->Buffer)
        return FALSE;

    switch (Entry->MatchType) {
    case MATCH_PATH:
        return RtlEqualUnicodeString(&Entry->Path, Path, TRUE);

    case MATCH_DIRECTORY: {
        // Directory prefix match: Path must start with Entry->Path
        USHORT dirLen = Entry->Path.Length;  // in bytes (WCHAR = 2 bytes)
        if (Path->Length <= dirLen)
            return FALSE;  // Path must be strictly longer than the directory prefix

        // Compare the prefix (case-insensitive)
        UNICODE_STRING pathPrefix;
        pathPrefix.Buffer = Path->Buffer;
        pathPrefix.Length = dirLen;
        pathPrefix.MaximumLength = dirLen;

        if (!RtlEqualUnicodeString(&Entry->Path, &pathPrefix, TRUE))
            return FALSE;

        // If recursive, any descendant matches
        if (Entry->Flags & RULE_FLAG_RECURSIVE)
            return TRUE;

        // Non-recursive: only immediate children (no backslash after prefix)
        // The prefix already ends with '\', so check that the remainder
        // has no more backslashes.
        USHORT remainingChars = (Path->Length - dirLen) / sizeof(WCHAR);
        PWCH   remainingBuf = (PWCH)((PUCHAR)Path->Buffer + dirLen);

        for (USHORT i = 0; i < remainingChars; i++) {
            if (remainingBuf[i] == L'\\')
                return FALSE;  // nested directory — not an immediate child
        }
        return TRUE;
    }

    case MATCH_PATTERN:
        // Phase 3 — not implemented
        return FALSE;

    default:
        return FALSE;
    }
}
