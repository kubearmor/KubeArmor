#pragma once
#include <fltKernel.h>
#include <ntstrsafe.h>
#include "DeviceIOCTL.h"

#define RULE_ENTRY_TAG 'rulE'
#define RULE_PATH_TAG 'rulP'

#define NUM_BUCKETS 61  // prime no.

enum class RuleAction : short {
    Audit,
    Block,
    Allow
};

typedef struct _RULE_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING Path;
    RuleAction Action;
    RULE_TYPE RuleType;      // File or Process
    MATCH_TYPE MatchType;    // Path, Directory, Pattern
    USHORT Flags;            // RULE_FLAG_* bitmask
} RULE_ENTRY, * PRULE_ENTRY;

PRULE_ENTRY AllocateRuleEntry(
    _In_ PUNICODE_STRING Path,
    _In_ RuleAction Action,
    _In_ RULE_TYPE RuleType,
    _In_ MATCH_TYPE MatchType,
    _In_ USHORT Flags);

VOID FreeRuleEntry(_In_ PRULE_ENTRY Entry);

ULONG HashPath(_In_ PUNICODE_STRING Path);
BOOLEAN MatchPath(_In_ PRULE_ENTRY Entry, _In_ PUNICODE_STRING Path);
BOOLEAN MatchFileRule(_In_ PRULE_ENTRY Entry, _In_ PUNICODE_STRING Path);
