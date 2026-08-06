#pragma once

#include "FastMutex.h"
#include "Rule.h"

#define RULE_TABLE_TAG 'rulP'

typedef struct _RULE_HASH_TABLE {
	LIST_ENTRY Buckets[NUM_BUCKETS];
} RULE_HASH_TABLE, * PRULE_HASH_TABLE;

struct Globals {
	NTSTATUS Init();

	// Process rule operations (existing)
	VOID SetDefaultProcessPosture(_In_ RuleAction Posture);
	RuleAction GetDefaultProcessPosture();
	BOOLEAN IsProcessWhitelist();
	BOOLEAN InsertRule(_In_ PUNICODE_STRING Path, _In_ RuleAction Action);
	// LookupRule returns a raw pointer — caller must hold m_Lock.
	// Prefer LookupRuleAction for safe lock-held action retrieval.
	PRULE_ENTRY LookupRule(_In_ PUNICODE_STRING Path);
	RuleAction  LookupRuleAction(_In_ PUNICODE_STRING Path);
	BOOLEAN RemoveRule(_In_ PUNICODE_STRING Path);
	VOID DestroyRuleHashTable();

	// File rule operations (new)
	BOOLEAN InsertFileRule(_In_ PUNICODE_STRING Path, _In_ RuleAction Action,
	                       _In_ MATCH_TYPE MatchType, _In_ USHORT Flags);
	PRULE_ENTRY LookupFileRule(_In_ PUNICODE_STRING Path);
	BOOLEAN RemoveFileRule(_In_ PUNICODE_STRING Path);
	VOID ClearAllFileRules();
	VOID DestroyFileRuleHashTable();

	// Clear all rules (both tables) — used by IOCTL_CLEAR_RULES
	VOID ClearAllRules();

private:
	// Process rule state (existing)
	ULONG m_ProcessWhitelist;
	RuleAction m_DefaultProcessPosture;
	PRULE_HASH_TABLE m_Table;
	FastMutex m_Lock;

	// File rule state (new)
	PRULE_HASH_TABLE m_FileRuleTable;
	FastMutex m_FileRuleLock;
};
