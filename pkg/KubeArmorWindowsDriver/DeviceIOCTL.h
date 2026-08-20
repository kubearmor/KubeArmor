// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

#pragma once

#define DEVICE_KARMOR 0x8022
#define MAX_PATH_LENGTH 520  // Support long NT paths (was 260)

// Rule types
typedef enum _RULE_TYPE : USHORT {
    RULE_TYPE_FILE = 1,
    RULE_TYPE_PROCESS = 2,
} RULE_TYPE;

// Rule match types
typedef enum _MATCH_TYPE : USHORT {
    MATCH_PATH = 1,        // Exact path match
    MATCH_DIRECTORY = 2,   // Directory prefix match
    MATCH_PATTERN = 3,     // Regex/glob pattern
} MATCH_TYPE;

// Rule actions (wire format — maps to RuleAction enum in Rule.h)
typedef enum _RULE_ACTION_IOCTL : SHORT {
    RULE_ACTION_AUDIT = 0,
    RULE_ACTION_BLOCK = 1,
    RULE_ACTION_ALLOW = 2,
} RULE_ACTION_IOCTL;

// Rule flags (bitmask)
#define RULE_FLAG_READONLY   0x0001  // Only block writes, allow reads
#define RULE_FLAG_RECURSIVE  0x0002  // Match subdirectories
#define RULE_FLAG_OWNERONLY  0x0004  // Match file owner

typedef struct _USER_RULE_REQUEST {
    RULE_TYPE RuleType;              // File or Process
    MATCH_TYPE MatchType;            // Path, Directory, or Pattern
    RULE_ACTION_IOCTL Action;        // Audit, Block, or Allow
    USHORT Flags;                    // RULE_FLAG_* bitmask
    WCHAR Path[MAX_PATH_LENGTH];     // Null-terminated NT path
} USER_RULE_REQUEST, * PUSER_RULE_REQUEST;

#define IOCTL_ADD_RULE    CTL_CODE(DEVICE_KARMOR, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_REMOVE_RULE CTL_CODE(DEVICE_KARMOR, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_CLEAR_RULES CTL_CODE(DEVICE_KARMOR, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
