#pragma once

#ifndef __EVENT_STRUCTS_H__
#define __EVENT_STRUCTS_H__

extern "C" {
    #include <ntddk.h>
}

#pragma pack(push, 1)

typedef enum _FS_EVENT_TYPE
{
    EventType_HostLog = 1,
    EventType_MatchHostPolicy = 2,
} FS_EVENT_TYPE;

typedef enum _FS_EVENT_OPERATION {
    EventOperation_Invalid = 0,
    EventOperation_Process = 1,
    EventOperation_File = 2,
    EventOperation_Network = 3
} FS_EVENT_OPERATION;

typedef struct _FILE_EVENT {
    ULONG Operation;
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG ProcessPathOffset;
    ULONG ProcessPathLength;
    ULONG FilePathOffset;
    ULONG FilePathLength;
    ULONG ParentProcessPathOffset;
    ULONG ParentProcessPathLength;
} FILE_EVENT, * PFILE_EVENT;

typedef struct _PROCESS_EVENT {
    ULONG operation;
    ULONG process_id;
    ULONG parent_process_id;
    ULONG process_path_offset;
    ULONG process_path_length;
    ULONG command_line_offset;
    ULONG command_line_length;
    ULONG parent_process_path_offset;
    ULONG parent_process_path_length;
} PROCESS_EVENT, * PPROCESS_EVENT;

typedef struct _NETWORK_EVENT {
    ULONG operation;
    ULONG protocol;
    USHORT local_port;
    USHORT remote_port;
    UCHAR local_address[16];
    UCHAR remote_address[16];
    ULONG data_length;
    UCHAR address_family;
} NETWORK_EVENT, * PNETWORK_EVENT;

typedef struct _EVENT {
    ULONGLONG timestamp;
    FS_EVENT_TYPE type;
    FS_EVENT_OPERATION operation;
    BOOLEAN blocked;
    union {
        FILE_EVENT File;
        PROCESS_EVENT Process;
        NETWORK_EVENT Network;
    } data;
} EVENT, * PEVENT;

typedef struct _REPLY {
    BOOLEAN ack;
} EVENT_REPLY, * PEVENT_REPLY;

#pragma pack(pop)

#endif // !__EVENT_STRUCTS_H__
