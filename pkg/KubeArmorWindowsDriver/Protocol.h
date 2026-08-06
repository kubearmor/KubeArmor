// Protocol.h
#pragma once

extern "C" {
    #include <ntddk.h>
}

namespace protocol {
    // Wire data types
    typedef enum _DATA_TYPE : UCHAR {
        DATA_TYPE_UCHAR = 1,
        DATA_TYPE_USHORT = 2,
        DATA_TYPE_ULONG = 3,
        DATA_TYPE_ULONGLONG = 4,
        DATA_TYPE_CHAR = 5,
        DATA_TYPE_SHORT = 6,
        DATA_TYPE_LONG = 7,
        DATA_TYPE_LONGLONG = 8,
        DATA_TYPE_UNICODE_STRING = 9,
        DATA_TYPE_BINARY = 10,
        DATA_TYPE_BOOLEAN = 11,
    } DATA_TYPE;

    // Event types
    typedef enum _EVENT_TYPE : ULONG {
        EVENT_TYPE_PROCESS_CREATE = 1,
        EVENT_TYPE_PROCESS_TERMINATE = 2,
        EVENT_TYPE_THREAD_CREATE = 3,
        EVENT_TYPE_THREAD_TERMINATE = 4,
        EVENT_TYPE_IMAGE_LOAD = 5,

        EVENT_TYPE_FILE_CREATE = 100,
        EVENT_TYPE_FILE_CLOSE = 101,
        EVENT_TYPE_FILE_READ = 102,
        EVENT_TYPE_FILE_WRITE = 103,
        EVENT_TYPE_FILE_DELETE = 104,
        EVENT_TYPE_FILE_RENAME = 105,
        EVENT_TYPE_FILE_SET_INFO = 106,

    } EVENT_TYPE;

    // Common field IDs (1-99)
    typedef enum _COMMON_FIELD_ID : UCHAR {
        FIELD_EVENT_TYPE = 1,
        FIELD_TIMESTAMP = 2,
        FIELD_PROCESS_ID = 3,
        FIELD_THREAD_ID = 4,
        FIELD_SESSION_ID = 5,
    } COMMON_FIELD_ID;

    // File volume field IDs
    typedef enum _FILE_VOLUME_ID : UCHAR {
        FIELD_VOLUME_GUID = 50,
        FIELD_VOLUME_TYPE = 51,
        FIELD_VOLUME_NAME = 52,
    } FILE_VOLUME_ID;

    // Process event field IDs (100-149)
    typedef enum _PROCESS_FIELD_ID : UCHAR {
        FIELD_PARENT_PROCESS_ID = 100,
        FIELD_CREATOR_PROCESS_ID = 101,
        FIELD_IMAGE_PATH = 102,
        FIELD_COMMAND_LINE = 103,
        FIELD_EXIT_CODE = 104,
        FIELD_CREATE_FLAGS = 105,
        FIELD_PARENT_PROCESS_IMAGE_PATH = 106,
        FIELD_CREATOR_PROCESS_IMAGE_PATH = 107,
        FIELD_PROCESS_USER_SID = 108,
        FIELD_PROCESS_TOKEN_ELEVATION = 109,
        FIELD_PROCESS_TOKEN_ELEVATION_TYPE = 110,
    } PROCESS_FIELD_ID;

    // File event field IDs (150-199)
    typedef enum _FILE_FIELD_ID : UCHAR {
        FIELD_FILE_PATH = 150,
        FIELD_FILE_NAME = 151,
        FIELD_DESIRED_ACCESS = 152,
        FIELD_CREATE_OPTIONS = 153,
        FIELD_CREATE_DISPOSITION = 154,
        FIELD_FILE_ATTRIBUTES = 155,
        FIELD_SHARE_ACCESS = 156,
        FIELD_FILE_OFFSET = 157,
        FIELD_BYTES_TRANSFERRED = 158,
        FIELD_IO_STATUS = 159,
        FIELD_FILE_ID = 160,
    } FILE_FIELD_ID;

    // Thread event field IDs (200-249)
    typedef enum _THREAD_FIELD_ID : UCHAR {
        FIELD_CREATOR_THREAD_ID = 200,
        FIELD_START_ADDRESS = 201,
    } THREAD_FIELD_ID;
}
