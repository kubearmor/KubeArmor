// Serializer.h
#pragma once

#include "Buffer.h"
#include "Protocol.h"

using namespace protocol;

class Serializer {
public:
    explicit Serializer(Buffer& buffer) : m_Buffer(buffer) {}

    // Write field header: field_id | data_type
    BOOLEAN WriteFieldHeader(UCHAR FieldId, DATA_TYPE DataType)
    {
        if (!m_Buffer.WriteUChar(FieldId)) {
            return FALSE;
        }
        return m_Buffer.WriteUChar(static_cast<UCHAR>(DataType));
    }

    // Write fixed-size fields (field_id | data_type | data)
    BOOLEAN WriteFieldUChar(UCHAR FieldId, UCHAR Value)
    {
        if (!WriteFieldHeader(FieldId, DATA_TYPE_UCHAR)) {
            return FALSE;
        }
        return m_Buffer.WriteUChar(Value);
    }

    BOOLEAN WriteFieldUShort(UCHAR FieldId, USHORT Value)
    {
        if (!WriteFieldHeader(FieldId, DATA_TYPE_USHORT)) {
            return FALSE;
        }
        return m_Buffer.WriteUShort(Value);
    }

    BOOLEAN WriteFieldULong(UCHAR FieldId, ULONG Value)
    {
        if (!WriteFieldHeader(FieldId, DATA_TYPE_ULONG)) {
            return FALSE;
        }
        return m_Buffer.WriteULong(Value);
    }

    BOOLEAN WriteFieldULongLong(UCHAR FieldId, ULONGLONG Value)
    {
        if (!WriteFieldHeader(FieldId, DATA_TYPE_ULONGLONG)) {
            return FALSE;
        }
        return m_Buffer.WriteULongLong(Value);
    }

    BOOLEAN WriteFieldChar(UCHAR FieldId, CHAR Value)
    {
        if (!WriteFieldHeader(FieldId, DATA_TYPE_CHAR)) {
            return FALSE;
        }
        return m_Buffer.WriteChar(Value);
    }

    BOOLEAN WriteFieldShort(UCHAR FieldId, SHORT Value)
    {
        if (!WriteFieldHeader(FieldId, DATA_TYPE_SHORT)) {
            return FALSE;
        }
        return m_Buffer.WriteShort(Value);
    }

    BOOLEAN WriteFieldLong(UCHAR FieldId, LONG Value)
    {
        if (!WriteFieldHeader(FieldId, DATA_TYPE_LONG)) {
            return FALSE;
        }
        return m_Buffer.WriteLong(Value);
    }

    BOOLEAN WriteFieldLongLong(UCHAR FieldId, LONGLONG Value)
    {
        if (!WriteFieldHeader(FieldId, DATA_TYPE_LONGLONG)) {
            return FALSE;
        }
        return m_Buffer.WriteLongLong(Value);
    }

    BOOLEAN WriteFieldBoolean(UCHAR FieldId, BOOLEAN Value)
    {
        if (!WriteFieldHeader(FieldId, DATA_TYPE_BOOLEAN)) {
            return FALSE;
        }
        return m_Buffer.WriteUChar(Value ? 1 : 0);
    }

    // Write variable-length fields (field_id | data_type | length | data)
    BOOLEAN WriteFieldUnicodeString(UCHAR FieldId, PCUNICODE_STRING String)
    {
        if (String == nullptr || String->Buffer == nullptr || String->Length == 0) {
            // Write empty string: field_id | data_type | 0
            if (!WriteFieldHeader(FieldId, DATA_TYPE_UNICODE_STRING)) {
                return FALSE;
            }
            return m_Buffer.WriteUShort(0);
        }

        if (!WriteFieldHeader(FieldId, DATA_TYPE_UNICODE_STRING)) {
            return FALSE;
        }

        // Write length in bytes
        if (!m_Buffer.WriteUShort(String->Length)) {
            return FALSE;
        }

        // Write string data
        return m_Buffer.WriteBytes(String->Buffer, String->Length);
    }

    BOOLEAN WriteFieldWideString(UCHAR FieldId, PCWSTR String)
    {
        UNICODE_STRING ustr;

        if (String == nullptr) {
            RtlInitUnicodeString(&ustr, L"");
            return WriteFieldUnicodeString(FieldId, &ustr);
        }

        // Be careful with RtlInitUnicodeString - it doesn't check string length
        SIZE_T length = wcsnlen(String, MAXUSHORT / sizeof(WCHAR));
        ustr.Buffer = const_cast<PWSTR>(String);
        ustr.Length = static_cast<USHORT>(length * sizeof(WCHAR));
        ustr.MaximumLength = ustr.Length + sizeof(WCHAR);

        return WriteFieldUnicodeString(FieldId, &ustr);
    }

    BOOLEAN WriteFieldBinary(UCHAR FieldId, PVOID Data, ULONG Length)
    {
        if (Data == nullptr || Length == 0) {
            if (!WriteFieldHeader(FieldId, DATA_TYPE_BINARY)) {
                return FALSE;
            }
            return m_Buffer.WriteULong(0);
        }

        if (!WriteFieldHeader(FieldId, DATA_TYPE_BINARY)) {
            return FALSE;
        }

        // Write length
        if (!m_Buffer.WriteULong(Length)) {
            return FALSE;
        }

        // Write data
        return m_Buffer.WriteBytes(Data, Length);
    }

private:
    Buffer& m_Buffer;
};