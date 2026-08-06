// Buffer.h
#pragma once

#include "pch.h"

// Pool tags
#define BUFFER_POOL_TAG 'rBuF'

const size_t DEFAULT_MAX_SIZE = 32768; // 32 KB default buffer size

class Buffer {
public:
    // Constructor
    Buffer(_In_ ULONG MaxSize = DEFAULT_MAX_SIZE, _In_ POOL_FLAGS PoolFlags = POOL_FLAG_NON_PAGED)
        : m_Buffer(nullptr)
        , m_MaxSize(0)
        , m_CurrentSize(0)
        , m_OverflowOccurred(false)
    {
        if (MaxSize == 0) {
            return;
        }

        m_Buffer = static_cast<PUCHAR>(ExAllocatePool2(
            PoolFlags,
            MaxSize,
            BUFFER_POOL_TAG
        ));

        if (m_Buffer != nullptr) {
            m_MaxSize = MaxSize;
            RtlZeroMemory(m_Buffer, MaxSize);
        }
    }

    // Destructor
    ~Buffer()
    {
        if (m_Buffer != nullptr) {
            ExFreePoolWithTag(m_Buffer, BUFFER_POOL_TAG);
            m_Buffer = nullptr;
        }
        m_MaxSize = 0;
        m_CurrentSize = 0;
    }

    // prevent copy and move
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    Buffer(Buffer&& Other) = delete;
    Buffer& operator=(Buffer&& Other) = delete;

    // Basic getters
    PUCHAR GetBuffer() const { return m_Buffer; }
    ULONG GetMaxSize() const { return m_MaxSize; }
    ULONG GetCurrentSize() const { return m_CurrentSize; }
    ULONG GetRemainingSize() const { return m_MaxSize - m_CurrentSize; }
    BOOLEAN IsValid() const { return m_Buffer != nullptr; }
    BOOLEAN HasOverflow() const { return m_OverflowOccurred; }
    // Get current write position
    PUCHAR GetCurrentPosition() const
    {
        if (m_Buffer == nullptr || m_CurrentSize >= m_MaxSize) {
            return nullptr;
        }
        return m_Buffer + m_CurrentSize;
    }

    // Reset buffer for reuse
    VOID Reset()
    {
        m_CurrentSize = 0;
        m_OverflowOccurred = false;
        if (m_Buffer != nullptr) {
            RtlZeroMemory(m_Buffer, m_MaxSize);
        }
    }

    // Write raw bytes
    BOOLEAN WriteBytes(_In_reads_bytes_(Length) PVOID Data, _In_ ULONG Length)
    {
        if (m_OverflowOccurred || m_Buffer == nullptr) {
            return FALSE;
        }

        if (Data == nullptr || Length == 0) {
            return TRUE;  // Nothing to write
        }

        if (m_CurrentSize + Length > m_MaxSize) {
            m_OverflowOccurred = true;
            return FALSE;
        }

        RtlCopyMemory(m_Buffer + m_CurrentSize, Data, Length);
        m_CurrentSize += Length;
        return TRUE;
    }

    // Write single byte
     BOOLEAN WriteByte(_In_ UCHAR Value)
    {
        return WriteBytes(&Value, sizeof(Value));
    }

    // Write UCHAR
     BOOLEAN WriteUChar(_In_ UCHAR Value)
    {
        return WriteBytes(&Value, sizeof(Value));
    }

    // Write USHORT (little-endian)
     BOOLEAN WriteUShort(_In_ USHORT Value)
    {
        return WriteBytes(&Value, sizeof(Value));
    }

    // Write ULONG (little-endian)
     BOOLEAN WriteULong(_In_ ULONG Value)
    {
        return WriteBytes(&Value, sizeof(Value));
    }

    // Write ULONGLONG (little-endian)
     BOOLEAN WriteULongLong(_In_ ULONGLONG Value)
    {
        return WriteBytes(&Value, sizeof(Value));
    }

    // Write signed integers
     BOOLEAN WriteChar(_In_ CHAR Value)
    {
        return WriteBytes(&Value, sizeof(Value));
    }

     BOOLEAN WriteShort(_In_ SHORT Value)
    {
        return WriteBytes(&Value, sizeof(Value));
    }

     BOOLEAN WriteLong(_In_ LONG Value)
    {
        return WriteBytes(&Value, sizeof(Value));
    }

     BOOLEAN WriteLongLong(_In_ LONGLONG Value)
    {
        return WriteBytes(&Value, sizeof(Value));
    }

    // Write UNICODE_STRING (length-prefixed)
     BOOLEAN WriteUnicodeString(_In_ PCUNICODE_STRING String)
    {
        if (String == nullptr || String->Buffer == nullptr) {
            // Write zero length
            return WriteUShort(0);
        }

        // Write length (in bytes)
        if (!WriteUShort(String->Length)) {
            return FALSE;
        }

        // Write string data
        return WriteBytes(String->Buffer, String->Length);
    }

    // Write null-terminated wide string
     BOOLEAN WriteWideString(_In_opt_z_ PCWSTR String)
    {
        if (String == nullptr) {
            return WriteUShort(0);
        }

        SIZE_T length = wcslen(String) * sizeof(WCHAR);

        if (length > MAXUSHORT) {
            m_OverflowOccurred = true;
            return FALSE;
        }

        if (!WriteUShort(static_cast<USHORT>(length))) {
            return FALSE;
        }

        return WriteBytes(const_cast<PWSTR>(String), static_cast<ULONG>(length));
    }

    // Write length-prefixed binary data (with ulong length)
     BOOLEAN WriteLengthPrefixedData(
        _In_reads_bytes_(Length) PVOID Data,
        _In_ ULONG Length)
    {
        if (!WriteULong(Length)) {
            return FALSE;
        }

        if (Length == 0) {
            return TRUE;
        }

        return WriteBytes(Data, Length);
    }

private:
    PUCHAR m_Buffer;
    ULONG m_MaxSize;
    ULONG m_CurrentSize;
    BOOLEAN m_OverflowOccurred;
};