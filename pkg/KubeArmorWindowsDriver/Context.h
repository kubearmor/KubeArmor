#pragma once

#ifndef CONTEXT_H
#define CONTEXT_H

#include <fltKernel.h>
#include <ntstrsafe.h>
#include "Rule.h"

const ULONG c_CtxAllocTag = 'kctx';

//========================= //
//==== InstanceContext ==== //
//========================= //

enum class VolumeType : ULONG {
    Unknown = 0,
    Fixed = 1,
    Removable = 2,
    Network = 3,
    Ram = 4
};

struct InstanceContext {
    GUID volumeGuid;
    VolumeType volumeType;
    UNICODE_STRING volumeName;
    UNICODE_STRING usbDeviceVolumeLabel;
    BOOLEAN isUsbDevice;

    WCHAR volumeNameBuffer[64];
    WCHAR usbDeviceBuffer[128];
};

void PrintInstanceContext(InstanceContext* context);

// ======================== //

//============================= //
//==== StreamHandleContext ==== //
//============================= //

struct StreamHandleContext {
    // Process information
    HANDLE processId;
    UNICODE_STRING processPath;

    UNICODE_STRING filePath;           // Normalized file path
    ULONG fileHash;                    // Hash of file path for quick lookup

    // File classification flags
    BOOLEAN isExecutable;              // .exe, .dll, .sys, etc.
    BOOLEAN isSystemFile;              // In system directories
    BOOLEAN isDirectory;               // Is a directory (not a file)

    ULONG fileIoStatus; // created, truncated, superseded

    // File operation flags
    BOOLEAN isOpenedForExecution;      // FILE_EXECUTE access or SectionObjectPointers
    BOOLEAN deleteOnClose;             // FILE_DELETE_ON_CLOSE flag set
    BOOLEAN dispositionDelete;         // SetFileInformation(FileDispositionInfo) called
    BOOLEAN dispositionRename;
    BOOLEAN wasChanged;                // At least one successful write operation
    BOOLEAN wasRead;

    // Rule evaluation and enforcement
    BOOLEAN ruleEvaluated;             // Has rule engine been run?
    BOOLEAN readOnly;
    BOOLEAN ignoreEvent;
    ULONG ruleVersion;                 // Rule version at evaluation time
    RuleAction cachedRuleAction;       // Cached result: Allow/Block/Audit

    WCHAR processPathBuffer[512];
    WCHAR filePathBuffer[512];
};

void PrintStreamHandleContext(StreamHandleContext* context);

//============================= //

class Context {
public:
    static NTSTATUS InitializeInstanceContext(
        PCFLT_RELATED_OBJECTS fltObjects,
        InstanceContext* context);

    static VOID CleanupInstanceContext(InstanceContext* context);

    static NTSTATUS InitializeStreamHandleContext(
        PFLT_CALLBACK_DATA data,
        PCFLT_RELATED_OBJECTS fltObjects,
        StreamHandleContext* context);

    static VOID CleanupStreamHandleContext(StreamHandleContext* context);

private:
    // InstanceContext methods

    static NTSTATUS PopulateVolumeInfo(
        PCFLT_RELATED_OBJECTS fltObjects,
        InstanceContext* context);

    static NTSTATUS GetVolumeGuid(
        PFLT_VOLUME volume,
        GUID* volumeGuid,
        PUNICODE_STRING volumeName);

    static VolumeType ClassifyVolumeType(
        PFILE_FS_DEVICE_INFORMATION deviceInfo);

    static BOOLEAN IsUsbDevice(
        PDEVICE_OBJECT deviceObject,
        PCFLT_RELATED_OBJECTS fltObjects,
        InstanceContext* context);

    static NTSTATUS GetUsbDeviceVolumeLabel(
        PFLT_INSTANCE instance,
        PUNICODE_STRING volumeLabel);

    // StreamHandleContext methods

    static NTSTATUS PopulateFileInformation(
        PFLT_CALLBACK_DATA data,
        PCFLT_RELATED_OBJECTS fltObjects,
        StreamHandleContext* context);

    static NTSTATUS PopulateProcessPath(
        PFLT_CALLBACK_DATA data,
        StreamHandleContext* context
    );

    static BOOLEAN IsExecutableFile(PUNICODE_STRING extension);

    static BOOLEAN IsSystemFile(PUNICODE_STRING filePath);

    static ULONG ComputeFilePathHash(PUNICODE_STRING filePath);
};

#endif // CONTEXT_H