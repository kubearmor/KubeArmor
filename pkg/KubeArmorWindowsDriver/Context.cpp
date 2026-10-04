// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor


#include "Context.h"
#include <ntddstor.h>



NTSTATUS Context::InitializeInstanceContext(
    PCFLT_RELATED_OBJECTS fltObjects,
    InstanceContext* context) {

    if (!context || !fltObjects) {
        return STATUS_INVALID_PARAMETER;
    }

    // Zero memory (Filter Manager may not do this)
    RtlZeroMemory(context, sizeof(InstanceContext));

    // Map UNICODE_STRING to embedded buffers
    RtlInitEmptyUnicodeString(
        &context->volumeName,
        context->volumeNameBuffer,
        sizeof(context->volumeNameBuffer));

    RtlInitEmptyUnicodeString(
        &context->usbDeviceVolumeLabel,
        context->usbDeviceBuffer,
        sizeof(context->usbDeviceBuffer));

    // Populate complex volume information
    return PopulateVolumeInfo(fltObjects, context);
}

VOID Context::CleanupInstanceContext(InstanceContext* context) {
    if (!context) {
        return;
    }

    // no dynamic memory is to be released

    UNREFERENCED_PARAMETER(context);
}

NTSTATUS Context::PopulateVolumeInfo(
    PCFLT_RELATED_OBJECTS fltObjects,
    InstanceContext* context) {

    NTSTATUS status;

    // Get volume GUID and name
    status = GetVolumeGuid(
        fltObjects->Volume,
        &context->volumeGuid,
        &context->volumeName);

    if (!NT_SUCCESS(status)) {
        // Non-fatal, continue with empty GUID
        RtlZeroMemory(&context->volumeGuid, sizeof(GUID));
    }

    // Get device object
    PDEVICE_OBJECT deviceObject = nullptr;
    status = FltGetDiskDeviceObject(fltObjects->Volume, &deviceObject);

    if (!NT_SUCCESS(status)) {
        context->volumeType = VolumeType::Unknown;
        context->isUsbDevice = FALSE;
        return STATUS_SUCCESS;  // Non-fatal
    }

    // Get device information
    FILE_FS_DEVICE_INFORMATION deviceInfo;
    RtlZeroMemory(&deviceInfo, sizeof(deviceInfo));

    // Simple way: use device object properties directly
    deviceInfo.DeviceType = deviceObject->DeviceType;
    deviceInfo.Characteristics = deviceObject->Characteristics;

    // Classify volume type
    context->volumeType = ClassifyVolumeType(&deviceInfo);

    // Check if USB
    if (deviceInfo.Characteristics & FILE_REMOVABLE_MEDIA) {
        context->isUsbDevice = IsUsbDevice(deviceObject, fltObjects, context);
    }
    else {
        context->isUsbDevice = FALSE;
    }

    ObDereferenceObject(deviceObject);

    return STATUS_SUCCESS;
}

NTSTATUS Context::GetVolumeGuid(
    PFLT_VOLUME volume,
    GUID* volumeGuid,
    PUNICODE_STRING volumeName) {

    // Get volume GUID name
    NTSTATUS status = FltGetVolumeGuidName(volume, volumeName, nullptr);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Parse GUID from string
    // The string format is: \??\Volume{GUID}
    // We need to extract just the GUID part

    // Find the opening brace
    PWCHAR guidStart = wcsrchr(volumeName->Buffer, L'{');
    if (guidStart) {
        UNICODE_STRING guidString;
        RtlInitUnicodeString(&guidString, guidStart);
        status = RtlGUIDFromString(&guidString, volumeGuid);
    }
    else {
        status = STATUS_INVALID_PARAMETER;
    }

    return status;
}

VolumeType Context::ClassifyVolumeType(
    PFILE_FS_DEVICE_INFORMATION deviceInfo) {

    // Check for network device
    if (deviceInfo->Characteristics & FILE_REMOTE_DEVICE) {
        return VolumeType::Network;
    }

    // Check device type
    switch (deviceInfo->DeviceType) {
    case FILE_DEVICE_DISK:
    case FILE_DEVICE_DISK_FILE_SYSTEM:
        if (deviceInfo->Characteristics & FILE_REMOVABLE_MEDIA) {
            return VolumeType::Removable;
        }
        return VolumeType::Fixed;

    case FILE_DEVICE_VIRTUAL_DISK:
        return VolumeType::Ram;

    case FILE_DEVICE_CD_ROM:
    case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
        return VolumeType::Removable;

    case FILE_DEVICE_NETWORK:
    case FILE_DEVICE_NETWORK_FILE_SYSTEM:
        return VolumeType::Network;

    default:
        return VolumeType::Unknown;
    }
}

BOOLEAN Context::IsUsbDevice(
    PDEVICE_OBJECT deviceObject,
    PCFLT_RELATED_OBJECTS fltObjects,
    InstanceContext* context) {

    // Query storage device property
    STORAGE_PROPERTY_QUERY query;
    RtlZeroMemory(&query, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    // Allocate buffer
    ULONG bufferSize = sizeof(STORAGE_DEVICE_DESCRIPTOR) + 512;
    PSTORAGE_DEVICE_DESCRIPTOR descriptor =
        static_cast<PSTORAGE_DEVICE_DESCRIPTOR>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'bsuC'));

    if (!descriptor) {
        return FALSE;
    }

    // Build and send IRP
    KEVENT event;
    IO_STATUS_BLOCK ioStatus;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    PIRP irp = IoBuildDeviceIoControlRequest(
        IOCTL_STORAGE_QUERY_PROPERTY,
        deviceObject,
        &query,
        sizeof(query),
        descriptor,
        bufferSize,
        FALSE,
        &event,
        &ioStatus);

    if (!irp) {
        ExFreePoolWithTag(descriptor, 'bsuC');
        return FALSE;
    }

    NTSTATUS status = IoCallDriver(deviceObject, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, nullptr);
        status = ioStatus.Status;
    }

    BOOLEAN isUsb = FALSE;

    if (NT_SUCCESS(status) && descriptor->BusType == BusTypeUsb) {
        isUsb = TRUE;
        GetUsbDeviceVolumeLabel(fltObjects->Instance, &context->usbDeviceVolumeLabel);
    }

    ExFreePoolWithTag(descriptor, 'bsuC');
    return isUsb;
}

NTSTATUS Context::GetUsbDeviceVolumeLabel(
    PFLT_INSTANCE instance,
    PUNICODE_STRING volumeLabel) {

    if (!instance || !volumeLabel) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG bufferSize = sizeof(FILE_FS_VOLUME_INFORMATION) + 256 * sizeof(WCHAR);
    PFILE_FS_VOLUME_INFORMATION volumeInfo = nullptr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    volumeInfo = static_cast<PFILE_FS_VOLUME_INFORMATION>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'ivfC'));

    if (!volumeInfo) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        status = FltQueryVolumeInformation(
            instance,
            nullptr,
            volumeInfo,
            bufferSize,
            FileFsVolumeInformation);

        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[kubearmor] FltQueryVolumeInformation failed: 0x%08X\n", status);
            __leave;
        }

        if (volumeInfo->VolumeLabelLength > 0) {
            SIZE_T copyLength = min(
                (SIZE_T)volumeInfo->VolumeLabelLength,
                (SIZE_T)(volumeLabel->MaximumLength - sizeof(WCHAR)));

            RtlCopyMemory(volumeLabel->Buffer,
                volumeInfo->VolumeLabel,
                copyLength);

            volumeLabel->Length = (USHORT)copyLength;

            if (volumeLabel->Length < volumeLabel->MaximumLength - sizeof(WCHAR)) {
                volumeLabel->Buffer[volumeLabel->Length / sizeof(WCHAR)] = L'\0';
            }

            status = STATUS_SUCCESS;
        }
        else {
            volumeLabel->Length = 0;
            volumeLabel->Buffer[0] = L'\0';
            status = STATUS_SUCCESS;
        }
    }
    __finally {
        if (volumeInfo) {
            ExFreePoolWithTag(volumeInfo, 'ivfC');
        }
    }
    return status;
}

// ============================= //
// ==== StreamHandleContext ==== //
// ============================= //

NTSTATUS Context::InitializeStreamHandleContext(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    StreamHandleContext* context) {

    if (!context || !data || !fltObjects) {
        return STATUS_INVALID_PARAMETER;
    }

    // Zero memory
    RtlZeroMemory(context, sizeof(StreamHandleContext));


    // Set process ID
    context->processId = PsGetCurrentProcessId();

    // Map file path UNICODE_STRING to embedded buffer
    RtlInitEmptyUnicodeString(
        &context->filePath,
        context->filePathBuffer,
        sizeof(context->filePathBuffer));
        
    // Populate file information
    NTSTATUS status = PopulateFileInformation(data, fltObjects, context);
    if (!NT_SUCCESS(status)) {
        context->filePath.Length = 0;
    }

    
    // Map process path UNICODE_STRING to embedded buffer
    RtlInitEmptyUnicodeString(
        &context->processPath,
        context->processPathBuffer,
        sizeof(context->processPathBuffer));

    // Populate process path
    status = PopulateProcessPath(data, context);
    if (!NT_SUCCESS(status)) {
        context->processPath.Length = 0;
    }
    

    // Extract handle information from IRP
    ACCESS_MASK desiredAccess = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG createOptions = data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
    
    // Extract file io status
    switch (data->IoStatus.Information) {
    case FILE_SUPERSEDED:
    case FILE_OVERWRITTEN:
        context->fileIoStatus = FILE_OVERWRITTEN;
        break;
    case FILE_CREATED:
        context->fileIoStatus = FILE_CREATED;
        break;
    default:
        context->fileIoStatus = FILE_OPENED;
        break;
    }

    // Check if directory
    context->isDirectory = (createOptions & FILE_DIRECTORY_FILE) != 0;

    // Check if opened for execution
    context->isOpenedForExecution = (desiredAccess & FILE_EXECUTE) != 0;

    // Check delete on close flag
    context->deleteOnClose = (createOptions & FILE_DELETE_ON_CLOSE) != 0;
    

    // Initialize other operation flags
    context->dispositionDelete = FALSE;
    context->wasChanged = FALSE;

    // Initialize rule evaluation state
    context->ruleEvaluated = FALSE;
    context->ruleVersion = 0;
    context->cachedRuleAction = RuleAction::Allow;

    return STATUS_SUCCESS;
}

VOID Context::CleanupStreamHandleContext(StreamHandleContext* context) {
    if (!context) {
        return;
    }

    UNREFERENCED_PARAMETER(context);
}

NTSTATUS Context::PopulateFileInformation(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    StreamHandleContext* context) {

    UNREFERENCED_PARAMETER(fltObjects);

    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    NTSTATUS status;

    __try {
        // Get file name information
        status = FltGetFileNameInformation(
            data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);

        if (!NT_SUCCESS(status)) {
            __leave;
        }

        // Parse the name
        status = FltParseFileNameInformation(nameInfo);
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        // Copy file path
        SIZE_T copyLength = min(
            (SIZE_T)nameInfo->Name.Length,
            (SIZE_T)(context->filePath.MaximumLength - sizeof(WCHAR)));

        RtlCopyMemory(context->filePath.Buffer,
            nameInfo->Name.Buffer,
            copyLength);

        context->filePath.Length = (USHORT)copyLength;
        context->filePath.Buffer[context->filePath.Length / sizeof(WCHAR)] = L'\0';

        // Compute hash for quick lookups
        context->fileHash = ComputeFilePathHash(&context->filePath);

        // Classify file
        context->isExecutable = IsExecutableFile(&nameInfo->Extension);
        context->isSystemFile = IsSystemFile(&context->filePath);

        status = STATUS_SUCCESS;
    }
    __finally {
        if (nameInfo) {
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    return status;
}

NTSTATUS Context::PopulateProcessPath(
    PFLT_CALLBACK_DATA data,
    StreamHandleContext* context
) {
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = FltGetRequestorProcess(data);

    if (process == NULL) {
        DbgPrint("[kubearmor] unable to get requester process");
    }
    else {
        PUNICODE_STRING imagePath = NULL;
        status = SeLocateProcessImageName(process, &imagePath);
        if (status == STATUS_SUCCESS) {
            if (imagePath != NULL) {
                // Bounds check: cap copy length to the embedded buffer size
                SIZE_T copyLength = min(
                    (SIZE_T)imagePath->Length,
                    (SIZE_T)(context->processPath.MaximumLength - sizeof(WCHAR)));

                RtlCopyMemory(context->processPath.Buffer, imagePath->Buffer, copyLength);
                context->processPath.Length = (USHORT)copyLength;

                // Null terminate manually
                context->processPath.Buffer[context->processPath.Length / sizeof(WCHAR)] = L'\0';
                ExFreePool(imagePath);
            }
        }
        else {
            DbgPrint("[kubearmor] SeLocateProcessImageName failed 0x%x\n", status);
        }
    }
    return status;
}

BOOLEAN Context::IsExecutableFile(PUNICODE_STRING extension) {
    if (!extension || extension->Length == 0) {
        return FALSE;
    }

    static const WCHAR* execExtensions[] = {
        L".exe", L".dll", L".sys", L".com", L".scr",
        L".cpl", L".ocx", L".drv", L".efi"
    };

    for (ULONG i = 0; i < ARRAYSIZE(execExtensions); i++) {
        UNICODE_STRING extStr;
        RtlInitUnicodeString(&extStr, execExtensions[i]);

        if (RtlEqualUnicodeString(extension, &extStr, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN Context::IsSystemFile(PUNICODE_STRING filePath) {
    if (!filePath || filePath->Length == 0) {
        return FALSE;
    }

    // Static search prefixes — already in upper-case so we can do a
    // direct case-insensitive prefix comparison without any allocation.
    static const WCHAR* systemPrefixes[] = {
        L"\\WINDOWS\\SYSTEM32\\",
        L"\\WINDOWS\\SYSWOW64\\",
        L"\\WINDOWS\\WINSXS\\",
        L"\\PROGRAM FILES\\",
        L"\\PROGRAM FILES (X86)\\"
    };

    for (ULONG i = 0; i < ARRAYSIZE(systemPrefixes); i++) {
        UNICODE_STRING prefix;
        RtlInitUnicodeString(&prefix, systemPrefixes[i]);
        // RtlPrefixUnicodeString with CaseInsensitive=TRUE: O(prefix.Length),
        // no heap allocation, safe at any IRQL <= DISPATCH_LEVEL.
        if (RtlPrefixUnicodeString(&prefix, filePath, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

ULONG Context::ComputeFilePathHash(PUNICODE_STRING filePath) {
    if (!filePath || filePath->Length == 0) {
        return 0;
    }

    ULONG hash = 0;

    for (USHORT i = 0; i < filePath->Length / sizeof(WCHAR); i++) {
        // Case-insensitive hash
        WCHAR ch = RtlUpcaseUnicodeChar(filePath->Buffer[i]);
        hash = hash * 31 + ch;
    }

    return hash;
}

// ============================= //

void PrintInstanceContext(InstanceContext* context) {
    if (!context) {
        return;
    }
    KdPrint(("[Karmor] InstanceContext:\n"));
    KdPrint(("[Karmor]   VolumeType = %d\n", context->volumeType));
    KdPrint(("[Karmor]   VolumeName = %wZ\n", &context->volumeName));
    KdPrint(("[Karmor]   IsUsbDevice = %d\n", context->isUsbDevice));
    if (context->isUsbDevice) {
        KdPrint(("[Karmor]   UsbVolumeLabel = %wZ\n", &context->usbDeviceVolumeLabel));
    }
}
