#include "Filter.h"
#include "ETW.h"
#include "DeviceIOCTL.h"
#include "Globals.h"
#include "Buffer.h"
#include "Protocol.h"
#include "ProcessEvent.h"
#include "AsyncEventDispatcher.h"

Globals g_State;
SCANNER_DATA g_ScannerData;
BOOLEAN g_ProcessNotifyRegistered = FALSE, g_SymLinkCreated = FALSE;

void OnProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID LogProcessEvent(RuleAction action, PPROCESS_EVENT_DATA EventData);
DRIVER_DISPATCH KarmorDeviceControl, KarmorCreateClose;

#include <ntstrsafe.h>

void WriteLogFile(PCSTR format, ...) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    
    char buffer[512];
    va_list args;
    va_start(args, format);
    RtlStringCbVPrintfA(buffer, sizeof(buffer), format, args);
    va_end(args);

    UNICODE_STRING fileName;
    RtlInitUnicodeString(&fileName, L"\\SystemRoot\\KarmorLog.txt");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = ZwCreateFile(&fileHandle, 
        FILE_APPEND_DATA | FILE_WRITE_DATA | SYNCHRONIZE, 
        &objAttr, &ioStatusBlock, NULL, 
        FILE_ATTRIBUTE_NORMAL, 
        FILE_SHARE_READ, 
        FILE_OPEN_IF, 
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH, 
        NULL, 0);

    if (NT_SUCCESS(status)) {
        size_t len = 0;
        RtlStringCbLengthA(buffer, sizeof(buffer), &len);
        
        LARGE_INTEGER offset;
        offset.HighPart = -1;
        offset.LowPart = FILE_WRITE_TO_END_OF_FILE;
        
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, (ULONG)len, &offset, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("ZwWriteFile failed with status 0x%08X\n", status);
        }
        ZwClose(fileHandle);
    } else {
        DbgPrint("ZwCreateFile for KarmorLog failed with status 0x%08X\n", status);
    }
}
void KarmorUnload(PDRIVER_OBJECT DriverObject) {
    // Step 1: Deregister the process-notify callback and wait for it to drain.
    // PsSetCreateProcessNotifyRoutineEx with TRUE blocks until no callback is
    // currently executing, preventing race with OnProcessNotify after this point.
    if (g_ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
        g_ProcessNotifyRegistered = FALSE;
    }

    // Step 2: Stop the async dispatcher worker thread before touching the
    // FLT port or filter handle (the worker calls FltSendMessage which needs
    // both alive).  Uninitialize() blocks until the worker exits.
    g_AsyncDispatcher.Uninitialize();

    // Step 3: Tear down FLT communication and filter registration.
    // FltUnregisterFilter blocks until all in-flight minifilter callbacks
    // complete and all instance teardown callbacks finish.  Only after this
    // returns is it safe to free state that those callbacks touch.
    if (g_ScannerData.ClientPort) {
        FltCloseClientPort(g_ScannerData.Filter, &g_ScannerData.ClientPort);
        g_ScannerData.ClientPort = NULL;
    }
    if (g_ScannerData.ServerPort) {
        FltCloseCommunicationPort(g_ScannerData.ServerPort);
        g_ScannerData.ServerPort = NULL;
    }
    if (g_ScannerData.Filter) {
        FltUnregisterFilter(g_ScannerData.Filter);
        g_ScannerData.Filter = NULL;
    }

    // Step 4: Now that no minifilter callbacks can fire, destroy all state.
    // AppLocker and other filter drivers may have been calling into our
    // PreCreate path right up until FltUnregisterFilter returned - destroying
    // the hash tables or ProcessCache before that causes use-after-free.
    g_State.DestroyRuleHashTable();
    g_State.DestroyFileRuleHashTable();
    ProcessCache::GetInstance().Cleanup();

    // Step 5: Tear down the device object and symbolic link.
    if (g_SymLinkCreated) {
        UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Karmor");
        IoDeleteSymbolicLink(&symLink);
        g_SymLinkCreated = FALSE;
    }
    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);

    CleanupETW();
    KdPrint(("karmor driver Unload called\n"));
}

VOID TestRuleApi() {
    UNICODE_STRING testPath;
    RtlInitUnicodeString(&testPath, L"\\??\\C:\\Test\\Binary.exe");

    KdPrint(("Inserting rule...\n"));
    if (g_State.InsertRule(&testPath, RuleAction::Audit)) {
        KdPrint(("Rule inserted successfully\n"));
    }
    else {
        KdPrint(("Failed to insert rule\n"));
    }

    KdPrint(("Looking up rule...\n"));
    PRULE_ENTRY found = g_State.LookupRule(&testPath);
    if (found) {
        KdPrint(("Rule found: Path = %wZ, Action = %s\n",
            &found->Path,
            found->Action == RuleAction::Block ? "Block" : "Audit"));
    }
    else {
        KdPrint(("Rule not found\n"));
    }

    /*KdPrint(("Removing rule...\n"));
    if (g_State.RemoveRule(&testPath)) {
        KdPrint(("Rule removed successfully\n"));
    }
    else {
        KdPrint(("Failed to remove rule\n"));
    }*/

   /* KdPrint(("Destroying Rule Hash Table...\n"));
    g_State.DestroyRuleHashTable();*/
}

#ifdef __cplusplus
extern "C"
#endif
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    WriteLogFile("--- DriverEntry Started ---\r\n");
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = KarmorUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = KarmorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KarmorDeviceControl;

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Karmor");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Karmor");
    UNICODE_STRING fltPort = RTL_CONSTANT_STRING(L"\\ScannerPort");
    PDEVICE_OBJECT DeviceObject = nullptr;
    auto status = STATUS_SUCCESS;

    WriteLogFile("Calling g_State.Init()\r\n");
    status = g_State.Init();
    if (!NT_SUCCESS(status)) {
        KdPrint(("Karmor driver state initialized failed\n"));
        WriteLogFile("g_State.Init() failed with status 0x%08X\r\n", status);
        return status;
    }

    do {
        WriteLogFile("Calling RegisterFilter()\r\n");
        status = RegisterFilter(DriverObject);
        if (!NT_SUCCESS(status)) {
            KdPrint(("Failed to register Filter: (0x%x)\n", status));
            WriteLogFile("RegisterFilter() failed with status 0x%08X\r\n", status);
            return status;
        }

        WriteLogFile("Calling InitializeETW()\r\n");
        status = InitializeETW();
        if (!NT_SUCCESS(status)) {
            KdPrint(("Failed to initialize ETW: (0x%x)\n", status));
            WriteLogFile("InitializeETW() failed with status 0x%08X\r\n", status);
            CleanupETW();
            return status;
        }

        WriteLogFile("Calling IoCreateDevice()\r\n");
        status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
        if (!NT_SUCCESS(status)) {
            KdPrint(("failed to create device (0x%08X)\n", status));
            WriteLogFile("IoCreateDevice() failed with status 0x%08X\r\n", status);
            break;
        }
        DeviceObject->Flags |= DO_DIRECT_IO;

        status = IoCreateSymbolicLink(&symLink, &devName);
        if (!NT_SUCCESS(status)) {
            KdPrint(("failed to create symbolic link (0x%08X)\n", status));
            WriteLogFile("IoCreateSymbolicLink() failed with status 0x%08X\r\n", status);
            break;
        }
        g_SymLinkCreated = TRUE;

        status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
        if (!NT_SUCCESS(status)) {
            KdPrint(("failed to register process callback (0x%08X)\n", status));
            WriteLogFile("PsSetCreateProcessNotifyRoutineEx() failed with status 0x%08X\r\n", status);
            break;
        }
        g_ProcessNotifyRegistered = TRUE;

    } while (false);

    if (!NT_SUCCESS(status)) {
        if (g_ProcessNotifyRegistered)
        {
            PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
            g_ProcessNotifyRegistered = FALSE;
        }
        if (g_SymLinkCreated)
        {
            IoDeleteSymbolicLink(&symLink);
            g_SymLinkCreated = FALSE;
        }
        if (DeviceObject)
            IoDeleteDevice(DeviceObject);
    }

    if (NT_SUCCESS(status)) {
        KdPrint(("Karmor driver initialized successfully\n"));
        WriteLogFile("Driver initialized successfully\r\n");
    }

    return status;
}

/*
================================
    ETW Functions
================================
*/
NTSTATUS InitializeETW()
{
    NTSTATUS status;

    // Register ETW provider
    status = EtwRegister(
        &KarmorProvider,  // From generated header
        NULL,                         // Enable callback (optional)
        NULL,                         // Enable callback context
        &g_EtwRegHandle
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("EventRegister failed: 0x%x\n", status));
        return status;
    }

    KdPrint(("ETW provider registered successfully\n"));
    return STATUS_SUCCESS;
}

VOID CleanupETW()
{
    if (g_EtwRegHandle != 0) {
        EtwUnregister(g_EtwRegHandle);
        g_EtwRegHandle = 0;
    }
}

VOID LogProcessEvent(RuleAction action, PPROCESS_EVENT_DATA EventData)
{
    EVENT_DATA_DESCRIPTOR eventDataDescriptor[6];
    const EVENT_DESCRIPTOR* eventDescriptor;
    NTSTATUS status;

    // Select the appropriate event descriptor from generated header
    eventDescriptor = action == RuleAction::Block ? &ProcessBlocked : &ProcessAudited;

    // Prepare event data descriptors
    EventDataDescCreate(&eventDataDescriptor[0], &EventData->ProcessId, sizeof(ULONG));
    EventDataDescCreate(&eventDataDescriptor[1], &EventData->ParentProcessId, sizeof(ULONG));
    EventDataDescCreate(&eventDataDescriptor[2], EventData->ImagePath.Buffer, EventData->ImagePath.Length);
    EventDataDescCreate(&eventDataDescriptor[3], EventData->CommandLine.Buffer, EventData->CommandLine.Length);
    EventDataDescCreate(&eventDataDescriptor[4], EventData->UserSid.Buffer, EventData->UserSid.Length);
    EventDataDescCreate(&eventDataDescriptor[5], EventData->RuleName.Buffer, EventData->RuleName.Length);

    // Write ETW event with correct parameter order
    status = EtwWrite(
        g_EtwRegHandle,         // [in] REGHANDLE RegHandle
        eventDescriptor,        // [in] PCEVENT_DESCRIPTOR EventDescriptor  
        NULL,                   // [in, optional] LPCGUID ActivityId
        6,                      // [in] ULONG UserDataCount
        eventDataDescriptor     // [in, optional] PEVENT_DATA_DESCRIPTOR UserData
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("EtwWrite failed: 0x%x\n", status));
    }
}

/*
================================
    Device Dispatch Functions
================================
*/

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0) {
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, 0);
    return status;
}

NTSTATUS KarmorCreateClose(PDEVICE_OBJECT, PIRP Irp) {
    return CompleteIrp(Irp);
}

NTSTATUS KarmorDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_ADD_RULE: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(USER_RULE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PUSER_RULE_REQUEST request = (PUSER_RULE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        UNICODE_STRING path;
        RtlInitUnicodeString(&path, request->Path);

        RuleAction action = (RuleAction)request->Action;

        if (request->RuleType == RULE_TYPE_FILE) {
            // File rule — route to file rule table
            if (g_State.InsertFileRule(&path, action, request->MatchType, request->Flags))
            {
                status = STATUS_SUCCESS;
                KdPrint(("Added file rule: Path = %wZ, Action = %d, Flags = 0x%04X\n",
                    &path, (int)action, request->Flags));
            }
            else
            {
                status = STATUS_UNSUCCESSFUL;
            }
        }
        else {
            // Process rule — route to process rule table (existing)
            if (g_State.InsertRule(&path, action))
            {
                status = STATUS_SUCCESS;
                KdPrint(("Added process rule: Path = %wZ, Action = %d\n",
                    &path, (int)action));
            }
            else
            {
                status = STATUS_UNSUCCESSFUL;
            }
        }
        break;
    }

    case IOCTL_REMOVE_RULE: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(USER_RULE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PUSER_RULE_REQUEST request = (PUSER_RULE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        UNICODE_STRING path;
        RtlInitUnicodeString(&path, request->Path);

        BOOLEAN removed;
        if (request->RuleType == RULE_TYPE_FILE) {
            removed = g_State.RemoveFileRule(&path);
        }
        else {
            removed = g_State.RemoveRule(&path);
        }

        status = removed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        break;
    }

    case IOCTL_CLEAR_RULES: {
        g_State.ClearAllRules();
        status = STATUS_SUCCESS;
        KdPrint(("All rules cleared via IOCTL\n"));
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return CompleteIrp(Irp, status, info);
}

/*
================================
   Process Notify Routine
================================
*/


void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    Buffer event;

    if (!event.IsValid()) {
        DbgPrint("unable to initialize buffer!!");
        return;
    }

    protocol::EVENT_TYPE eType;

    BOOLEAN isBlocked = FALSE;

    if (CreateInfo != nullptr) {
        eType = EVENT_TYPE_PROCESS_CREATE;
        
        if (CreateInfo->ImageFileName != nullptr) {
            // Guard 1: If another kernel callback (e.g. AppLocker) has already
            // denied this process creation, do NOT overwrite their status code.
            // AppLocker uses specific NTSTATUS codes (e.g.
            // STATUS_ACCESS_DISABLED_BY_POLICY_OTHER) for audit tracking.
            // Overwriting with STATUS_ACCESS_DENIED confuses the AppLocker
            // service and can cause it to misclassify the event, potentially
            // applying a more restrictive policy to unrelated packaged apps.
            if (!NT_SUCCESS(CreateInfo->CreationStatus)) {
                goto skip_rule_check;
            }

            // Guard 2: Skip suffix-based process blocking for processes
            // launching from the Windows packaged app directory (\WindowsApps\).
            // Packaged apps have a package identity separate from their EXE path.
            // AppLocker's "Packaged App Rules" enforce policy on that package
            // identity — our file-path suffix match is the wrong tool here and
            // can conflict with AppLocker's enforcement infrastructure, causing
            // all packaged apps to be affected when only one is targeted.
            {
                UNICODE_STRING windowsAppsComponent;
                RtlInitUnicodeString(&windowsAppsComponent, L"\\WindowsApps\\");
                // Search for the component anywhere in the image path.
                UNICODE_STRING imagePath = *CreateInfo->ImageFileName;
                BOOLEAN isPackagedApp = FALSE;
                if (imagePath.Length > windowsAppsComponent.Length) {
                    for (USHORT i = 0;
                         i <= (imagePath.Length - windowsAppsComponent.Length) / sizeof(WCHAR);
                         ++i)
                    {
                        UNICODE_STRING slice;
                        slice.Buffer        = imagePath.Buffer + i;
                        slice.Length        = windowsAppsComponent.Length;
                        slice.MaximumLength = windowsAppsComponent.Length;
                        if (RtlEqualUnicodeString(&slice, &windowsAppsComponent, TRUE)) {
                            isPackagedApp = TRUE;
                            break;
                        }
                    }
                }
                if (isPackagedApp) {
                    goto skip_rule_check;
                }
            }

            // Use LookupRuleAction: acquires m_Lock internally and returns
            // a copied enum value. This is safe against concurrent
            // ClearAllRules calls which free RULE_ENTRY objects under the
            // same lock — no raw pointer is held after the call returns.
            {
                RuleAction action = g_State.LookupRuleAction(
                    (PUNICODE_STRING)CreateInfo->ImageFileName);
                if (action == RuleAction::Block) {
                    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    isBlocked = TRUE;
                    DbgPrint("Blocking execution of %wZ\n", CreateInfo->ImageFileName);
                }
            }

        skip_rule_check:;
        }
    }
    else {
        eType = EVENT_TYPE_PROCESS_TERMINATE;
    }

    NTSTATUS status = ProcessEventSerializer::SerializeProcessEvent(event, eType, Process, ProcessId, CreateInfo, isBlocked);
    if (!NT_SUCCESS(status)) {
        return;
    }

    DbgPrint("process event serialized!!");

    // Guard: skip sending if no user-mode client is connected
    if (g_ScannerData.ClientPort == nullptr) {
        DbgPrint("!!! no user-mode client connected, skipping process event send");
        return;
    }

    LARGE_INTEGER timeOut = { 0 };
    timeOut.QuadPart = 0;

    DbgPrint("sending %lu bytes data to user-end", event.GetCurrentSize());

    status = FltSendMessage(g_ScannerData.Filter,
        &g_ScannerData.ClientPort,
        (PVOID)event.GetBuffer(),
        event.GetCurrentSize(),
        NULL,
        NULL,
        &timeOut);

    //DbgPrintHex(event.GetBuffer(), event.GetCurrentSize());
    if (status == STATUS_SUCCESS) {
        DbgPrint("!!! successfully process sent event to user-mode");
    }
    else {
        DbgPrint("!!! couldn't send process event to user-mode, status 0x%X\n", status);

    }
    /*UNREFERENCED_PARAMETER(Process);
    if (CreateInfo) {
        KdPrint(("Process Create (%u)\n", HandleToUlong(ProcessId)));
        //
        // process created
        //
        auto imagePath = CreateInfo->ImageFileName;
        if (!imagePath)
            return;

        PROCESS_EVENT_DATA eventData = { 0 };
        eventData.ProcessId = HandleToULong(ProcessId);
        eventData.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
        eventData.ImagePath = *CreateInfo->ImageFileName;
        if (CreateInfo->CommandLine) {
            eventData.CommandLine = *CreateInfo->CommandLine;
        }
        else {
            RtlInitUnicodeString(&eventData.CommandLine, L"");
        }
        RtlInitUnicodeString(&eventData.UserSid, L"Unknown");

        // Set rule name based on your rule evaluation
        UNICODE_STRING ruleName;
        RtlInitUnicodeString(&ruleName, L"DefaultRule");
        eventData.RuleName = ruleName;

        PRULE_ENTRY matched = g_State.LookupRule((PUNICODE_STRING)CreateInfo->ImageFileName);
        if (matched) {
            if (matched->Action == RuleAction::Block) {
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                LogProcessEvent(RuleAction::Block, &eventData);
                KdPrint(("Blocked execution of %wZ\n", imagePath));
                
            }
            else {
                LogProcessEvent(RuleAction::Audit, &eventData);
                KdPrint(("Audited execution of %wZ\n", imagePath));
            }
        }
        else if (g_State.IsProcessWhitelist()) {
            auto defautlProcessPosture = g_State.GetDefaultProcessPosture();
            if (defautlProcessPosture == RuleAction::Audit) {
                LogProcessEvent(RuleAction::Audit, &eventData);
                KdPrint(("Audited execution of not allowed process %wZ\n", imagePath));
            }
            else if (defautlProcessPosture == RuleAction::Block) {
                KdPrint(("Blocking execution of not allowed process is not supported"));
            }
        }
    }
    else {
        KdPrint(("Process Exit (%u)\n", HandleToUlong(ProcessId)));
    }*/
}

