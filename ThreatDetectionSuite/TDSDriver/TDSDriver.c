#include <ntifs.h>
#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>
#include "../TDSCommon/TDSCommon.h"

NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(_In_ PEPROCESS Process);

PDEVICE_OBJECT g_DeviceObject = NULL;

KSPIN_LOCK g_IrpQueueLock;
LIST_ENTRY g_PendingIrpList;

KSPIN_LOCK g_EventQueueLock;
LIST_ENTRY g_EventQueueHead;

PVOID g_ObRegistrationHandle = NULL;
ULONG g_EdrPid = 0;
ULONG g_ServicePid = 0; // FIX: Track the PID of the service that opened the device (Issue 11)
BOOLEAN g_MonitoringActive = FALSE;

// WFP handles
HANDLE g_EngineHandle = NULL;
UINT32 g_CalloutId = 0;
UINT64 g_FilterId = 0;

// FIX: Unique GUID for WFP Callout (Issue 9)
// {B2A1C3D4-E5F6-4A7B-8C9D-E0F1A2B3C4D5}
DEFINE_GUID(TDS_WFP_CALLOUT_GUID, 0xb2a1c3d4, 0xe5f6, 0x4a7b, 0x8c, 0x9d, 0xe0, 0xf1, 0xa2, 0xb3, 0xc4, 0xd5);

typedef struct _TDS_PENDING_IRP {
    LIST_ENTRY ListEntry;
    PIRP Irp;
} TDS_PENDING_IRP, *PTDS_PENDING_IRP;

// FIX: Correct struct packing for event item (Issue 5)
typedef struct _EVENT_ITEM {
    LIST_ENTRY ListEntry;
    ULONG TotalSize;
    // The actual event data follows immediately.
    // Memory layout: [EVENT_ITEM] [TDS_EVENT_HEADER] [TDS_*_DATA] [Variable Strings...]
} EVENT_ITEM, *PEVENT_ITEM;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS TDSDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS TDSDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

PVOID GetProcessPeb(PEPROCESS Process) {
    PVOID peb = PsGetProcessWow64Process(Process);
    if (!peb) peb = PsGetProcessPeb(Process);
    return peb;
}

BOOLEAN IsLsass(PEPROCESS Process) {
    UNICODE_STRING lsassName;
    RtlInitUnicodeString(&lsassName, L"\\Windows\\System32\\lsass.exe");
    PUNICODE_STRING procName = NULL;
    SeLocateProcessImageName(Process, &procName);
    if (procName) {
        BOOLEAN match = RtlSuffixUnicodeString(&lsassName, procName, TRUE);
        ExFreePool(procName);
        return match;
    }
    return FALSE;
}

VOID CancelPendingIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    KIRQL irql;

    IoReleaseCancelSpinLock(Irp->CancelIrql);

    KeAcquireSpinLock(&g_IrpQueueLock, &irql);
    RemoveEntryList(&((PTDS_PENDING_IRP)Irp->Tail.Overlay.DriverContext[0])->ListEntry);
    ExFreePoolWithTag(Irp->Tail.Overlay.DriverContext[0], 'SDTe');
    KeReleaseSpinLock(&g_IrpQueueLock, irql);

    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

void DispatchPendingEvents() {
    KIRQL irpIrql, eventIrql;
    
    // FIX: Canonical locking order to prevent deadlocks (Issue 1)
    // Always lock IRP queue first, then Event queue
    KeAcquireSpinLock(&g_IrpQueueLock, &irpIrql);
    KeAcquireSpinLock(&g_EventQueueLock, &eventIrql);

    if (IsListEmpty(&g_PendingIrpList) || IsListEmpty(&g_EventQueueHead)) {
        KeReleaseSpinLock(&g_EventQueueLock, eventIrql);
        KeReleaseSpinLock(&g_IrpQueueLock, irpIrql);
        return;
    }

    PLIST_ENTRY irpEntry = RemoveHeadList(&g_PendingIrpList);
    PTDS_PENDING_IRP pIrp = CONTAINING_RECORD(irpEntry, TDS_PENDING_IRP, ListEntry);
    
    PLIST_ENTRY eventEntry = RemoveHeadList(&g_EventQueueHead);
    PEVENT_ITEM pEvent = CONTAINING_RECORD(eventEntry, EVENT_ITEM, ListEntry);

    PIRP Irp = pIrp->Irp;
    
    // FIX: Clear cancel routine safely (Issue 8)
    if (IoSetCancelRoutine(Irp, NULL) == NULL) {
        // IRP is being cancelled. The cancel routine will complete it.
        // We must put the event back and free the pIrp wrapper.
        InsertHeadList(&g_EventQueueHead, &pEvent->ListEntry);
        KeReleaseSpinLock(&g_EventQueueLock, eventIrql);
        KeReleaseSpinLock(&g_IrpQueueLock, irpIrql);
        ExFreePoolWithTag(pIrp, 'SDTe');
        return;
    }

    KeReleaseSpinLock(&g_EventQueueLock, eventIrql);
    KeReleaseSpinLock(&g_IrpQueueLock, irpIrql);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    
    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(pEvent + 1);
    ULONG requiredLen = sizeof(TDS_EVENT_HEADER) + header->DataSize;

    if (outLen >= requiredLen) {
        // IOCTL_TDS_GET_NEXT_EVENT is METHOD_BUFFERED
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, header, requiredLen);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = requiredLen;
    } else {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    ExFreePoolWithTag(pIrp, 'SDTe');
    ExFreePoolWithTag(pEvent, 'SDTe');
}

void QueueTDSEvent(PEVENT_ITEM item) {
    KIRQL irql;
    KeAcquireSpinLock(&g_EventQueueLock, &irql);
    InsertTailList(&g_EventQueueHead, &item->ListEntry);
    KeReleaseSpinLock(&g_EventQueueLock, irql);
    
    DispatchPendingEvents();
}

void WfpClassifyOutbound(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut) 
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        ULONG pid = (ULONG)inMetaValues->processId;
        
        ULONG dataSize = sizeof(TDS_NETWORK_EVENT_DATA);
        ULONG totalItemSize = sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize;
        PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, totalItemSize, 'SDTe');
        
        if (item) {
            RtlZeroMemory(item, totalItemSize);
            item->TotalSize = totalItemSize;
            
            PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
            header->Type = TDSEventNetworkConnect;
            header->ProcessId = pid;
            header->DataSize = dataSize;
            KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);

            PTDS_NETWORK_EVENT_DATA nEvent = (PTDS_NETWORK_EVENT_DATA)(header + 1);
            if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.type == FWP_UINT32) {
                nEvent->RemoteAddress = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
            }
            if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.type == FWP_UINT16) {
                nEvent->RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
            }
            if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.type == FWP_UINT8) {
                nEvent->Protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
            }

            QueueTDSEvent(item);
        }
    }
}

NTSTATUS WfpNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID* filterKey, FWPS_FILTER0* filter) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

NTSTATUS InitializeWFP(PDEVICE_OBJECT DeviceObject) {
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    
    // FIX: Open engine, add callout, add filter (Issue 6, 7)
    NTSTATUS status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) return status;

    FWPS_CALLOUT0 sCallout = {0};
    sCallout.calloutKey = TDS_WFP_CALLOUT_GUID;
    sCallout.classifyFn = WfpClassifyOutbound;
    sCallout.notifyFn = WfpNotify;
    
    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &g_CalloutId);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        return status;
    }

    FWPM_CALLOUT0 mCallout = {0};
    mCallout.calloutKey = TDS_WFP_CALLOUT_GUID;
    mCallout.displayData.name = L"TDS Network Callout";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        FwpsCalloutUnregisterById0(g_CalloutId);
        g_CalloutId = 0;
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        return status;
    }

    FWPM_FILTER0 filter = {0};
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"TDS Network Filter";
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = TDS_WFP_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterId);
    if (!NT_SUCCESS(status)) {
        // Dynamic session will clean up the mCallout
        FwpsCalloutUnregisterById0(g_CalloutId);
        g_CalloutId = 0;
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    return status;
}

OB_PRE_CALLBACK_STATUS TDSPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
        ULONG targetPid = HandleToUlong(PsGetProcessId(targetProcess));
        
        if (g_EdrPid != 0 && targetPid == g_EdrPid) {
            ACCESS_MASK forbidden = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME;
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~forbidden;
            } else {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~forbidden;
            }
        }

        if (IsLsass(targetProcess)) {
            ACCESS_MASK forbidden = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME;
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~forbidden;
            } else {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~forbidden;
            }
        }
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterObCallbacks() {
    OB_CALLBACK_REGISTRATION obRegistration;
    OB_OPERATION_REGISTRATION opRegistration;

    RtlZeroMemory(&obRegistration, sizeof(obRegistration));
    obRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    obRegistration.OperationRegistrationCount = 1;
    // FIX: Correct altitude for AV/EDR (Issue 13)
    RtlInitUnicodeString(&obRegistration.Altitude, L"320123");
    obRegistration.RegistrationContext = NULL;

    RtlZeroMemory(&opRegistration, sizeof(opRegistration));
    opRegistration.ObjectType = PsProcessType;
    opRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegistration.PreOperation = TDSPreCallback;
    opRegistration.PostOperation = NULL;

    obRegistration.OperationRegistration = &opRegistration;
    return ObRegisterCallbacks(&obRegistration, &g_ObRegistrationHandle);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNICODE_STRING deviceName, symLink;

    RtlInitUnicodeString(&deviceName, L"\\Device\\ThreatDetectionSuite");
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\ThreatDetectionSuite");

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = TDSDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TDSDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TDSDispatchDeviceControl;

    InitializeListHead(&g_PendingIrpList);
    KeInitializeSpinLock(&g_IrpQueueLock);
    InitializeListHead(&g_EventQueueHead);
    KeInitializeSpinLock(&g_EventQueueLock);

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    if (NT_SUCCESS(status)) {
        status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    }
    if (NT_SUCCESS(status)) {
        status = RegisterObCallbacks();
    }
    if (NT_SUCCESS(status)) {
        status = InitializeWFP(g_DeviceObject);
    }

    if (NT_SUCCESS(status)) {
        g_MonitoringActive = TRUE;
    } else {
        DriverUnload(DriverObject);
    }

    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\ThreatDetectionSuite");
    IoDeleteSymbolicLink(&symLink);

    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    
    if (g_ObRegistrationHandle) ObUnRegisterCallbacks(g_ObRegistrationHandle);
    
    // FIX: Safe teardown of WFP (Issue 12)
    if (g_EngineHandle) {
        // dynamic session handles filter/callout deletion, but we must unregister the kernel callback
        if (g_CalloutId) FwpsCalloutUnregisterById0(g_CalloutId);
        FwpmEngineClose0(g_EngineHandle);
    }

    KIRQL irql;
    KeAcquireSpinLock(&g_IrpQueueLock, &irql);
    while (!IsListEmpty(&g_PendingIrpList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_PendingIrpList);
        PTDS_PENDING_IRP pIrp = CONTAINING_RECORD(entry, TDS_PENDING_IRP, ListEntry);
        
        if (IoSetCancelRoutine(pIrp->Irp, NULL) != NULL) {
            pIrp->Irp->IoStatus.Status = STATUS_CANCELLED;
            pIrp->Irp->IoStatus.Information = 0;
            IoCompleteRequest(pIrp->Irp, IO_NO_INCREMENT);
        }
        ExFreePoolWithTag(pIrp, 'SDTe');
    }
    KeReleaseSpinLock(&g_IrpQueueLock, irql);

    KeAcquireSpinLock(&g_EventQueueLock, &irql);
    while (!IsListEmpty(&g_EventQueueHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_EventQueueHead);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, EVENT_ITEM, ListEntry), 'SDTe');
    }
    KeReleaseSpinLock(&g_EventQueueLock, irql);

    IoDeleteDevice(g_DeviceObject);
}

NTSTATUS TDSDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    if (irpSp->MajorFunction == IRP_MJ_CREATE) {
        // FIX: Track Service PID (Issue 11)
        if (g_ServicePid == 0) {
            g_ServicePid = HandleToUlong(PsGetCurrentProcessId());
        }
    } else if (irpSp->MajorFunction == IRP_MJ_CLOSE) {
        if (HandleToUlong(PsGetCurrentProcessId()) == g_ServicePid) {
            g_ServicePid = 0;
            g_EdrPid = 0;
        }
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS TDSDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    ULONG currentPid = HandleToUlong(PsGetCurrentProcessId());

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_TDS_SET_PROTECTION_POLICY:
            // FIX: Enforce that only the tracked service PID can configure protection (Issue 10)
            if (currentPid != g_ServicePid || !SeSinglePrivilegeCheck(SeExports->SeDebugPrivilege, Irp->RequestorMode)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            g_EdrPid = currentPid;
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            break;

        case IOCTL_TDS_GET_NEXT_EVENT: {
            if (currentPid != g_ServicePid) {
                status = STATUS_ACCESS_DENIED;
                break;
            }

            PTDS_PENDING_IRP pIrp = (PTDS_PENDING_IRP)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(TDS_PENDING_IRP), 'SDTe');
            if (pIrp) {
                pIrp->Irp = Irp;
                Irp->Tail.Overlay.DriverContext[0] = pIrp;
                
                IoMarkIrpPending(Irp);
                IoSetCancelRoutine(Irp, CancelPendingIrp);
                
                KIRQL irql;
                KeAcquireSpinLock(&g_IrpQueueLock, &irql);
                InsertTailList(&g_PendingIrpList, &pIrp->ListEntry);
                KeReleaseSpinLock(&g_IrpQueueLock, irql);
                
                DispatchPendingEvents();
                return STATUS_PENDING;
            }
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
    }

    if (status != STATUS_PENDING) {
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    return status;
}

void ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    
    ULONG dataSize = sizeof(TDS_PROCESS_EVENT_DATA);
    ULONG imgLen = 0;
    ULONG cmdLen = 0;

    // FIX: Verify pointers before access (Issue 3)
    if (CreateInfo) {
        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            imgLen = CreateInfo->ImageFileName->Length;
        }
        if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer) {
            cmdLen = CreateInfo->CommandLine->Length;
        }
        dataSize += imgLen + cmdLen;
    }
    
    ULONG totalSize = sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize;
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, totalSize, 'SDTe');
    if (!item) return;

    RtlZeroMemory(item, totalSize);
    item->TotalSize = totalSize;

    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
    header->Type = CreateInfo ? TDSEventProcessCreate : TDSEventProcessTerminate;
    header->ProcessId = HandleToUlong(ProcessId);
    header->DataSize = dataSize;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);

    if (CreateInfo) {
        PTDS_PROCESS_EVENT_DATA pEvent = (PTDS_PROCESS_EVENT_DATA)(header + 1);
        pEvent->Create = TRUE;
        pEvent->ParentProcessId = HandleToUlong(CreateInfo->ParentProcessId);
        
        PUCHAR buffer = (PUCHAR)(pEvent + 1);
        ULONG remaining = totalSize - (ULONG)(buffer - (PUCHAR)item);

        // FIX: Strict bounds checking to prevent buffer overflow (Issue 4)
        if (imgLen > 0 && remaining >= imgLen) {
            pEvent->ImagePathOffset = (ULONG)(buffer - (PUCHAR)header);
            RtlCopyMemory(buffer, CreateInfo->ImageFileName->Buffer, imgLen);
            buffer += imgLen;
            remaining -= imgLen;
        }
        
        if (cmdLen > 0 && remaining >= cmdLen) {
            pEvent->CommandLineOffset = (ULONG)(buffer - (PUCHAR)header);
            RtlCopyMemory(buffer, CreateInfo->CommandLine->Buffer, cmdLen);
        }
    }

    QueueTDSEvent(item);
}

void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    ULONG imgLen = (FullImageName && FullImageName->Buffer) ? FullImageName->Length : 0;
    ULONG dataSize = sizeof(TDS_IMAGE_LOAD_DATA) + imgLen;
    ULONG totalSize = sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize;
    
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, totalSize, 'SDTe');
    if (!item) return;

    RtlZeroMemory(item, totalSize);
    item->TotalSize = totalSize;

    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
    header->Type = TDSEventImageLoad;
    header->ProcessId = HandleToUlong(ProcessId);
    header->DataSize = dataSize;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);

    PTDS_IMAGE_LOAD_DATA iEvent = (PTDS_IMAGE_LOAD_DATA)(header + 1);
    iEvent->LoadAddress = (ULONG64)ImageInfo->ImageBase;
    iEvent->ImageSize = (ULONG64)ImageInfo->ImageSize;

    if (imgLen > 0) {
        PUCHAR buffer = (PUCHAR)(iEvent + 1);
        iEvent->ImagePathOffset = (ULONG)(buffer - (PUCHAR)header);
        RtlCopyMemory(buffer, FullImageName->Buffer, imgLen);
    }

    QueueTDSEvent(item);
}
