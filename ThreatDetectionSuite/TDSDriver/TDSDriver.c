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
BOOLEAN g_MonitoringActive = FALSE;

// WFP handles
HANDLE g_EngineHandle = NULL;
UINT32 g_CalloutId = 0;

// DEFINE_GUID for WFP Callout
DEFINE_GUID(TDS_WFP_CALLOUT_GUID, 0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12);

typedef struct _TDS_PENDING_IRP {
    LIST_ENTRY ListEntry;
    PIRP Irp;
} TDS_PENDING_IRP, *PTDS_PENDING_IRP;

typedef struct _EVENT_ITEM {
    LIST_ENTRY ListEntry;
    TDS_EVENT_HEADER Event;
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
    RtlInitUnicodeString(&lsassName, L"lsass.exe");
    PUNICODE_STRING procName = NULL;
    SeLocateProcessImageName(Process, &procName);
    if (procName) {
        BOOLEAN match = RtlSuffixUnicodeString(&lsassName, procName, TRUE);
        ExFreePool(procName);
        return match;
    }
    return FALSE;
}

void DispatchPendingEvents() {
    KIRQL irpIrql, eventIrql;
    
    KeAcquireSpinLock(&g_EventQueueLock, &eventIrql);
    if (IsListEmpty(&g_EventQueueHead)) {
        KeReleaseSpinLock(&g_EventQueueLock, eventIrql);
        return;
    }

    KeAcquireSpinLock(&g_IrpQueueLock, &irpIrql);
    if (IsListEmpty(&g_PendingIrpList)) {
        KeReleaseSpinLock(&g_IrpQueueLock, irpIrql);
        KeReleaseSpinLock(&g_EventQueueLock, eventIrql);
        return;
    }

    PLIST_ENTRY irpEntry = RemoveHeadList(&g_PendingIrpList);
    PTDS_PENDING_IRP pIrp = CONTAINING_RECORD(irpEntry, TDS_PENDING_IRP, ListEntry);
    
    PLIST_ENTRY eventEntry = RemoveHeadList(&g_EventQueueHead);
    PEVENT_ITEM pEvent = CONTAINING_RECORD(eventEntry, EVENT_ITEM, ListEntry);

    KeReleaseSpinLock(&g_IrpQueueLock, irpIrql);
    KeReleaseSpinLock(&g_EventQueueLock, eventIrql);

    PIRP Irp = pIrp->Irp;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG requiredLen = sizeof(TDS_EVENT_HEADER) + pEvent->Event.DataSize;

    if (outLen >= requiredLen) {
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &pEvent->Event, requiredLen);
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
        PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_ITEM) + dataSize, 'SDTe');
        if (item) {
            RtlZeroMemory(item, sizeof(EVENT_ITEM) + dataSize);
            item->Event.Type = TDSEventNetworkConnect;
            item->Event.ProcessId = pid;
            item->Event.DataSize = dataSize;
            KeQuerySystemTimePrecise((PLARGE_INTEGER)&item->Event.Timestamp);

            PTDS_NETWORK_EVENT_DATA nEvent = (PTDS_NETWORK_EVENT_DATA)(&item->Event + 1);
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
    FWPS_CALLOUT0 callout = {0};
    callout.calloutKey = TDS_WFP_CALLOUT_GUID;
    callout.classifyFn = WfpClassifyOutbound;
    callout.notifyFn = WfpNotify;
    
    NTSTATUS status = FwpsCalloutRegister0(DeviceObject, &callout, &g_CalloutId);
    if (!NT_SUCCESS(status)) return status;

    return STATUS_SUCCESS;
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
    RtlInitUnicodeString(&obRegistration.Altitude, L"388888");
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
    if (g_CalloutId) FwpsCalloutUnregisterById0(g_CalloutId);

    KIRQL irql;
    KeAcquireSpinLock(&g_IrpQueueLock, &irql);
    while (!IsListEmpty(&g_PendingIrpList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_PendingIrpList);
        PTDS_PENDING_IRP pIrp = CONTAINING_RECORD(entry, TDS_PENDING_IRP, ListEntry);
        pIrp->Irp->IoStatus.Status = STATUS_CANCELLED;
        IoCompleteRequest(pIrp->Irp, IO_NO_INCREMENT);
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
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS TDSDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_TDS_SET_PROTECTION_POLICY:
            if (Irp->RequestorMode != KernelMode && !SeSinglePrivilegeCheck(SeExports->SeDebugPrivilege, Irp->RequestorMode)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            g_EdrPid = HandleToUlong(PsGetCurrentProcessId());
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            break;

        case IOCTL_TDS_GET_NEXT_EVENT: {
            KIRQL irql;
            PTDS_PENDING_IRP pIrp = (PTDS_PENDING_IRP)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(TDS_PENDING_IRP), 'SDTe');
            if (pIrp) {
                pIrp->Irp = Irp;
                IoMarkIrpPending(Irp);
                
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
    
    ULONG dataSize = CreateInfo ? sizeof(TDS_PROCESS_EVENT_DATA) + CreateInfo->ImageFileName->Length + (CreateInfo->CommandLine ? CreateInfo->CommandLine->Length : 0) : 0;
    
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_ITEM) + dataSize, 'SDTe');
    if (!item) return;

    RtlZeroMemory(item, sizeof(EVENT_ITEM) + dataSize);
    item->Event.Type = CreateInfo ? TDSEventProcessCreate : TDSEventProcessTerminate;
    item->Event.ProcessId = HandleToUlong(ProcessId);
    item->Event.DataSize = dataSize;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&item->Event.Timestamp);

    if (CreateInfo) {
        PTDS_PROCESS_EVENT_DATA pEvent = (PTDS_PROCESS_EVENT_DATA)(&item->Event + 1);
        pEvent->Create = TRUE;
        pEvent->ParentProcessId = HandleToUlong(CreateInfo->ParentProcessId);
        
        PUCHAR buffer = (PUCHAR)(pEvent + 1);
        pEvent->ImagePathOffset = (ULONG)(buffer - (PUCHAR)(&item->Event + 1));
        RtlCopyMemory(buffer, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
        buffer += CreateInfo->ImageFileName->Length;
        
        if (CreateInfo->CommandLine) {
            pEvent->CommandLineOffset = (ULONG)(buffer - (PUCHAR)(&item->Event + 1));
            RtlCopyMemory(buffer, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);
        }
    }

    QueueTDSEvent(item);
}

void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    ULONG dataSize = sizeof(TDS_IMAGE_LOAD_DATA) + (FullImageName ? FullImageName->Length : 0);
    
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_ITEM) + dataSize, 'SDTe');
    if (!item) return;

    RtlZeroMemory(item, sizeof(EVENT_ITEM) + dataSize);
    item->Event.Type = TDSEventImageLoad;
    item->Event.ProcessId = HandleToUlong(ProcessId);
    item->Event.DataSize = dataSize;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&item->Event.Timestamp);

    PTDS_IMAGE_LOAD_DATA iEvent = (PTDS_IMAGE_LOAD_DATA)(&item->Event + 1);
    iEvent->LoadAddress = (ULONG64)ImageInfo->ImageBase;
    iEvent->ImageSize = (ULONG64)ImageInfo->ImageSize;

    if (FullImageName) {
        PUCHAR buffer = (PUCHAR)(iEvent + 1);
        iEvent->ImagePathOffset = (ULONG)(buffer - (PUCHAR)(&item->Event + 1));
        RtlCopyMemory(buffer, FullImageName->Buffer, FullImageName->Length);
    }

    QueueTDSEvent(item);
}
