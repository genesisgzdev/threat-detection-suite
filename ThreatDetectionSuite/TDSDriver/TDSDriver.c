#include <ntifs.h>
#include <ntddk.h>
#include <fltKernel.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>
#include "../TDSCommon/TDSCommon.h"

NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(_In_ PEPROCESS Process);

PDEVICE_OBJECT g_DeviceObject = NULL;
PFLT_FILTER g_FilterHandle = NULL;

KSPIN_LOCK g_IrpQueueLock;
LIST_ENTRY g_PendingIrpList;

KSPIN_LOCK g_EventQueueLock;
LIST_ENTRY g_EventQueueHead;

PVOID g_ObRegistrationHandle = NULL;
LARGE_INTEGER g_RegistryCookie = {0};
ULONG g_EdrPid = 0;
ULONG g_ServicePid = 0; 
BOOLEAN g_MonitoringActive = FALSE;

// WFP handles
HANDLE g_EngineHandle = NULL;
UINT32 g_CalloutIdV4 = 0;
UINT32 g_CalloutIdV6 = 0;
UINT32 g_CalloutIdDgV4 = 0;
UINT32 g_CalloutIdDgV6 = 0;
UINT64 g_FilterIdV4 = 0;
UINT64 g_FilterIdV6 = 0;
UINT64 g_FilterIdDgV4 = 0;
UINT64 g_FilterIdDgV6 = 0;

// FIX: Professional, non-sequential WFP Callout GUIDs (Issue 3)
// {EB6A1F3C-7D4E-4B2A-9C8D-1E2F3A4B5C6D}
DEFINE_GUID(TDS_WFP_CALLOUT_V4_GUID, 0xeb6a1f3c, 0x7d4e, 0x4b2a, 0x9c, 0x8d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d);
// {A1B2C3D4-E5F6-4A1B-8C9D-E0F1A2B3C4D5}
DEFINE_GUID(TDS_WFP_CALLOUT_V6_GUID, 0xa1b2c3d4, 0xe5f6, 0x4a1b, 0x8c, 0x9d, 0xe0, 0xf1, 0xa2, 0xb3, 0xc4, 0xd5);
// {F1E2D3C4-B5A6-4987-8E7D-6C5B4A392817}
DEFINE_GUID(TDS_WFP_CALLOUT_DATAGRAM_V4_GUID, 0xf1e2d3c4, 0xb5a6, 0x4987, 0x8e, 0x7d, 0x6c, 0x5b, 0x4a, 0x39, 0x28, 0x17);
// {D1C2B3A4-9E8D-4C7B-6A5F-4E3D2C1B0A98}
DEFINE_GUID(TDS_WFP_CALLOUT_DATAGRAM_V6_GUID, 0xd1c2b3a4, 0x9e8d, 0x4c7b, 0x6a, 0x5f, 0x4e, 0x3d, 0x2c, 0x1b, 0x0a, 0x98);

typedef struct _TDS_PENDING_IRP {
    LIST_ENTRY ListEntry;
    PIRP Irp;
} TDS_PENDING_IRP, *PTDS_PENDING_IRP;

typedef struct _EVENT_ITEM {
    LIST_ENTRY ListEntry;
    ULONG TotalSize;
} EVENT_ITEM, *PEVENT_ITEM;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS TDSDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS TDSDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
void ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);

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
    PTDS_PENDING_IRP pIrp = (PTDS_PENDING_IRP)Irp->Tail.Overlay.DriverContext[0];
    if (pIrp) {
        RemoveEntryList(&pIrp->ListEntry);
        ExFreePoolWithTag(pIrp, 'SDTe');
    }
    KeReleaseSpinLock(&g_IrpQueueLock, irql);

    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

void DispatchPendingEvents() {
    KIRQL irpIrql, eventIrql;
    
    // Canonical locking order: IRP first, then Events
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
    
    if (IoSetCancelRoutine(Irp, NULL) == NULL) {
        // IRP is being cancelled. Re-queue event and wait for next IRP.
        InsertHeadList(&g_EventQueueHead, &pEvent->ListEntry);
        KeReleaseSpinLock(&g_EventQueueLock, eventIrql);
        KeReleaseSpinLock(&g_IrpQueueLock, irpIrql);
        ExFreePoolWithTag(pIrp, 'SDTe');
        return;
    }

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    
    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(pEvent + 1);
    ULONG requiredLen = sizeof(TDS_EVENT_HEADER) + header->DataSize;

    if (outLen >= requiredLen) {
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, header, requiredLen);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = requiredLen;
        
        KeReleaseSpinLock(&g_EventQueueLock, eventIrql);
        KeReleaseSpinLock(&g_IrpQueueLock, irpIrql);
        
        ExFreePoolWithTag(pEvent, 'SDTe');
    } else {
        // FIX: Buffer too small - Put event back in head, don't drop it (Issue 1)
        InsertHeadList(&g_EventQueueHead, &pEvent->ListEntry);
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        
        KeReleaseSpinLock(&g_EventQueueLock, eventIrql);
        KeReleaseSpinLock(&g_IrpQueueLock, irpIrql);
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    ExFreePoolWithTag(pIrp, 'SDTe');
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

            if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4 || inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V4) {
                nEvent->AddressFamily = 2; // AF_INET
                UINT16 addrIdx = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS;
                UINT16 portIdx = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT : FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT;
                UINT16 protoIdx = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL : FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL;

                if (inFixedValues->incomingValue[addrIdx].value.type == FWP_UINT32) nEvent->Ipv4Address = inFixedValues->incomingValue[addrIdx].value.uint32;
                if (inFixedValues->incomingValue[portIdx].value.type == FWP_UINT16) nEvent->RemotePort = inFixedValues->incomingValue[portIdx].value.uint16;
                if (inFixedValues->incomingValue[protoIdx].value.type == FWP_UINT8) nEvent->Protocol = inFixedValues->incomingValue[protoIdx].value.uint8;
            } 
            else if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6 || inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6) {
                nEvent->AddressFamily = 23; // AF_INET6
                UINT16 addrIdx = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS;
                UINT16 portIdx = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT;
                UINT16 protoIdx = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL : FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL;

                if (inFixedValues->incomingValue[addrIdx].value.type == FWP_BYTE_ARRAY16_TYPE && inFixedValues->incomingValue[addrIdx].value.byteArray16) {
                    RtlCopyMemory(nEvent->Ipv6Address, inFixedValues->incomingValue[addrIdx].value.byteArray16->byteArray16, 16);
                }
                if (inFixedValues->incomingValue[portIdx].value.type == FWP_UINT16) nEvent->RemotePort = inFixedValues->incomingValue[portIdx].value.uint16;
                if (inFixedValues->incomingValue[protoIdx].value.type == FWP_UINT8) nEvent->Protocol = inFixedValues->incomingValue[protoIdx].value.uint8;
            }

            QueueTDSEvent(item);
        }
    }
}

NTSTATUS WfpNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID* filterKey, FWPS_FILTER0* filter) {
    UNREFERENCED_PARAMETER(notifyType); UNREFERENCED_PARAMETER(filterKey); UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

NTSTATUS InitializeWFP(PDEVICE_OBJECT DeviceObject) {
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    
    NTSTATUS status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) return status;

    FWPS_CALLOUT0 sCallout = {0};
    sCallout.classifyFn = WfpClassifyOutbound;
    sCallout.notifyFn = WfpNotify;
    
    sCallout.calloutKey = TDS_WFP_CALLOUT_V4_GUID;
    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &g_CalloutIdV4);
    if (!NT_SUCCESS(status)) goto Cleanup;

    sCallout.calloutKey = TDS_WFP_CALLOUT_V6_GUID;
    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &g_CalloutIdV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    sCallout.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V4_GUID;
    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &g_CalloutIdDgV4);
    if (!NT_SUCCESS(status)) goto Cleanup;

    sCallout.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V6_GUID;
    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &g_CalloutIdDgV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    FWPM_CALLOUT0 mCallout = {0};
    mCallout.displayData.name = L"TDS Callout";
    
    mCallout.calloutKey = TDS_WFP_CALLOUT_V4_GUID; mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL); if (!NT_SUCCESS(status)) goto Cleanup;

    mCallout.calloutKey = TDS_WFP_CALLOUT_V6_GUID; mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL); if (!NT_SUCCESS(status)) goto Cleanup;

    mCallout.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V4_GUID; mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL); if (!NT_SUCCESS(status)) goto Cleanup;

    mCallout.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V6_GUID; mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V6;
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL); if (!NT_SUCCESS(status)) goto Cleanup;

    FWPM_FILTER0 filter = {0};
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; filter.action.calloutKey = TDS_WFP_CALLOUT_V4_GUID;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdV4);

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6; filter.action.calloutKey = TDS_WFP_CALLOUT_V6_GUID;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdV6);

    filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4; filter.action.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V4_GUID;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdDgV4);

    filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V6; filter.action.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V6_GUID;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdDgV6);

    return STATUS_SUCCESS;

Cleanup:
    if (g_CalloutIdV4) FwpsCalloutUnregisterById0(g_CalloutIdV4);
    if (g_CalloutIdV6) FwpsCalloutUnregisterById0(g_CalloutIdV6);
    if (g_CalloutIdDgV4) FwpsCalloutUnregisterById0(g_CalloutIdDgV4);
    if (g_CalloutIdDgV6) FwpsCalloutUnregisterById0(g_CalloutIdDgV6);
    if (g_EngineHandle) { FwpmEngineClose0(g_EngineHandle); g_EngineHandle = NULL; }
    return status;
}

OB_PRE_CALLBACK_STATUS TDSPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    ULONG targetPid = 0;

    if (OperationInformation->ObjectType == *PsProcessType) {
        targetPid = HandleToUlong(PsGetProcessId((PEPROCESS)OperationInformation->Object));
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        targetPid = HandleToUlong(PsGetProcessId(IoThreadToProcess((PETHREAD)OperationInformation->Object)));
    }

    if (g_EdrPid != 0 && targetPid == g_EdrPid) {
        ACCESS_MASK forbidden = (OperationInformation->ObjectType == *PsProcessType) ? 
            (PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME) : 
            (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT);
        
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~forbidden;
        else OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~forbidden;
    }

    if (OperationInformation->ObjectType == *PsProcessType && IsLsass((PEPROCESS)OperationInformation->Object)) {
        ACCESS_MASK forbidden = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME;
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~forbidden;
        else OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~forbidden;
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterObCallbacks() {
    OB_CALLBACK_REGISTRATION obRegistration = {0};
    OB_OPERATION_REGISTRATION opRegistration[2] = {0};

    obRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    obRegistration.OperationRegistrationCount = 2;
    RtlInitUnicodeString(&obRegistration.Altitude, L"320123");
    
    opRegistration[0].ObjectType = PsProcessType;
    opRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegistration[0].PreOperation = TDSPreCallback;

    opRegistration[1].ObjectType = PsThreadType;
    opRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegistration[1].PreOperation = TDSPreCallback;

    obRegistration.OperationRegistration = opRegistration;
    return ObRegisterCallbacks(&obRegistration, &g_ObRegistrationHandle);
}

NTSTATUS TDSUnloadFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS TDSPostCreateCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags) {
    // FIX: Check draining to avoid BSOD (Issue 2)
    if (Flags & FLTFL_POST_OPERATION_DRAINING) return FLT_POSTOP_FINISHED_PROCESSING;
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);

    if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Information == FILE_DOES_NOT_EXIST)) return FLT_POSTOP_FINISHED_PROCESSING;

    if (Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE) {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
            FltParseFileNameInformation(nameInfo);
            ULONG pathLen = nameInfo->Name.Length;
            ULONG dataSize = sizeof(TDS_FILE_EVENT_DATA) + pathLen;
            PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize, 'SDTe');
            if (item) {
                RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize);
                PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
                header->Type = TDSEventFileDelete; header->ProcessId = HandleToUlong(PsGetCurrentProcessId()); header->DataSize = dataSize;
                KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);
                PTDS_FILE_EVENT_DATA fData = (PTDS_FILE_EVENT_DATA)(header + 1);
                fData->Operation = 2; fData->FilePathOffset = sizeof(TDS_EVENT_HEADER) + sizeof(TDS_FILE_EVENT_DATA);
                RtlCopyMemory((PUCHAR)header + fData->FilePathOffset, nameInfo->Name.Buffer, pathLen);
                QueueTDSEvent(item);
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS TDSPreSetInformationCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_opt_ PVOID *CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx || infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
            FltParseFileNameInformation(nameInfo);
            ULONG pathLen = nameInfo->Name.Length;
            ULONG targetLen = (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) ? ((PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->FileNameLength : 0;
            ULONG dataSize = sizeof(TDS_FILE_EVENT_DATA) + pathLen + targetLen;
            PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize, 'SDTe');
            if (item) {
                RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize);
                PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
                header->ProcessId = HandleToUlong(PsGetCurrentProcessId()); header->DataSize = dataSize;
                KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);
                PTDS_FILE_EVENT_DATA fData = (PTDS_FILE_EVENT_DATA)(header + 1);
                fData->FilePathOffset = sizeof(TDS_EVENT_HEADER) + sizeof(TDS_FILE_EVENT_DATA);
                RtlCopyMemory((PUCHAR)header + fData->FilePathOffset, nameInfo->Name.Buffer, pathLen);
                if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
                    header->Type = TDSEventFileOp; fData->Operation = 3; fData->TargetPathOffset = fData->FilePathOffset + pathLen;
                    RtlCopyMemory((PUCHAR)header + fData->TargetPathOffset, ((PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->FileName, targetLen);
                } else { header->Type = TDSEventFileDelete; fData->Operation = 2; }
                QueueTDSEvent(item);
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = { { IRP_MJ_CREATE, 0, NULL, TDSPostCreateCallback }, { IRP_MJ_SET_INFORMATION, 0, TDSPreSetInformationCallback, NULL }, { IRP_MJ_OPERATION_END } };
CONST FLT_REGISTRATION FilterRegistration = { sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, Callbacks, TDSUnloadFilter, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    if (notifyClass == RegNtPreSetValueKey || notifyClass == RegNtPreDeleteKey || notifyClass == RegNtPreDeleteValueKey || notifyClass == RegNtPreRenameKey) {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        UNICODE_STRING keyPath = { 0 }; ULONG size = 0;
        ObQueryNameString(info->Object, NULL, 0, &size);
        POBJECT_NAME_INFORMATION nameInfo = size > 0 ? (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, 'SDTe') : NULL;
        if (nameInfo && NT_SUCCESS(ObQueryNameString(info->Object, nameInfo, size, &size))) keyPath = nameInfo->Name;

        ULONG valueNameLen = (notifyClass == RegNtPreSetValueKey && info->ValueName) ? info->ValueName->Length : 0;
        ULONG dataBufSize = (notifyClass == RegNtPreSetValueKey && info->Data) ? (info->DataSize > 128 ? 128 : info->DataSize) : 0;
        ULONG dataSize = sizeof(TDS_REGISTRY_EVENT_DATA) + keyPath.Length + valueNameLen + dataBufSize;
        PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize, 'SDTe');
        if (item) {
            RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize);
            PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
            header->Type = (notifyClass == RegNtPreSetValueKey) ? TDSEventRegistrySet : (notifyClass == RegNtPreDeleteKey || notifyClass == RegNtPreDeleteValueKey) ? TDSEventRegistryDelete : TDSEventRegistryRename;
            header->ProcessId = HandleToUlong(PsGetCurrentProcessId()); header->DataSize = dataSize;
            KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);
            PTDS_REGISTRY_EVENT_DATA regData = (PTDS_REGISTRY_EVENT_DATA)(header + 1);
            regData->Type = (notifyClass == RegNtPreSetValueKey) ? info->Type : 0; regData->DataSize = (notifyClass == RegNtPreSetValueKey) ? info->DataSize : 0;
            PUCHAR buffer = (PUCHAR)(regData + 1);
            if (keyPath.Length > 0) { regData->KeyPathOffset = (ULONG)(buffer - (PUCHAR)header); RtlCopyMemory(buffer, keyPath.Buffer, keyPath.Length); buffer += keyPath.Length; }
            if (valueNameLen > 0) { regData->ValueNameOffset = (ULONG)(buffer - (PUCHAR)header); RtlCopyMemory(buffer, info->ValueName->Buffer, valueNameLen); buffer += valueNameLen; }
            if (dataBufSize > 0) { regData->DataOffset = (ULONG)(buffer - (PUCHAR)header); RtlCopyMemory(buffer, info->Data, dataBufSize); }
            QueueTDSEvent(item);
        }
        if (nameInfo) ExFreePoolWithTag(nameInfo, 'SDTe');
    }
    return STATUS_SUCCESS;
}

void ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (!Create) return;
    BOOLEAN isRemote = (ProcessId != PsGetCurrentProcessId());
    ULONG dataSize = isRemote ? sizeof(TDS_REMOTE_THREAD_DATA) : 0;
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize, 'SDTe');
    if (!item) return;
    RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize);
    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
    header->Type = isRemote ? TDSEventRemoteThread : TDSEventThreadCreate;
    header->ProcessId = HandleToUlong(PsGetCurrentProcessId()); header->ThreadId = HandleToUlong(ThreadId); header->DataSize = dataSize;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);
    if (isRemote) ((PTDS_REMOTE_THREAD_DATA)(header + 1))->TargetProcessId = HandleToUlong(ProcessId);
    QueueTDSEvent(item);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath); UNICODE_STRING deviceName, symLink;
    RtlInitUnicodeString(&deviceName, L"\\Device\\ThreatDetectionSuite"); RtlInitUnicodeString(&symLink, L"\\DosDevices\\ThreatDetectionSuite");
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&symLink, &deviceName); if (!NT_SUCCESS(status)) { IoDeleteDevice(g_DeviceObject); return status; }
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = TDSDispatchCreateClose; DriverObject->MajorFunction[IRP_MJ_CLOSE] = TDSDispatchCreateClose; DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TDSDispatchDeviceControl;
    InitializeListHead(&g_PendingIrpList); KeInitializeSpinLock(&g_IrpQueueLock); InitializeListHead(&g_EventQueueHead); KeInitializeSpinLock(&g_EventQueueLock);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE); PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine); PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    RegisterObCallbacks();
    UNICODE_STRING altitude; RtlInitUnicodeString(&altitude, L"320123"); CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegistryCookie, NULL);
    InitializeWFP(g_DeviceObject);
    FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle); if (g_FilterHandle) FltStartFiltering(g_FilterHandle);
    g_MonitoringActive = TRUE; return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink; RtlInitUnicodeString(&symLink, L"\\DosDevices\\ThreatDetectionSuite"); IoDeleteSymbolicLink(&symLink);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE); PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine); PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (g_RegistryCookie.QuadPart != 0) CmUnRegisterCallback(g_RegistryCookie);
    if (g_ObRegistrationHandle) ObUnRegisterCallbacks(g_ObRegistrationHandle);
    if (g_FilterHandle) { FltUnregisterFilter(g_FilterHandle); g_FilterHandle = NULL; }
    if (g_EngineHandle) { if (g_CalloutIdV4) FwpsCalloutUnregisterById0(g_CalloutIdV4); if (g_CalloutIdV6) FwpsCalloutUnregisterById0(g_CalloutIdV6); if (g_CalloutIdDgV4) FwpsCalloutUnregisterById0(g_CalloutIdDgV4); if (g_CalloutIdDgV6) FwpsCalloutUnregisterById0(g_CalloutIdDgV6); FwpmEngineClose0(g_EngineHandle); }
    KIRQL irql; KeAcquireSpinLock(&g_IrpQueueLock, &irql);
    while (!IsListEmpty(&g_PendingIrpList)) { PLIST_ENTRY entry = RemoveHeadList(&g_PendingIrpList); PTDS_PENDING_IRP pIrp = CONTAINING_RECORD(entry, TDS_PENDING_IRP, ListEntry); if (IoSetCancelRoutine(pIrp->Irp, NULL) != NULL) { pIrp->Irp->IoStatus.Status = STATUS_CANCELLED; IoCompleteRequest(pIrp->Irp, IO_NO_INCREMENT); } ExFreePoolWithTag(pIrp, 'SDTe'); }
    KeReleaseSpinLock(&g_IrpQueueLock, irql); KeAcquireSpinLock(&g_EventQueueLock, &irql);
    while (!IsListEmpty(&g_EventQueueHead)) { PLIST_ENTRY entry = RemoveHeadList(&g_EventQueueHead); ExFreePoolWithTag(CONTAINING_RECORD(entry, EVENT_ITEM, ListEntry), 'SDTe'); }
    KeReleaseSpinLock(&g_EventQueueLock, irql); IoDeleteDevice(g_DeviceObject);
}

NTSTATUS TDSDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject); PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    if (irpSp->MajorFunction == IRP_MJ_CREATE) { if (g_ServicePid == 0) g_ServicePid = HandleToUlong(PsGetCurrentProcessId()); }
    else if (irpSp->MajorFunction == IRP_MJ_CLOSE) { if (HandleToUlong(PsGetCurrentProcessId()) == g_ServicePid) { g_ServicePid = 0; g_EdrPid = 0; } }
    Irp->IoStatus.Status = STATUS_SUCCESS; IoCompleteRequest(Irp, IO_NO_INCREMENT); return STATUS_SUCCESS;
}

NTSTATUS TDSDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject); PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG currentPid = HandleToUlong(PsGetCurrentProcessId());
    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_TDS_SET_PROTECTION_POLICY: if (currentPid != g_ServicePid || !SeSinglePrivilegeCheck(SeExports->SeDebugPrivilege, Irp->RequestorMode)) { Irp->IoStatus.Status = STATUS_ACCESS_DENIED; break; }
            g_EdrPid = currentPid; Irp->IoStatus.Status = STATUS_SUCCESS; break;
        case IOCTL_TDS_GET_NEXT_EVENT: if (currentPid != g_ServicePid) { Irp->IoStatus.Status = STATUS_ACCESS_DENIED; break; }
            PTDS_PENDING_IRP pIrp = (PTDS_PENDING_IRP)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(TDS_PENDING_IRP), 'SDTe');
            if (pIrp) { pIrp->Irp = Irp; Irp->Tail.Overlay.DriverContext[0] = pIrp; IoMarkIrpPending(Irp); IoSetCancelRoutine(Irp, CancelPendingIrp);
                KIRQL irql; KeAcquireSpinLock(&g_IrpQueueLock, &irql); InsertTailList(&g_PendingIrpList, &pIrp->ListEntry); KeReleaseSpinLock(&g_IrpQueueLock, irql);
                DispatchPendingEvents(); return STATUS_PENDING; }
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES; break;
    }
    IoCompleteRequest(Irp, IO_NO_INCREMENT); return Irp->IoStatus.Status;
}

void ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process); ULONG imgLen = (CreateInfo && CreateInfo->ImageFileName) ? CreateInfo->ImageFileName->Length : 0;
    ULONG cmdLen = (CreateInfo && CreateInfo->CommandLine) ? CreateInfo->CommandLine->Length : 0;
    ULONG dataSize = sizeof(TDS_PROCESS_EVENT_DATA) + imgLen + cmdLen;
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize, 'SDTe');
    if (!item) return;
    RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize);
    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
    header->Type = CreateInfo ? TDSEventProcessCreate : TDSEventProcessTerminate; header->ProcessId = HandleToUlong(ProcessId); header->DataSize = dataSize;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);
    if (CreateInfo) {
        PTDS_PROCESS_EVENT_DATA pEvent = (PTDS_PROCESS_EVENT_DATA)(header + 1); pEvent->Create = TRUE; pEvent->ParentProcessId = HandleToUlong(CreateInfo->ParentProcessId);
        PUCHAR buffer = (PUCHAR)(pEvent + 1);
        if (imgLen > 0) { pEvent->ImagePathOffset = (ULONG)(buffer - (PUCHAR)header); RtlCopyMemory(buffer, CreateInfo->ImageFileName->Buffer, imgLen); buffer += imgLen; }
        if (cmdLen > 0) { pEvent->CommandLineOffset = (ULONG)(buffer - (PUCHAR)header); RtlCopyMemory(buffer, CreateInfo->CommandLine->Buffer, cmdLen); }
    }
    QueueTDSEvent(item);
}

void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    ULONG imgLen = (FullImageName && FullImageName->Buffer) ? FullImageName->Length : 0;
    ULONG dataSize = sizeof(TDS_IMAGE_LOAD_DATA) + imgLen;
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize, 'SDTe');
    if (!item) return;
    RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize);
    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
    header->Type = TDSEventImageLoad; header->ProcessId = HandleToUlong(ProcessId); header->DataSize = dataSize;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);
    PTDS_IMAGE_LOAD_DATA iEvent = (PTDS_IMAGE_LOAD_DATA)(header + 1); iEvent->LoadAddress = (ULONG64)ImageInfo->ImageBase; iEvent->ImageSize = (ULONG64)ImageInfo->ImageSize;
    if (imgLen > 0) { iEvent->ImagePathOffset = (ULONG)((PUCHAR)(iEvent + 1) - (PUCHAR)header); RtlCopyMemory(iEvent + 1, FullImageName->Buffer, imgLen); }
    QueueTDSEvent(item);
}
