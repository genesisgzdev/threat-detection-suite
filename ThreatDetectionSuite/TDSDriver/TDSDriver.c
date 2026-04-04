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
ULONG g_ServicePid = 0; // FIX: Track the PID of the service that opened the device (Issue 11)
BOOLEAN g_MonitoringActive = FALSE;

// WFP handles
HANDLE g_EngineHandle = NULL;
UINT32 g_CalloutId = 0;
UINT32 g_CalloutIdV6 = 0;
UINT32 g_CalloutIdDgV4 = 0;
UINT32 g_CalloutIdDgV6 = 0;
UINT64 g_FilterId = 0;
UINT64 g_FilterIdV6 = 0;
UINT64 g_FilterIdDgV4 = 0;
UINT64 g_FilterIdDgV6 = 0;

// FIX: Unique GUID for WFP Callout (Issue 9)
// {6447814A-5813-40E9-974A-4B95D0337C71}
DEFINE_GUID(TDS_WFP_CALLOUT_GUID, 0x6447814a, 0x5813, 0x40e9, 0x97, 0x4a, 0x4b, 0x95, 0xd0, 0x33, 0x7c, 0x71);
// {A4341934-8B63-4702-861C-84725345712C}
DEFINE_GUID(TDS_WFP_CALLOUT_V6_GUID, 0xa4341934, 0x8b63, 0x4702, 0x86, 0x1c, 0x84, 0x72, 0x53, 0x45, 0x71, 0x2c);
// {F692070E-1144-469A-9E23-7A91104E144A}
DEFINE_GUID(TDS_WFP_CALLOUT_DATAGRAM_V4_GUID, 0xf692070e, 0x1144, 0x469a, 0x9e, 0x23, 0x7a, 0x91, 0x10, 0x4e, 0x14, 0x4a);
// {C54E2401-447A-4416-8D6E-821F440A762D}
DEFINE_GUID(TDS_WFP_CALLOUT_DATAGRAM_V6_GUID, 0xc54e2401, 0x447a, 0x4416, 0x8d, 0x6e, 0x82, 0x1f, 0x44, 0x0a, 0x76, 0x2d);

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

                if (inFixedValues->incomingValue[addrIdx].value.type == FWP_UINT32) {
                    nEvent->Ipv4Address = inFixedValues->incomingValue[addrIdx].value.uint32;
                }
                if (inFixedValues->incomingValue[portIdx].value.type == FWP_UINT16) {
                    nEvent->RemotePort = inFixedValues->incomingValue[portIdx].value.uint16;
                }
                if (inFixedValues->incomingValue[protoIdx].value.type == FWP_UINT8) {
                    nEvent->Protocol = inFixedValues->incomingValue[protoIdx].value.uint8;
                }
            } 
            else if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6 || inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6) {
                nEvent->AddressFamily = 23; // AF_INET6
                
                UINT16 addrIdx = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS;
                UINT16 portIdx = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT;
                UINT16 protoIdx = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL : FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL;

                if (inFixedValues->incomingValue[addrIdx].value.type == FWP_BYTE_ARRAY16_TYPE && inFixedValues->incomingValue[addrIdx].value.byteArray16) {
                    RtlCopyMemory(nEvent->Ipv6Address, inFixedValues->incomingValue[addrIdx].value.byteArray16->byteArray16, 16);
                }
                if (inFixedValues->incomingValue[portIdx].value.type == FWP_UINT16) {
                    nEvent->RemotePort = inFixedValues->incomingValue[portIdx].value.uint16;
                }
                if (inFixedValues->incomingValue[protoIdx].value.type == FWP_UINT8) {
                    nEvent->Protocol = inFixedValues->incomingValue[protoIdx].value.uint8;
                }
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
    sCallout.classifyFn = WfpClassifyOutbound;
    sCallout.notifyFn = WfpNotify;
    
    sCallout.calloutKey = TDS_WFP_CALLOUT_GUID;
    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &g_CalloutId);
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
    
    mCallout.calloutKey = TDS_WFP_CALLOUT_GUID;
    mCallout.displayData.name = L"TDS Network Callout V4";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    mCallout.calloutKey = TDS_WFP_CALLOUT_V6_GUID;
    mCallout.displayData.name = L"TDS Network Callout V6";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    mCallout.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V4_GUID;
    mCallout.displayData.name = L"TDS Datagram Callout V4";
    mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    mCallout.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V6_GUID;
    mCallout.displayData.name = L"TDS Datagram Callout V6";
    mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V6;
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    FWPM_FILTER0 filter = {0};
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"TDS Network Filter V4";
    filter.action.calloutKey = TDS_WFP_CALLOUT_GUID;
    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterId);
    if (!NT_SUCCESS(status)) goto Cleanup;

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.displayData.name = L"TDS Network Filter V6";
    filter.action.calloutKey = TDS_WFP_CALLOUT_V6_GUID;
    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
    filter.displayData.name = L"TDS Datagram Filter V4";
    filter.action.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V4_GUID;
    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdDgV4);
    if (!NT_SUCCESS(status)) goto Cleanup;

    filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V6;
    filter.displayData.name = L"TDS Datagram Filter V6";
    filter.action.calloutKey = TDS_WFP_CALLOUT_DATAGRAM_V6_GUID;
    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdDgV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    return STATUS_SUCCESS;

Cleanup:
    if (g_CalloutId) FwpsCalloutUnregisterById0(g_CalloutId);
    if (g_CalloutIdV6) FwpsCalloutUnregisterById0(g_CalloutIdV6);
    if (g_CalloutIdDgV4) FwpsCalloutUnregisterById0(g_CalloutIdDgV4);
    if (g_CalloutIdDgV6) FwpsCalloutUnregisterById0(g_CalloutIdDgV6);
    g_CalloutId = g_CalloutIdV6 = g_CalloutIdDgV4 = g_CalloutIdDgV6 = 0;
    
    if (g_EngineHandle) {
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
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
        PEPROCESS targetProcess = IoThreadToProcess(targetThread);
        ULONG targetPid = HandleToUlong(PsGetProcessId(targetProcess));
        
        if (g_EdrPid != 0 && targetPid == g_EdrPid) {
            ACCESS_MASK forbidden = THREAD_TERMINATE | THREAD_SUSPEND_RESUME;
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
    OB_OPERATION_REGISTRATION opRegistration[2];

    RtlZeroMemory(&obRegistration, sizeof(obRegistration));
    obRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    obRegistration.OperationRegistrationCount = 2;
    // FIX: Correct altitude for AV/EDR (Issue 13)
    RtlInitUnicodeString(&obRegistration.Altitude, L"320123");
    obRegistration.RegistrationContext = NULL;

    RtlZeroMemory(opRegistration, sizeof(opRegistration));
    
    opRegistration[0].ObjectType = PsProcessType;
    opRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegistration[0].PreOperation = TDSPreCallback;
    opRegistration[0].PostOperation = NULL;

    opRegistration[1].ObjectType = PsThreadType;
    opRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegistration[1].PreOperation = TDSPreCallback;
    opRegistration[1].PostOperation = NULL;

    obRegistration.OperationRegistration = opRegistration;
    return ObRegisterCallbacks(&obRegistration, &g_ObRegistrationHandle);
}

NTSTATUS TDSUnloadFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS TDSPostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
) {
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Information == FILE_DOES_NOT_EXIST)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    BOOLEAN isDelete = FALSE;
    if (Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE) {
        isDelete = TRUE;
    }

    if (isDelete) {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
            FltParseFileNameInformation(nameInfo);

            ULONG pathLen = nameInfo->Name.Length;
            ULONG dataSize = sizeof(TDS_FILE_EVENT_DATA) + pathLen;
            ULONG totalSize = sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize;
            PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, totalSize, 'SDTe');
            if (item) {
                RtlZeroMemory(item, totalSize);
                item->TotalSize = totalSize;
                PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
                header->Type = TDSEventFileDelete;
                header->ProcessId = HandleToUlong(PsGetCurrentProcessId());
                header->ThreadId = HandleToUlong(PsGetCurrentThreadId());
                header->DataSize = dataSize;
                KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);

                PTDS_FILE_EVENT_DATA fData = (PTDS_FILE_EVENT_DATA)(header + 1);
                fData->Operation = 2; // Delete
                fData->FilePathOffset = sizeof(TDS_EVENT_HEADER) + sizeof(TDS_FILE_EVENT_DATA);
                RtlCopyMemory((PUCHAR)header + fData->FilePathOffset, nameInfo->Name.Buffer, pathLen);

                QueueTDSEvent(item);
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS TDSPreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_opt_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx ||
        infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
        
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
            FltParseFileNameInformation(nameInfo);

            ULONG pathLen = nameInfo->Name.Length;
            ULONG targetLen = 0;
            
            if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
                PFILE_RENAME_INFORMATION renameInfo = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                targetLen = renameInfo->FileNameLength;
            }

            ULONG dataSize = sizeof(TDS_FILE_EVENT_DATA) + pathLen + targetLen;
            ULONG totalSize = sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize;
            PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, totalSize, 'SDTe');
            if (item) {
                RtlZeroMemory(item, totalSize);
                item->TotalSize = totalSize;
                PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
                header->ProcessId = HandleToUlong(PsGetCurrentProcessId());
                header->ThreadId = HandleToUlong(PsGetCurrentThreadId());
                header->DataSize = dataSize;
                KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);

                PTDS_FILE_EVENT_DATA fData = (PTDS_FILE_EVENT_DATA)(header + 1);
                fData->FilePathOffset = sizeof(TDS_EVENT_HEADER) + sizeof(TDS_FILE_EVENT_DATA);
                RtlCopyMemory((PUCHAR)header + fData->FilePathOffset, nameInfo->Name.Buffer, pathLen);

                if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
                    header->Type = TDSEventFileOp;
                    fData->Operation = 3; // Rename
                    fData->TargetPathOffset = fData->FilePathOffset + pathLen;
                    PFILE_RENAME_INFORMATION renameInfo = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                    RtlCopyMemory((PUCHAR)header + fData->TargetPathOffset, renameInfo->FileName, targetLen);
                } else {
                    header->Type = TDSEventFileDelete;
                    fData->Operation = 2; // Delete
                }

                QueueTDSEvent(item);
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, NULL, TDSPostCreateCallback },
    { IRP_MJ_SET_INFORMATION, 0, TDSPreSetInformationCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    TDSUnloadFilter,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    
    if (notifyClass == RegNtPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        
        UNICODE_STRING keyPath = { 0 };
        ULONG size = 0;
        ObQueryNameString(info->Object, NULL, 0, &size);
        POBJECT_NAME_INFORMATION nameInfo = NULL;
        if (size > 0) {
            nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, 'SDTe');
            if (nameInfo) {
                if (NT_SUCCESS(ObQueryNameString(info->Object, nameInfo, size, &size))) {
                    keyPath = nameInfo->Name;
                }
            }
        }

        ULONG valueNameLen = (info->ValueName) ? info->ValueName->Length : 0;
        ULONG dataBufSize = (info->DataSize > 128) ? 128 : info->DataSize;
        if (info->Data == NULL) dataBufSize = 0;
        
        ULONG dataSize = sizeof(TDS_REGISTRY_EVENT_DATA) + keyPath.Length + valueNameLen + dataBufSize;
        ULONG totalSize = sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize;
        
        PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, totalSize, 'SDTe');
        if (item) {
            RtlZeroMemory(item, totalSize);
            item->TotalSize = totalSize;

            PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
            header->Type = TDSEventRegistryOp;
            header->ProcessId = HandleToUlong(PsGetCurrentProcessId());
            header->ThreadId = HandleToUlong(PsGetCurrentThreadId());
            header->DataSize = dataSize;
            KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);

            PTDS_REGISTRY_EVENT_DATA regData = (PTDS_REGISTRY_EVENT_DATA)(header + 1);
            regData->Type = info->Type;
            regData->DataSize = info->DataSize;
            
            PUCHAR buffer = (PUCHAR)(regData + 1);
            if (keyPath.Length > 0) {
                regData->KeyPathOffset = (ULONG)(buffer - (PUCHAR)header);
                RtlCopyMemory(buffer, keyPath.Buffer, keyPath.Length);
                buffer += keyPath.Length;
            }
            if (valueNameLen > 0) {
                regData->ValueNameOffset = (ULONG)(buffer - (PUCHAR)header);
                RtlCopyMemory(buffer, info->ValueName->Buffer, valueNameLen);
                buffer += valueNameLen;
            }
            if (dataBufSize > 0) {
                regData->DataOffset = (ULONG)(buffer - (PUCHAR)header);
                RtlCopyMemory(buffer, info->Data, dataBufSize);
            }

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
    ULONG totalSize = sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + dataSize;
    
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, totalSize, 'SDTe');
    if (!item) return;

    RtlZeroMemory(item, totalSize);
    item->TotalSize = totalSize;

    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
    header->ThreadId = HandleToUlong(ThreadId);
    header->DataSize = dataSize;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);

    if (isRemote) {
        header->Type = TDSEventRemoteThread;
        header->ProcessId = HandleToUlong(PsGetCurrentProcessId()); // Creator PID
        PTDS_REMOTE_THREAD_DATA rData = (PTDS_REMOTE_THREAD_DATA)(header + 1);
        rData->TargetProcessId = HandleToUlong(ProcessId);
    } else {
        header->Type = TDSEventThreadCreate;
        header->ProcessId = HandleToUlong(ProcessId);
    }

    QueueTDSEvent(item);
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
        status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    }
    if (NT_SUCCESS(status)) {
        status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    }
    if (NT_SUCCESS(status)) {
        status = RegisterObCallbacks();
    }
    if (NT_SUCCESS(status)) {
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"320123");
        status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegistryCookie, NULL);
    }
    if (NT_SUCCESS(status)) {
        status = InitializeWFP(g_DeviceObject);
    }
    if (NT_SUCCESS(status)) {
        status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
        if (NT_SUCCESS(status)) {
            status = FltStartFiltering(g_FilterHandle);
            if (!NT_SUCCESS(status)) {
                FltUnregisterFilter(g_FilterHandle);
                g_FilterHandle = NULL;
            }
        }
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
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    
    if (g_RegistryCookie.QuadPart != 0) CmUnRegisterCallback(g_RegistryCookie);

    if (g_ObRegistrationHandle) ObUnRegisterCallbacks(g_ObRegistrationHandle);
    
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
    
    // FIX: Safe teardown of WFP (Issue 12)
    if (g_EngineHandle) {
        // dynamic session handles filter/callout deletion, but we must unregister the kernel callback
        if (g_CalloutId) FwpsCalloutUnregisterById0(g_CalloutId);
        if (g_CalloutIdV6) FwpsCalloutUnregisterById0(g_CalloutIdV6);
        if (g_CalloutIdDgV4) FwpsCalloutUnregisterById0(g_CalloutIdDgV4);
        if (g_CalloutIdDgV6) FwpsCalloutUnregisterById0(g_CalloutIdDgV6);
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
