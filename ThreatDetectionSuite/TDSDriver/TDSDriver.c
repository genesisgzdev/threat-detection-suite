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
NPAGED_LOOKASIDE_LIST g_EventLookasideList;

KSPIN_LOCK g_IrpQueueLock;
LIST_ENTRY g_PendingIrpList;

// [INDUSTRIAL UPDATE] Lock-Free Interlocked Singly Linked List
DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) SLIST_HEADER g_EventQueueHead;

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

DEFINE_GUID(TDS_WFP_CALLOUT_V4_GUID, 0xeb6a1f3c, 0x7d4e, 0x4b2a, 0x9c, 0x8d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d);
DEFINE_GUID(TDS_WFP_CALLOUT_V6_GUID, 0xa1b2c3d4, 0xe5f6, 0x4a1b, 0x8c, 0x9d, 0xe0, 0xf1, 0xa2, 0xb3, 0xc4, 0xd5);
DEFINE_GUID(TDS_WFP_CALLOUT_DATAGRAM_V4_GUID, 0xf1e2d3c4, 0xb5a6, 0x4987, 0x8e, 0x7d, 0x6c, 0x5b, 0x4a, 0x39, 0x28, 0x17);
DEFINE_GUID(TDS_WFP_CALLOUT_DATAGRAM_V6_GUID, 0xd1c2b3a4, 0x9e8d, 0x4c7b, 0x6a, 0x5f, 0x4e, 0x3d, 0x2c, 0x1b, 0x0a, 0x98);
DEFINE_GUID(TDS_SUBLAYER_GUID, 0x29c786a3, 0x5a1b, 0x4f4f, 0xb4, 0x8a, 0x8e, 0x1f, 0x1d, 0x1c, 0x1b, 0x1a);

typedef struct _TDS_PENDING_IRP {
    LIST_ENTRY ListEntry;
    PIRP Irp;
} TDS_PENDING_IRP, *PTDS_PENDING_IRP;

typedef struct _EVENT_ITEM {
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) SLIST_ENTRY ListEntry; // MUST BE FIRST
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

BOOLEAN IsEdrProcess(PEPROCESS Process) {
    UNICODE_STRING edrName;
    RtlInitUnicodeString(&edrName, L"TDSService.exe");
    PUNICODE_STRING procName = NULL;
    BOOLEAN match = FALSE;
    if (NT_SUCCESS(SeLocateProcessImageName(Process, &procName))) {
        if (RtlSuffixUnicodeString(&edrName, procName, TRUE)) match = TRUE;
        ExFreePool(procName);
    }
    return match;
}

BOOLEAN IsLsass(PEPROCESS Process) {
    if (PsGetProcessSignatureLevel(Process) < 7) return FALSE;
    UNICODE_STRING lsassSuffix;
    RtlInitUnicodeString(&lsassSuffix, L"\\Windows\\System32\\lsass.exe");
    PUNICODE_STRING procName = NULL;
    BOOLEAN match = FALSE;
    if (NT_SUCCESS(SeLocateProcessImageName(Process, &procName))) {
        if (RtlSuffixUnicodeString(&lsassSuffix, procName, TRUE)) match = TRUE;
        ExFreePool(procName);
    }
    return match;
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
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

void DispatchPendingEvents() {
    KIRQL irpIrql;
    PSLIST_ENTRY entry;

    while (TRUE) {
        KeAcquireSpinLock(&g_IrpQueueLock, &irpIrql);
        if (IsListEmpty(&g_PendingIrpList)) { KeReleaseSpinLock(&g_IrpQueueLock, irpIrql); break; }
        
        // [INDUSTRIAL UPDATE] Lock-Free Pop from SList
        entry = InterlockedPopEntrySList(&g_EventQueueHead);
        if (entry == NULL) { KeReleaseSpinLock(&g_IrpQueueLock, irpIrql); break; }
        
        PLIST_ENTRY irpEntry = g_PendingIrpList.Flink;
        PTDS_PENDING_IRP pIrp = CONTAINING_RECORD(irpEntry, TDS_PENDING_IRP, ListEntry);
        PIRP Irp = pIrp->Irp;
        
        if (IoSetCancelRoutine(Irp, NULL) == NULL) {
            RemoveEntryList(&pIrp->ListEntry); ExFreePoolWithTag(pIrp, 'SDTe');
            KeReleaseSpinLock(&g_IrpQueueLock, irpIrql); 
            // Return popped event since IRP was cancelled
            InterlockedPushEntrySList(&g_EventQueueHead, entry);
            continue;
        }
        RemoveEntryList(&pIrp->ListEntry);
        KeReleaseSpinLock(&g_IrpQueueLock, irpIrql);
        
        PEVENT_ITEM pEvent = CONTAINING_RECORD(entry, EVENT_ITEM, ListEntry);
        PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
        ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
        PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(pEvent + 1);
        ULONG requiredLen = sizeof(TDS_EVENT_HEADER) + header->DataSize;
        
        if (outLen >= requiredLen) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, header, requiredLen);
            Irp->IoStatus.Status = STATUS_SUCCESS; Irp->IoStatus.Information = requiredLen;
        } else {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        }
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        ExFreePoolWithTag(pIrp, 'SDTe'); 
        ExFreeFromNpagedLookasideList(&g_EventLookasideList, pEvent);
    }
}

void QueueTDSEvent(PEVENT_ITEM item) {
    // [INDUSTRIAL UPDATE] Lock-Free Push to SList.
    // Memory allocation alignment is handled by the lookaside list natively on x64.
    InterlockedPushEntrySList(&g_EventQueueHead, &item->ListEntry);
    DispatchPendingEvents();
}

void WfpClassifyOutbound(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, const void* classifyContext, const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut) {
    UNREFERENCED_PARAMETER(layerData); UNREFERENCED_PARAMETER(classifyContext); UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flowContext);
    classifyOut->actionType = FWP_ACTION_PERMIT;
    if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        ULONG pid = (ULONG)inMetaValues->processId;
        if (inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V4 || inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6) {
            UINT16 port = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
            if (port == 53 && inMetaValues->packetSize > 512) { classifyOut->actionType = FWP_ACTION_BLOCK; return; }
        }
        PEVENT_ITEM item = (PEVENT_ITEM)ExAllocateFromNpagedLookasideList(&g_EventLookasideList);
        if (item) {
            RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + sizeof(TDS_NETWORK_EVENT_DATA));
            PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
            header->Type = TDSEventNetworkConnect; header->ProcessId = pid; header->DataSize = sizeof(TDS_NETWORK_EVENT_DATA);
            KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);
            QueueTDSEvent(item);
        }
    }
}

NTSTATUS InitializeWFP(PDEVICE_OBJECT DeviceObject) {
    FWPM_SESSION0 session = {0}; session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    NTSTATUS status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) return status;
    FWPM_SUBLAYER0 subLayer = {0}; subLayer.subLayerKey = TDS_SUBLAYER_GUID; subLayer.displayData.name = L"TDS Sublayer"; subLayer.weight = 0xFFFF;
    FwpmSubLayerAdd0(g_EngineHandle, &subLayer, NULL);
    FWPS_CALLOUT0 sCallout = {0}; sCallout.classifyFn = WfpClassifyOutbound; sCallout.calloutKey = TDS_WFP_CALLOUT_V4_GUID;
    FwpsCalloutRegister0(DeviceObject, &sCallout, &g_CalloutIdV4);
    FWPM_FILTER0 filter = {0}; filter.subLayerKey = TDS_SUBLAYER_GUID; filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; filter.action.calloutKey = TDS_WFP_CALLOUT_V4_GUID;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdV4);
    return STATUS_SUCCESS;
}

OB_PRE_CALLBACK_STATUS TDSPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext); PEPROCESS targetProcess = NULL;
    if (OperationInformation->ObjectType == *PsProcessType) targetProcess = (PEPROCESS)OperationInformation->Object;
    else if (OperationInformation->ObjectType == *PsThreadType) targetProcess = IoThreadToProcess((PETHREAD)OperationInformation->Object);
    if (!targetProcess) return OB_PREOP_SUCCESS;
    ULONG targetPid = HandleToUlong(PsGetProcessId(targetProcess));
    if ((g_EdrPid != 0 && targetPid == g_EdrPid) || IsEdrProcess(targetProcess)) {
        ACCESS_MASK forbidden = (OperationInformation->ObjectType == *PsProcessType) ? (PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD) : (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT);
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~forbidden;
        else OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~forbidden;
    }
    return OB_PREOP_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS TDSPreWriteCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_opt_ PVOID *CompletionContext) {
    if (Data->RequestorMode == KernelMode || (Data->Iopb->IrpFlags & IRP_PAGING_IO)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    PEPROCESS req = FltGetRequestorProcess(Data);
    if (req && IsEdrProcess(req)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->Iopb->Parameters.Write.Length > 65536) {
        PEVENT_ITEM item = (PEVENT_ITEM)ExAllocateFromNpagedLookasideList(&g_EventLookasideList);
        if (item) {
            RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER));
            PTDS_EVENT_HEADER h = (PTDS_EVENT_HEADER)(item + 1); h->Type = TDSEventRansomwareActivity; h->ProcessId = HandleToUlong(PsGetCurrentProcessId());
            QueueTDSEvent(item);
        }
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = { { IRP_MJ_WRITE, 0, TDSPreWriteCallback, NULL }, { IRP_MJ_OPERATION_END } };
CONST FLT_REGISTRATION FilterRegistration = { sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, Callbacks, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath); UNICODE_STRING deviceName, symLink;
    RtlInitUnicodeString(&deviceName, L"\\Device\\TDS_Core_Kernel"); RtlInitUnicodeString(&symLink, L"\\DosDevices\\TDS_Core_Link");
    IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    IoCreateSymbolicLink(&symLink, &deviceName);
    DriverObject->DriverUnload = DriverUnload;
    
    // [INDUSTRIAL UPDATE] Initialize SList
    InitializeListHead(&g_PendingIrpList); KeInitializeSpinLock(&g_IrpQueueLock);
    InitializeSListHead(&g_EventQueueHead);
    
    ExInitializeNpagedLookasideList(&g_EventLookasideList, NULL, NULL, 0, MAX_EVENT_BUFFER_SIZE + sizeof(EVENT_ITEM), 'SDTe', 0);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    InitializeWFP(g_DeviceObject); FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle); FltStartFiltering(g_FilterHandle);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink; RtlInitUnicodeString(&symLink, L"\\DosDevices\\TDS_Core_Link"); IoDeleteSymbolicLink(&symLink);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
    ExDeleteNpagedLookasideList(&g_EventLookasideList);
    IoDeleteDevice(g_DeviceObject);
}

void ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocateFromNpagedLookasideList(&g_EventLookasideList);
    if (item) {
        PTDS_EVENT_HEADER h = (PTDS_EVENT_HEADER)(item + 1); h->Type = CreateInfo ? TDSEventProcessCreate : TDSEventProcessTerminate;
        h->ProcessId = HandleToUlong(ProcessId); QueueTDSEvent(item);
    }
}

