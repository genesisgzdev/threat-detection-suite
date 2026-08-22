#include <ntifs.h>
#include <ntddk.h>
#include <fltKernel.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wdmsec.h>
#include <initguid.h>
#include "../TDSCommon/TDSCommon.h"

NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(_In_ PEPROCESS Process);

PDEVICE_OBJECT g_DeviceObject = NULL;
PFLT_FILTER g_FilterHandle = NULL;
NPAGED_LOOKASIDE_LIST g_EventLookasideList;

// [INDUSTRIAL UPDATE] Lock-Free Interlocked Singly Linked List
DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) SLIST_HEADER g_EventQueueHead;

PVOID g_ObRegistrationHandle = NULL;
LARGE_INTEGER g_RegistryCookie = {0};
PEPROCESS g_ServiceProcess = NULL;
TDS_PROTECTION_POLICY g_Policy = { 1, sizeof(TDS_PROTECTION_POLICY), TDS_POLICY_FLAG_PROTECT_SERVICE, 1, 0, 0, {0, 0, 0} };
KSPIN_LOCK g_PolicyLock;
volatile LONG g_EventCount = 0;
volatile LONG g_DroppedEventCount = 0;
volatile LONG g_EventHighWatermark = 0;
BOOLEAN g_ThreadNotifyRegistered = FALSE;
BOOLEAN g_ImageNotifyRegistered = FALSE;
BOOLEAN g_RegistryCallbackRegistered = FALSE;

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
BOOLEAN g_WfpSubLayerAdded = FALSE;

DEFINE_GUID(TDS_WFP_CALLOUT_V4_GUID, 0xeb6a1f3c, 0x7d4e, 0x4b2a, 0x9c, 0x8d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d);
DEFINE_GUID(TDS_WFP_CALLOUT_V6_GUID, 0xa1b2c3d4, 0xe5f6, 0x4a1b, 0x8c, 0x9d, 0xe0, 0xf1, 0xa2, 0xb3, 0xc4, 0xd5);
DEFINE_GUID(TDS_WFP_CALLOUT_DATAGRAM_V4_GUID, 0xf1e2d3c4, 0xb5a6, 0x4987, 0x8e, 0x7d, 0x6c, 0x5b, 0x4a, 0x39, 0x28, 0x17);
DEFINE_GUID(TDS_WFP_CALLOUT_DATAGRAM_V6_GUID, 0xd1c2b3a4, 0x9e8d, 0x4c7b, 0x6a, 0x5f, 0x4e, 0x3d, 0x2c, 0x1b, 0x0a, 0x98);
DEFINE_GUID(TDS_SUBLAYER_GUID, 0x29c786a3, 0x5a1b, 0x4f4f, 0xb4, 0x8a, 0x8e, 0x1f, 0x1d, 0x1c, 0x1b, 0x1a);
DEFINE_GUID(TDS_DEVICE_CLASS_GUID, 0x4b4f7e1d, 0x7c31, 0x4d73, 0x9c, 0x32, 0xe7, 0x83, 0x20, 0x4d, 0x1a, 0x61);

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
OB_PREOP_CALLBACK_STATUS TDSPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
static BOOLEAN IsAuthorizedPolicyCaller(PIRP Irp) {
    // Authorization is established by the secure device ACL and the IOCTL
    // access bit. Do not infer identity from an executable name or path.
    return NT_SUCCESS(IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS));
}

static NTSTATUS RegisterProtectionCallbacks(void) {
    OB_OPERATION_REGISTRATION operations[2] = {0};
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = TDSPreCallback;
    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = TDSPreCallback;

    OB_CALLBACK_REGISTRATION registration = {0};
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"385120");
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = RTL_NUMBER_OF(operations);
    registration.Altitude = altitude;
    registration.RegistrationContext = NULL;
    registration.OperationRegistration = operations;
    return ObRegisterCallbacks(&registration, &g_ObRegistrationHandle);
}

static NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR information) {
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS TDSDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS TDSDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS accessStatus = STATUS_SUCCESS;
    if (code == IOCTL_TDS_SET_PROTECTION_POLICY || code == IOCTL_TDS_SET_RUNTIME_POLICY) {
        accessStatus = IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS);
    } else if (code == IOCTL_TDS_GET_NEXT_EVENT || code == IOCTL_TDS_GET_QUEUE_STATS) {
        accessStatus = IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS);
    }
    if (!NT_SUCCESS(accessStatus)) {
        return CompleteIrp(Irp, accessStatus, 0);
    }

    if (code == IOCTL_TDS_SET_PROTECTION_POLICY || code == IOCTL_TDS_SET_RUNTIME_POLICY) {
        if (!IsAuthorizedPolicyCaller(Irp)) {
            return CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);
        }
        if (inLength != sizeof(TDS_PROTECTION_POLICY) || Irp->AssociatedIrp.SystemBuffer == NULL) {
            return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
        }
        PTDS_PROTECTION_POLICY requested = (PTDS_PROTECTION_POLICY)Irp->AssociatedIrp.SystemBuffer;
        if (requested->Version != 1 || requested->Size != sizeof(TDS_PROTECTION_POLICY) ||
            (requested->Flags & ~(TDS_POLICY_FLAG_PROTECT_SERVICE | TDS_POLICY_FLAG_ENABLE_WFP | TDS_POLICY_FLAG_ENABLE_MINIFILTER)) != 0 ||
            requested->ObserveOnly > 1 || requested->AllowProcessTermination > 1 ||
            requested->AllowNetworkContainment > 1 || requested->Reserved[0] != 0 ||
            requested->Reserved[1] != 0 || requested->Reserved[2] != 0) {
            return CompleteIrp(Irp, STATUS_REVISION_MISMATCH, 0);
        }
        PEPROCESS caller = IoGetRequestorProcess(Irp);
        if (!caller) return CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);
        ObReferenceObject(caller);
        PEPROCESS previous = (PEPROCESS)InterlockedExchangePointer((PVOID volatile *)&g_ServiceProcess, caller);
        if (previous) ObDereferenceObject(previous);

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
        g_Policy = *requested;
        KeReleaseSpinLock(&g_PolicyLock, oldIrql);
        return CompleteIrp(Irp, STATUS_SUCCESS, 0);
    }

    if (code == IOCTL_TDS_GET_NEXT_EVENT) {
        if (outLength < sizeof(TDS_EVENT_HEADER) || Irp->AssociatedIrp.SystemBuffer == NULL) {
            return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, sizeof(TDS_EVENT_HEADER));
        }
        PSLIST_ENTRY entry = InterlockedPopEntrySList(&g_EventQueueHead);
        if (entry == NULL) return CompleteIrp(Irp, STATUS_NO_MORE_ENTRIES, 0);

        PEVENT_ITEM item = CONTAINING_RECORD(entry, EVENT_ITEM, ListEntry);
        PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
        ULONG required = sizeof(TDS_EVENT_HEADER) + header->DataSize;
        if (header->DataSize > MAX_EVENT_BUFFER_SIZE - sizeof(TDS_EVENT_HEADER) || required > outLength) {
            InterlockedDecrement(&g_EventCount);
            ExFreeToNpagedLookasideList(&g_EventLookasideList, item);
            return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, required);
        }
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, header, required);
        InterlockedDecrement(&g_EventCount);
        ExFreeToNpagedLookasideList(&g_EventLookasideList, item);
        return CompleteIrp(Irp, STATUS_SUCCESS, required);
    }

    if (code == IOCTL_TDS_GET_QUEUE_STATS) {
        if (outLength < sizeof(TDS_QUEUE_STATS) || Irp->AssociatedIrp.SystemBuffer == NULL) {
            return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, sizeof(TDS_QUEUE_STATS));
        }
        PTDS_QUEUE_STATS stats = (PTDS_QUEUE_STATS)Irp->AssociatedIrp.SystemBuffer;
        RtlZeroMemory(stats, sizeof(*stats));
        stats->Version = 1;
        stats->Size = sizeof(*stats);
        stats->QueueDepth = (ULONG)max(0, InterlockedCompareExchange(&g_EventCount, 0, 0));
        stats->DroppedEvents = (ULONG)max(0, InterlockedCompareExchange(&g_DroppedEventCount, 0, 0));
        stats->HighWatermark = (ULONG)max(0, InterlockedCompareExchange(&g_EventHighWatermark, 0, 0));
        return CompleteIrp(Irp, STATUS_SUCCESS, sizeof(*stats));
    }

    return CompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

PVOID GetProcessPeb(PEPROCESS Process) {
    PVOID peb = PsGetProcessWow64Process(Process);
    if (!peb) peb = PsGetProcessPeb(Process);
    return peb;
}

BOOLEAN IsServiceProcess(PEPROCESS Process) {
    return Process != NULL && Process == (PEPROCESS)InterlockedCompareExchangePointer(
        (PVOID volatile *)&g_ServiceProcess, NULL, NULL);
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

void QueueTDSEvent(PEVENT_ITEM item) {
    LONG count = InterlockedIncrement(&g_EventCount);
    if (count > EVENT_QUEUE_LIMIT) {
        InterlockedDecrement(&g_EventCount);
        InterlockedIncrement(&g_DroppedEventCount);
        ExFreeToNpagedLookasideList(&g_EventLookasideList, item);
        return;
    }
    LONG highWatermark = InterlockedCompareExchange(&g_EventHighWatermark, 0, 0);
    while (count > highWatermark) {
        LONG observed = InterlockedCompareExchange(&g_EventHighWatermark, count, highWatermark);
        if (observed == highWatermark || observed >= count) break;
        highWatermark = observed;
    }
    InterlockedPushEntrySList(&g_EventQueueHead, &item->ListEntry);
}

void WfpClassifyOutbound(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, const void* classifyContext, const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut) {
    UNREFERENCED_PARAMETER(layerData); UNREFERENCED_PARAMETER(classifyContext); UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flowContext);
    if (!inFixedValues || !inMetaValues || !classifyOut || !inFixedValues->incomingValue) return;
    TDS_PROTECTION_POLICY policy;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
    policy = g_Policy;
    KeReleaseSpinLock(&g_PolicyLock, oldIrql);
    classifyOut->actionType = FWP_ACTION_PERMIT;
    if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        ULONG pid = (ULONG)inMetaValues->processId;
        if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
            const ULONG remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
            const ULONG remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
            const ULONG protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
            if (inFixedValues->valueCount <= remoteAddressIndex ||
                inFixedValues->valueCount <= remotePortIndex ||
                inFixedValues->valueCount <= protocolIndex) return;
            const FWP_VALUE0* remoteAddress = &inFixedValues->incomingValue[remoteAddressIndex].value;
            const FWP_VALUE0* remotePort = &inFixedValues->incomingValue[remotePortIndex].value;
            const FWP_VALUE0* protocol = &inFixedValues->incomingValue[protocolIndex].value;
            if (remoteAddress->type != FWP_UINT32 || remotePort->type != FWP_UINT16 || protocol->type != FWP_UINT8) return;
            const UINT16 port = remotePort->uint16;
            if (!policy.ObserveOnly && policy.AllowNetworkContainment &&
                port == 53 && inMetaValues->packetSize > 512) {
                classifyOut->actionType = FWP_ACTION_BLOCK;
                return;
            }
        }
        PEVENT_ITEM item = (PEVENT_ITEM)ExAllocateFromNpagedLookasideList(&g_EventLookasideList);
        if (item) {
            RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + sizeof(TDS_NETWORK_EVENT_DATA));
            PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
            header->Type = TDSEventNetworkConnect; header->ProcessId = pid; header->DataSize = sizeof(TDS_NETWORK_EVENT_DATA);
            PTDS_NETWORK_EVENT_DATA network = (PTDS_NETWORK_EVENT_DATA)(header + 1);
            network->AddressFamily = AF_INET;
            network->Ipv4Address = remoteAddress->uint32;
            network->RemotePort = remotePort->uint16;
            network->Protocol = protocol->uint8;
            KeQuerySystemTimePrecise((PLARGE_INTEGER)&header->Timestamp);
            QueueTDSEvent(item);
        }
    }
}

static VOID CleanupWFP(VOID) {
    if (g_EngineHandle) {
        if (g_FilterIdV4) { FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdV4); g_FilterIdV4 = 0; }
        if (g_CalloutIdV4) { FwpsCalloutUnregisterById0(g_CalloutIdV4); g_CalloutIdV4 = 0; }
        if (g_WfpSubLayerAdded) {
            FwpmSubLayerDeleteByKey0(g_EngineHandle, &TDS_SUBLAYER_GUID);
            g_WfpSubLayerAdded = FALSE;
        }
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }
}

NTSTATUS InitializeWFP(PDEVICE_OBJECT DeviceObject) {
    FWPM_SESSION0 session = {0}; session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    NTSTATUS status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) return status;
    FWPM_SUBLAYER0 subLayer = {0}; subLayer.subLayerKey = TDS_SUBLAYER_GUID; subLayer.displayData.name = L"TDS Sublayer"; subLayer.weight = 0xFFFF;
    status = FwpmSubLayerAdd0(g_EngineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) { CleanupWFP(); return status; }
    g_WfpSubLayerAdded = TRUE;
    FWPS_CALLOUT0 sCallout = {0}; sCallout.classifyFn = WfpClassifyOutbound; sCallout.calloutKey = TDS_WFP_CALLOUT_V4_GUID;
    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &g_CalloutIdV4);
    if (!NT_SUCCESS(status)) { CleanupWFP(); return status; }
    FWPM_FILTER0 filter = {0}; filter.subLayerKey = TDS_SUBLAYER_GUID; filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; filter.action.calloutKey = TDS_WFP_CALLOUT_V4_GUID;
    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterIdV4);
    if (!NT_SUCCESS(status)) { CleanupWFP(); return status; }
    return status;
}

OB_PREOP_CALLBACK_STATUS TDSPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext); PEPROCESS targetProcess = NULL;
    if (OperationInformation->ObjectType == *PsProcessType) targetProcess = (PEPROCESS)OperationInformation->Object;
    else if (OperationInformation->ObjectType == *PsThreadType) targetProcess = IoThreadToProcess((PETHREAD)OperationInformation->Object);
    if (!targetProcess) return OB_PREOP_SUCCESS;
    TDS_PROTECTION_POLICY policy;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
    policy = g_Policy;
    KeReleaseSpinLock(&g_PolicyLock, oldIrql);
    if ((policy.Flags & TDS_POLICY_FLAG_PROTECT_SERVICE) == 0) return OB_PREOP_SUCCESS;
    if (IsServiceProcess(targetProcess)) {
        ACCESS_MASK forbidden = (OperationInformation->ObjectType == *PsProcessType) ? (PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD) : (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT);
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~forbidden;
        else OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~forbidden;
    }
    return OB_PREOP_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS TDSPreWriteCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_opt_ PVOID *CompletionContext) {
    if (Data->RequestorMode == KernelMode || (Data->Iopb->IrpFlags & IRP_PAGING_IO)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    PEPROCESS req = FltGetRequestorProcess(Data);
    if (req && IsServiceProcess(req)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
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

NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);
    const REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    TDS_EVENT_TYPE eventType;
    if (notifyClass == RegNtPreSetValueKey) eventType = TDSEventRegistrySet;
    else if (notifyClass == RegNtPreDeleteValueKey) eventType = TDSEventRegistryDelete;
    else return STATUS_SUCCESS;

    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocateFromNpagedLookasideList(&g_EventLookasideList);
    if (!item) return STATUS_SUCCESS;
    RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER));
    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
    header->Type = eventType;
    header->ProcessId = HandleToUlong(PsGetCurrentProcessId());
    header->DataSize = 0;
    KeQuerySystemTimePrecise(&header->Timestamp);
    QueueTDSEvent(item);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath); UNICODE_STRING deviceName, symLink, deviceSddl;
    RtlInitUnicodeString(&deviceName, L"\\Device\\TDS_Core_Kernel"); RtlInitUnicodeString(&symLink, L"\\DosDevices\\TDS_Core_Link");
    RtlInitUnicodeString(&deviceSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    KeInitializeSpinLock(&g_PolicyLock);
    NTSTATUS status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceSddl, &TDS_DEVICE_CLASS_GUID, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(g_DeviceObject); g_DeviceObject = NULL; return status; }
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = TDSDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TDSDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TDSDispatchDeviceControl;
    
    // [INDUSTRIAL UPDATE] Initialize SList
    InitializeSListHead(&g_EventQueueHead);
    
    ExInitializeNpagedLookasideList(&g_EventLookasideList, NULL, NULL, 0, MAX_EVENT_BUFFER_SIZE + sizeof(EVENT_ITEM), 'SDTe', 0);
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) { IoDeleteSymbolicLink(&symLink); IoDeleteDevice(g_DeviceObject); return status; }
    UNICODE_STRING registryAltitude;
    RtlInitUnicodeString(&registryAltitude, L"385121");
    status = CmRegisterCallbackEx(RegistryCallback, &registryAltitude, DriverObject, NULL, &g_RegistryCookie, NULL);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
        IoDeleteSymbolicLink(&symLink); IoDeleteDevice(g_DeviceObject); return status;
    }
    g_RegistryCallbackRegistered = TRUE;
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    if (!NT_SUCCESS(status)) { CmUnRegisterCallback(g_RegistryCookie); g_RegistryCallbackRegistered = FALSE; PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE); IoDeleteSymbolicLink(&symLink); IoDeleteDevice(g_DeviceObject); return status; }
    g_ThreadNotifyRegistered = TRUE;
    status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (!NT_SUCCESS(status)) { PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine); g_ThreadNotifyRegistered = FALSE; CmUnRegisterCallback(g_RegistryCookie); g_RegistryCallbackRegistered = FALSE; PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE); IoDeleteSymbolicLink(&symLink); IoDeleteDevice(g_DeviceObject); return status; }
    g_ImageNotifyRegistered = TRUE;
    status = InitializeWFP(g_DeviceObject);
    if (!NT_SUCCESS(status)) { if (g_ImageNotifyRegistered) { PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine); g_ImageNotifyRegistered = FALSE; } if (g_ThreadNotifyRegistered) { PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine); g_ThreadNotifyRegistered = FALSE; } CmUnRegisterCallback(g_RegistryCookie); g_RegistryCallbackRegistered = FALSE; PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE); IoDeleteSymbolicLink(&symLink); IoDeleteDevice(g_DeviceObject); return status; }
    status = RegisterProtectionCallbacks();
    if (!NT_SUCCESS(status)) {
        if (g_ImageNotifyRegistered) { PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine); g_ImageNotifyRegistered = FALSE; }
        if (g_ThreadNotifyRegistered) { PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine); g_ThreadNotifyRegistered = FALSE; }
        if (g_RegistryCallbackRegistered) { CmUnRegisterCallback(g_RegistryCookie); g_RegistryCallbackRegistered = FALSE; }
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
        CleanupWFP();
        IoDeleteSymbolicLink(&symLink); IoDeleteDevice(g_DeviceObject); return status;
    }
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (NT_SUCCESS(status)) status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        if (g_FilterHandle) { FltUnregisterFilter(g_FilterHandle); g_FilterHandle = NULL; }
        if (g_ObRegistrationHandle) { ObUnRegisterCallbacks(g_ObRegistrationHandle); g_ObRegistrationHandle = NULL; }
        if (g_RegistryCallbackRegistered) { CmUnRegisterCallback(g_RegistryCookie); g_RegistryCallbackRegistered = FALSE; }
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
        CleanupWFP();
        IoDeleteSymbolicLink(&symLink); IoDeleteDevice(g_DeviceObject); return status;
    }
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING symLink; RtlInitUnicodeString(&symLink, L"\\DosDevices\\TDS_Core_Link"); IoDeleteSymbolicLink(&symLink);
    if (g_FilterHandle) { FltUnregisterFilter(g_FilterHandle); g_FilterHandle = NULL; }
    if (g_ObRegistrationHandle) { ObUnRegisterCallbacks(g_ObRegistrationHandle); g_ObRegistrationHandle = NULL; }
    if (g_RegistryCallbackRegistered) { CmUnRegisterCallback(g_RegistryCookie); g_RegistryCallbackRegistered = FALSE; }
    CleanupWFP();
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
    if (g_ImageNotifyRegistered) { PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine); g_ImageNotifyRegistered = FALSE; }
    if (g_ThreadNotifyRegistered) { PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine); g_ThreadNotifyRegistered = FALSE; }
    PEPROCESS serviceProcess = (PEPROCESS)InterlockedExchangePointer((PVOID volatile *)&g_ServiceProcess, NULL);
    if (serviceProcess) ObDereferenceObject(serviceProcess);
    PSLIST_ENTRY entry;
    while ((entry = InterlockedPopEntrySList(&g_EventQueueHead)) != NULL) {
        PEVENT_ITEM item = CONTAINING_RECORD(entry, EVENT_ITEM, ListEntry);
        ExFreeToNpagedLookasideList(&g_EventLookasideList, item);
    }
    ExDeleteNpagedLookasideList(&g_EventLookasideList);
    IoDeleteDevice(g_DeviceObject);
}

void ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (!CreateInfo && IsServiceProcess(Process)) {
        PEPROCESS previous = (PEPROCESS)InterlockedCompareExchangePointer(
            (PVOID volatile *)&g_ServiceProcess, NULL, Process);
        if (previous == Process) ObDereferenceObject(Process);
    }
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocateFromNpagedLookasideList(&g_EventLookasideList);
    if (item) {
        const ULONG maxData = MAX_EVENT_BUFFER_SIZE - sizeof(TDS_EVENT_HEADER);
        ULONG imageBytes = 0;
        ULONG commandLineBytes = 0;
        if (CreateInfo && CreateInfo->ImageFileName) imageBytes = min((ULONG)CreateInfo->ImageFileName->Length, maxData - sizeof(TDS_PROCESS_EVENT_DATA) - 2 * sizeof(wchar_t));
        if (CreateInfo && CreateInfo->CommandLine) commandLineBytes = min((ULONG)CreateInfo->CommandLine->Length, maxData - sizeof(TDS_PROCESS_EVENT_DATA) - imageBytes - 2 * sizeof(wchar_t));
        RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + sizeof(TDS_PROCESS_EVENT_DATA) + imageBytes + commandLineBytes + 2 * sizeof(wchar_t));
        PTDS_EVENT_HEADER h = (PTDS_EVENT_HEADER)(item + 1);
        h->Type = CreateInfo ? TDSEventProcessCreate : TDSEventProcessTerminate;
        h->DataSize = CreateInfo ? sizeof(TDS_PROCESS_EVENT_DATA) + imageBytes + commandLineBytes + 2 * sizeof(wchar_t) : 0;
        KeQuerySystemTimePrecise(&h->Timestamp);
        if (CreateInfo) {
            PTDS_PROCESS_EVENT_DATA data = (PTDS_PROCESS_EVENT_DATA)(h + 1);
            data->Create = TRUE;
            data->ParentProcessId = CreateInfo->ParentProcessId ? HandleToUlong(CreateInfo->ParentProcessId) : 0;
            PUCHAR cursor = (PUCHAR)data + sizeof(TDS_PROCESS_EVENT_DATA);
            data->ImagePathOffset = sizeof(TDS_PROCESS_EVENT_DATA);
            if (imageBytes) {
                RtlCopyMemory(cursor, CreateInfo->ImageFileName->Buffer, imageBytes);
                cursor += imageBytes;
            }
            cursor += sizeof(wchar_t);
            data->CommandLineOffset = (ULONG)(cursor - (PUCHAR)data);
            if (commandLineBytes) RtlCopyMemory(cursor, CreateInfo->CommandLine->Buffer, commandLineBytes);
        }
        h->ProcessId = HandleToUlong(ProcessId); QueueTDSEvent(item);
    }
}

void ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocateFromNpagedLookasideList(&g_EventLookasideList);
    if (!item) return;
    RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER));
    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
    header->Type = Create ? TDSEventThreadCreate : TDSEventHandleOp;
    header->ProcessId = HandleToUlong(ProcessId);
    header->ThreadId = HandleToUlong(ThreadId);
    KeQuerySystemTimePrecise(&header->Timestamp);
    QueueTDSEvent(item);
}

void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    if (!FullImageName || !FullImageName->Buffer || !ImageInfo) return;
    const ULONG available = MAX_EVENT_BUFFER_SIZE - sizeof(TDS_EVENT_HEADER) - sizeof(TDS_IMAGE_LOAD_DATA) - sizeof(wchar_t);
    const USHORT pathBytes = (USHORT)min((ULONG)FullImageName->Length, available);
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocateFromNpagedLookasideList(&g_EventLookasideList);
    if (!item) return;
    RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(TDS_EVENT_HEADER) + sizeof(TDS_IMAGE_LOAD_DATA) + pathBytes + sizeof(wchar_t));
    PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)(item + 1);
    PTDS_IMAGE_LOAD_DATA data = (PTDS_IMAGE_LOAD_DATA)(header + 1);
    header->Type = TDSEventImageLoad;
    header->ProcessId = HandleToUlong(ProcessId);
    header->DataSize = sizeof(TDS_IMAGE_LOAD_DATA) + pathBytes + sizeof(wchar_t);
    KeQuerySystemTimePrecise(&header->Timestamp);
    data->LoadAddress = (ULONG64)(ULONG_PTR)ImageInfo->ImageBase;
    data->ImageSize = ImageInfo->ImageSize;
    data->ImagePathOffset = sizeof(TDS_IMAGE_LOAD_DATA);
    RtlCopyMemory((PUCHAR)data + data->ImagePathOffset, FullImageName->Buffer, pathBytes);
    QueueTDSEvent(item);
}
