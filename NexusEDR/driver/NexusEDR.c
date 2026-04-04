#include <ntddk.h>
#include <wdf.h>
#include "../common/NexusCommon.h"

//
// Global state
//
PDEVICE_OBJECT g_DeviceObject = NULL;
KSPIN_LOCK g_EventQueueLock;
LIST_ENTRY g_EventQueueHead;
PVOID g_ObRegistrationHandle = NULL;
PKEVENT g_UserEvent = NULL;
BOOLEAN g_MonitoringActive = FALSE;

OB_PRE_CALLBACK_STATUS NexusPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
        ULONG targetPid = HandleToUlong(PsGetProcessId(targetProcess));

        // Self-protection: Prevent terminating the EDR process
        // (Assume the EDR service will tell the driver its PID via IOCTL later)
        // For now, if it's a critical system process or we want to monitor LSASS
        
        if (targetPid == 4) return OB_PREOP_SUCCESS; // System

        ACCESS_MASK dangerousAccess = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD;
        
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & dangerousAccess) != 0) {
                // Log handle access to LSASS
                // if (IsLsass(targetProcess)) ...
                
                PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(EVENT_ITEM) + sizeof(NEXUS_HANDLE_EVENT), 'sxuN');
                if (item) {
                    RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(NEXUS_HANDLE_EVENT));
                    item->Event.Type = NexusEventHandleOp;
                    item->Event.ProcessId = HandleToUlong(PsGetCurrentProcessId());
                    KeQuerySystemTimePrecise(&item->Event.Timestamp);
                    
                    PNEXUS_HANDLE_EVENT hEvent = (PNEXUS_HANDLE_EVENT)(&item->Event);
                    hEvent->TargetProcessId = targetPid;
                    hEvent->DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
                    hEvent->IsThread = FALSE;
                    
                    QueueNexusEvent(item);
                }
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
    obRegistration.RegistrationContext = NULL;
    RtlInitUnicodeString(&obRegistration.Altitude, L"388888");

    RtlZeroMemory(&opRegistration, sizeof(opRegistration));
    opRegistration.ObjectType = PsProcessType;
    opRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegistration.PreOperation = NexusPreCallback;
    opRegistration.PostOperation = NULL;

    obRegistration.OperationRegistration = &opRegistration;

    return ObRegisterCallbacks(&obRegistration, &g_ObRegistrationHandle);
}


typedef struct _EVENT_ITEM {
    LIST_ENTRY ListEntry;
    NEXUS_EVENT_HEADER Event;
    // Data follows header...
} EVENT_ITEM, *PEVENT_ITEM;

//
// Prototypes
//
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS NexusDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NexusDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//
// Callbacks (to be implemented in next turn)
//
void ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

//
// Implementation
//

PKEVENT g_UserEvent = NULL;
BOOLEAN g_MonitoringActive = FALSE;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING deviceName, symLink;

    RtlInitUnicodeString(&deviceName, L"\\Device\\NexusEDR");
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\NexusEDR");

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = NexusDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NexusDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NexusDispatchDeviceControl;

    InitializeListHead(&g_EventQueueHead);
    KeInitializeSpinLock(&g_EventQueueLock);

    // Register Callbacks
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    if (NT_SUCCESS(status)) {
        status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    }
    if (NT_SUCCESS(status)) {
        status = RegisterObCallbacks();
    }

    if (NT_SUCCESS(status)) {
        g_MonitoringActive = TRUE;
        DbgPrint("NexusEDR: Driver loaded and monitoring active.\n");
    }

    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\NexusEDR");
    IoDeleteSymbolicLink(&symLink);

    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (g_ObRegistrationHandle) ObUnRegisterCallbacks(g_ObRegistrationHandle);

    if (g_UserEvent) ObDereferenceObject(g_UserEvent);

    // Flush queue
    KIRQL irql;
    KeAcquireSpinLock(&g_EventQueueLock, &irql);
    while (!IsListEmpty(&g_EventQueueHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_EventQueueHead);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, EVENT_ITEM, ListEntry), 'sxuN');
    }
    KeReleaseSpinLock(&g_EventQueueLock, irql);

    IoDeleteDevice(g_DeviceObject);
    DbgPrint("NexusEDR: Driver unloaded.\n");
}

NTSTATUS NexusDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS NexusDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_NEXUS_REGISTER_EVENT_EVENT:
            if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HANDLE)) {
                HANDLE hEvent = *(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
                status = ObReferenceObjectByHandle(hEvent, EVENT_MODIFY_STATE, *ExEventObjectType, UserMode, (PVOID*)&g_UserEvent, NULL);
                if (NT_SUCCESS(status)) info = sizeof(HANDLE);
            }
            break;

        case IOCTL_NEXUS_GET_NEXT_EVENT:
            // Pop event from queue and copy to userland buffer
            KIRQL irql;
            KeAcquireSpinLock(&g_EventQueueLock, &irql);
            if (!IsListEmpty(&g_EventQueueHead)) {
                PLIST_ENTRY entry = RemoveHeadList(&g_EventQueueHead);
                PEVENT_ITEM item = CONTAINING_RECORD(entry, EVENT_ITEM, ListEntry);
                KeReleaseSpinLock(&g_EventQueueLock, irql);

                ULONG size = sizeof(NEXUS_EVENT_HEADER); // Simplify for now
                if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= size) {
                    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &item->Event, size);
                    status = STATUS_SUCCESS;
                    info = size;
                } else {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                ExFreePoolWithTag(item, 'sxuN');
            } else {
                KeReleaseSpinLock(&g_EventQueueLock, irql);
                status = STATUS_NO_MORE_ENTRIES;
            }
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

//
// Helper: Queue event and signal userland
//
void QueueNexusEvent(PEVENT_ITEM item) {
    KIRQL irql;
    KeAcquireSpinLock(&g_EventQueueLock, &irql);
    InsertTailList(&g_EventQueueHead, &item->ListEntry);
    KeReleaseSpinLock(&g_EventQueueLock, irql);

    if (g_UserEvent) {
        KeSetEvent(g_UserEvent, IO_NO_INCREMENT, FALSE);
    }
}

void ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(EVENT_ITEM) + sizeof(NEXUS_PROCESS_EVENT), 'sxuN');
    if (!item) return;

    RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(NEXUS_PROCESS_EVENT));
    item->Event.Type = CreateInfo ? NexusEventProcessCreate : NexusEventProcessTerminate;
    item->Event.ProcessId = HandleToUlong(ProcessId);
    KeQuerySystemTimePrecise(&item->Event.Timestamp);

    if (CreateInfo) {
        PNEXUS_PROCESS_EVENT pEvent = (PNEXUS_PROCESS_EVENT)(&item->Event);
        pEvent->Create = TRUE;
        pEvent->ParentProcessId = HandleToUlong(CreateInfo->ParentProcessId);
        
        if (CreateInfo->ImageFileName) {
            RtlCopyMemory(pEvent->ImagePath, CreateInfo->ImageFileName->Buffer, 
                          min(CreateInfo->ImageFileName->Length, sizeof(pEvent->ImagePath) - 2));
        }
        
        if (CreateInfo->CommandLine) {
            RtlCopyMemory(pEvent->CommandLine, CreateInfo->CommandLine->Buffer, 
                          min(CreateInfo->CommandLine->Length, sizeof(pEvent->CommandLine) - 2));
        }
    }

    QueueNexusEvent(item);
}

void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    PEVENT_ITEM item = (PEVENT_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(EVENT_ITEM) + sizeof(NEXUS_IMAGE_LOAD_EVENT), 'sxuN');
    if (!item) return;

    RtlZeroMemory(item, sizeof(EVENT_ITEM) + sizeof(NEXUS_IMAGE_LOAD_EVENT));
    item->Event.Type = NexusEventImageLoad;
    item->Event.ProcessId = HandleToUlong(ProcessId);
    KeQuerySystemTimePrecise(&item->Event.Timestamp);

    PNEXUS_IMAGE_LOAD_EVENT iEvent = (PNEXUS_IMAGE_LOAD_EVENT)(&item->Event);
    iEvent->LoadAddress = ImageInfo->ImageBase;
    iEvent->ImageSize = ImageInfo->ImageSize;

    if (FullImageName) {
        RtlCopyMemory(iEvent->ImagePath, FullImageName->Buffer, 
                      min(FullImageName->Length, sizeof(iEvent->ImagePath) - 2));
    }

    QueueNexusEvent(item);
}

