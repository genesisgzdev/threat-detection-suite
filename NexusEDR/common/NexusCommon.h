#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

//
// IOCTL Definitions for NexusEDR
//
#define NEXUS_DEVICE_TYPE 0x8000

#define IOCTL_NEXUS_REGISTER_EVENT_EVENT \
    CTL_CODE(NEXUS_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NEXUS_GET_NEXT_EVENT \
    CTL_CODE(NEXUS_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NEXUS_SET_POLICY \
    CTL_CODE(NEXUS_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Event Types
//
typedef enum _NEXUS_EVENT_TYPE {
    NexusEventProcessCreate,
    NexusEventProcessTerminate,
    NexusEventThreadCreate,
    NexusEventImageLoad,
    NexusEventRegistryOp,
    NexusEventFileOp,
    NexusEventHandleOp
} NEXUS_EVENT_TYPE;

//
// Event Structures
//
typedef struct _NEXUS_EVENT_HEADER {
    NEXUS_EVENT_TYPE Type;
    LARGE_INTEGER Timestamp;
    ULONG ProcessId;
    ULONG ThreadId;
} NEXUS_EVENT_HEADER, *PNEXUS_EVENT_HEADER;

typedef struct _NEXUS_PROCESS_EVENT {
    NEXUS_EVENT_HEADER Header;
    ULONG ParentProcessId;
    BOOLEAN Create;
    WCHAR ImagePath[512];
    WCHAR CommandLine[1024];
} NEXUS_PROCESS_EVENT, *PNEXUS_PROCESS_EVENT;

typedef struct _NEXUS_IMAGE_LOAD_EVENT {
    NEXUS_EVENT_HEADER Header;
    PVOID LoadAddress;
    ULONG64 ImageSize;
    WCHAR ImagePath[512];
} NEXUS_IMAGE_LOAD_EVENT, *PNEXUS_IMAGE_LOAD_EVENT;

typedef struct _NEXUS_HANDLE_EVENT {
    NEXUS_EVENT_HEADER Header;
    ULONG TargetProcessId;
    ULONG DesiredAccess;
    BOOLEAN IsThread;
} NEXUS_HANDLE_EVENT, *PNEXUS_HANDLE_EVENT;

//
// Shared buffer size for events
//
#define MAX_EVENT_QUEUE_SIZE 1024
