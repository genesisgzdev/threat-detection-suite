#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

//
// IOCTL Definitions for ThreatDetectionSuite
//
#define TDS_DEVICE_TYPE 0x8000

#define IOCTL_TDS_REGISTER_EVENT_EVENT \
    CTL_CODE(TDS_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_TDS_GET_NEXT_EVENT \
    CTL_CODE(TDS_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_TDS_SET_POLICY \
    CTL_CODE(TDS_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Event Types
//
typedef enum _TDS_EVENT_TYPE {
    TDSEventProcessCreate,
    TDSEventProcessTerminate,
    TDSEventThreadCreate,
    TDSEventImageLoad,
    TDSEventRegistryOp,
    TDSEventFileOp,
    TDSEventHandleOp
} TDS_EVENT_TYPE;

//
// Event Structures
//
typedef struct _TDS_EVENT_HEADER {
    TDS_EVENT_TYPE Type;
    LARGE_INTEGER Timestamp;
    ULONG ProcessId;
    ULONG ThreadId;
} TDS_EVENT_HEADER, *PTDS_EVENT_HEADER;

typedef struct _TDS_PROCESS_EVENT {
    TDS_EVENT_HEADER Header;
    ULONG ParentProcessId;
    BOOLEAN Create;
    WCHAR ImagePath[512];
    WCHAR CommandLine[1024];
} TDS_PROCESS_EVENT, *PTDS_PROCESS_EVENT;

typedef struct _TDS_IMAGE_LOAD_EVENT {
    TDS_EVENT_HEADER Header;
    PVOID LoadAddress;
    ULONG64 ImageSize;
    WCHAR ImagePath[512];
} TDS_IMAGE_LOAD_EVENT, *PTDS_IMAGE_LOAD_EVENT;

typedef struct _TDS_HANDLE_EVENT {
    TDS_EVENT_HEADER Header;
    ULONG TargetProcessId;
    ULONG DesiredAccess;
    BOOLEAN IsThread;
} TDS_HANDLE_EVENT, *PTDS_HANDLE_EVENT;

//
// Shared buffer size for events
//
#define MAX_EVENT_QUEUE_SIZE 1024
