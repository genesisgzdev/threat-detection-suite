#pragma once

#ifdef _KERNEL_MODE
#include <ntdef.h>
#include <ntifs.h>
#else
#include <windows.h>
#include <winioctl.h>
#include <stdint.h>
#endif

#define IOCTL_TDS_SET_PROTECTION_POLICY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_TDS_GET_NEXT_EVENT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_TDS_SET_RUNTIME_POLICY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_TDS_GET_QUEUE_STATS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)

#define MAX_EVENT_BUFFER_SIZE 4096
#define EVENT_QUEUE_LIMIT 10000

typedef struct _TDS_QUEUE_STATS {
    ULONG Version;
    ULONG Size;
    ULONG QueueDepth;
    ULONG DroppedEvents;
} TDS_QUEUE_STATS, *PTDS_QUEUE_STATS;

typedef enum _TDS_EVENT_TYPE {
    TDSEventProcessCreate = 1,
    TDSEventProcessTerminate,
    TDSEventImageLoad,
    TDSEventThreadCreate,
    TDSEventRemoteThread,
    TDSEventRegistrySet,
    TDSEventRegistryDelete,
    TDSEventRegistryRename,
    TDSEventFileOp,
    TDSEventFileDelete,
    TDSEventGhostingAttempt,
    TDSEventRansomwareActivity,
    TDSEventVssDeletion,
    TDSEventNetworkConnect,
    TDSEventEtwTiApcInjection,
    TDSEventHandleOp,
    TDSEventApcInjection,
    TDSEventRegistryOp
} TDS_EVENT_TYPE;

typedef struct _TDS_EVENT_HEADER {
    TDS_EVENT_TYPE Type;
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG DataSize;
    LARGE_INTEGER Timestamp;
} TDS_EVENT_HEADER, *PTDS_EVENT_HEADER;

typedef struct _TDS_PROTECTION_POLICY {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG ObserveOnly;
    ULONG AllowProcessTermination;
    ULONG AllowNetworkContainment;
    ULONG Reserved[3];
} TDS_PROTECTION_POLICY, *PTDS_PROTECTION_POLICY;

#define TDS_POLICY_FLAG_PROTECT_SERVICE 0x00000001UL
#define TDS_POLICY_FLAG_ENABLE_WFP      0x00000002UL
#define TDS_POLICY_FLAG_ENABLE_MINIFILTER 0x00000004UL

typedef struct _TDS_PROCESS_EVENT_DATA {
    BOOLEAN Create;
    ULONG ParentProcessId;
    ULONG ImagePathOffset;
    ULONG CommandLineOffset;
} TDS_PROCESS_EVENT_DATA, *PTDS_PROCESS_EVENT_DATA;

typedef struct _TDS_IMAGE_LOAD_DATA {
    ULONG64 LoadAddress;
    ULONG64 ImageSize;
    ULONG ImagePathOffset;
} TDS_IMAGE_LOAD_DATA, *PTDS_IMAGE_LOAD_DATA;

typedef struct _TDS_REGISTRY_EVENT_DATA {
    ULONG Type;
    ULONG DataSize;
    ULONG KeyPathOffset;
    ULONG ValueNameOffset;
    ULONG DataOffset;
} TDS_REGISTRY_EVENT_DATA, *PTDS_REGISTRY_EVENT_DATA;

typedef struct _TDS_NETWORK_EVENT_DATA {
    ULONG AddressFamily;
    ULONG Ipv4Address;
    UCHAR Ipv6Address[16];
    USHORT RemotePort;
    UCHAR Protocol;
} TDS_NETWORK_EVENT_DATA, *PTDS_NETWORK_EVENT_DATA;

typedef struct _TDS_FILE_EVENT_DATA {
    ULONG Operation;
    ULONG FilePathOffset;
    ULONG TargetPathOffset;
} TDS_FILE_EVENT_DATA, *PTDS_FILE_EVENT_DATA;

typedef struct _TDS_REMOTE_THREAD_DATA {
    ULONG TargetProcessId;
} TDS_REMOTE_THREAD_DATA, *PTDS_REMOTE_THREAD_DATA;
