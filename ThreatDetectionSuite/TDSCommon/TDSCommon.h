#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#ifdef __cplusplus
#include <string>
#include <atomic>
#include <cstdint>
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

#define IOCTL_TDS_PROTECT_PID \
    CTL_CODE(TDS_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
    TDSEventHandleOp,
    TDSEventProcessHollowing
} TDS_EVENT_TYPE;

//
// MITRE ATT&CK Technique IDs
//
#define MITRE_T1055 L"T1055" // Process Injection
#define MITRE_T1055_012 L"T1055.012" // Process Hollowing
#define MITRE_T1003_001 L"T1003.001" // LSASS Memory
#define MITRE_T1112 L"T1112" // Modify Registry
#define MITRE_T1070_001 L"T1070.001" // Clear Windows Event Logs

//
// Event Structures
//
typedef struct _TDS_EVENT_HEADER {
    TDS_EVENT_TYPE Type;
    LARGE_INTEGER Timestamp;
    ULONG ProcessId;
    ULONG ThreadId;
    WCHAR TechniqueId[16];
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

typedef struct _TDS_REGISTRY_EVENT {
    TDS_EVENT_HEADER Header;
    WCHAR KeyPath[512];
    WCHAR ValueName[256];
    ULONG OperationType;
} TDS_REGISTRY_EVENT, *PTDS_REGISTRY_EVENT;

typedef struct _TDS_PROCESS_HOLLOWING_EVENT {
    TDS_EVENT_HEADER Header;
    PVOID ExpectedImageBase;
    PVOID ActualImageBase;
    WCHAR ImagePath[512];
} TDS_PROCESS_HOLLOWING_EVENT, *PTDS_PROCESS_HOLLOWING_EVENT;

#ifdef __cplusplus
//
// High-performance metrics using std::atomic
//
struct TDS_METRICS {
    std::atomic<uint64_t> ProcessEvents{0};
    std::atomic<uint64_t> RegistryEvents{0};
    std::atomic<uint64_t> FileEvents{0};
    std::atomic<uint64_t> HandleEvents{0};
    std::atomic<uint64_t> HollowingEvents{0};
};

//
// JSONL log entry definition
//
struct TDS_JSONL_LOG {
    std::wstring TimestampISO8601;
    uint32_t ProcessId;
    std::wstring EventType;
    std::wstring TechniqueId;
    std::wstring Details;
};
#endif

//
// Shared buffer size for events
//
#define MAX_EVENT_QUEUE_SIZE 1024
