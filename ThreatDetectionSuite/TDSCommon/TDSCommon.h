#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <stdint.h>
#endif

// FIX: Move TDS_USER_METRICS OUTSIDE of #pragma pack(1) (Issue 14)
#ifndef _KERNEL_MODE
#include <atomic>
struct TDS_USER_METRICS {
    std::atomic<uint64_t> TotalEventsProcessed{0};
    std::atomic<uint64_t> ThreatsMitigated{0};
    std::atomic<uint64_t> DriverEventsDropped{0};
};
#endif

#pragma pack(push, 1)

#define TDS_DEVICE_TYPE (unsigned long)0x8000

#define IOCTL_TDS_GET_NEXT_EVENT \
    CTL_CODE(TDS_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_TDS_SET_PROTECTION_POLICY \
    CTL_CODE(TDS_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_TDS_HEARTBEAT \
    CTL_CODE(TDS_DEVICE_TYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum _TDS_EVENT_TYPE {
    TDSEventProcessCreate = 1,
    TDSEventProcessTerminate = 2,
    TDSEventThreadCreate = 3,
    TDSEventImageLoad = 4,
    TDSEventRegistryOp = 5,
    TDSEventFileOp = 6,
    TDSEventHandleOp = 7,
    TDSEventHollowingDetected = 8,
    TDSEventNetworkConnect = 9, 
    TDSEventRemoteThread = 10,
    TDSEventFileCreate = 11,
    TDSEventFileDelete = 12,
    TDSEventRegistrySet = 13,
    TDSEventRegistryDelete = 14,
    TDSEventRegistryRename = 15,
    TDSEventApcInjection = 16,
    TDSEventEarlyBirdInjection = 17
} TDS_EVENT_TYPE;

typedef enum _TDS_THREAT_SEVERITY {
    TDS_SEVERITY_CRITICAL = 80,
    TDS_SEVERITY_HIGH = 50,
    TDS_SEVERITY_MEDIUM = 25,
    TDS_SEVERITY_INFO = 10
} TDS_THREAT_SEVERITY;

typedef enum _TDS_THREAT_CATEGORY {
    CAT_PROCESS_BEHAVIOR = 0, 
    CAT_DLL_INJECTION, 
    CAT_MEMORY_ANOMALY,
    CAT_FILE_ANOMALY, 
    CAT_REGISTRY_ANOMALY, 
    CAT_NETWORK_ANOMALY,
    CAT_PRIVILEGE_ESC, 
    CAT_DKOM_DETECTION,
    CAT_ANTI_ANALYSIS, 
    CAT_CREDENTIAL_THEFT,
    CAT_HOOK_DETECTION, 
    CAT_LOLBIN_ABUSE, 
    CAT_PERSISTENCE,
    CAT_C2_COMMUNICATION, 
    CAT_KERNEL_ANOMALY, 
    CAT_ROOTKIT_INDICATOR, 
    CAT_EVASION
} TDS_THREAT_CATEGORY;

#define TDS_MAX_THREAT_CATEGORY 17

typedef enum _TDS_REMEDIATION_ACTION {
    ACTION_KILL_PROCESS,
    ACTION_DELETE_FILE,
    ACTION_REMOVE_REGISTRY,
    ACTION_DELETE_SCHEDULED_TASK,
    ACTION_CLEAR_STARTUP,
    ACTION_BLOCK_NETWORK,
    ACTION_UNHOOK_API,
    ACTION_QUARANTINE,
    ACTION_MAX_REMEDIATION
} TDS_REMEDIATION_ACTION;

typedef struct _TDS_NETWORK_EVENT_DATA {
    uint8_t AddressFamily; 
    uint8_t Protocol;
    uint16_t RemotePort;
    union {
        uint32_t Ipv4Address;
        uint8_t Ipv6Address[16];
    };
} TDS_NETWORK_EVENT_DATA, *PTDS_NETWORK_EVENT_DATA;

typedef struct _TDS_REMOTE_THREAD_DATA {
    uint32_t TargetProcessId;
} TDS_REMOTE_THREAD_DATA, *PTDS_REMOTE_THREAD_DATA;

typedef struct _TDS_EVENT_HEADER {
    TDS_EVENT_TYPE Type;
    uint64_t Timestamp;
    uint32_t ProcessId;
    uint32_t ThreadId;
    TDSEventApcInjection = 16,
    TDSEventEarlyBirdInjection = 17,
    TDSEventGhostingAttempt = 18
    } TDS_EVENT_TYPE;

    typedef struct _TDS_PROCESS_EVENT_DATA {
    uint32_t ParentProcessId;
    uint8_t Create;
    uint32_t ImagePathOffset;
    uint32_t CommandLineOffset;
    } TDS_PROCESS_EVENT_DATA, *PTDS_PROCESS_EVENT_DATA;

    typedef struct _TDS_IMAGE_LOAD_DATA {
    uint64_t LoadAddress;
    uint64_t ImageSize;
    uint32_t ImagePathOffset;
    } TDS_IMAGE_LOAD_DATA, *PTDS_IMAGE_LOAD_DATA;

    typedef struct _TDS_FILE_EVENT_DATA {
    uint8_t Operation; // 1: Create, 2: Delete, 3: Rename, 4: Ghosting Attempt
    uint32_t FilePathOffset;
    uint32_t TargetPathOffset; 
    } TDS_FILE_EVENT_DATA, *PTDS_FILE_EVENT_DATA;
typedef struct _TDS_HANDLE_OP_DATA {
    uint32_t TargetProcessId;
    uint32_t DesiredAccess;
    uint8_t IsThread;
} TDS_HANDLE_OP_DATA, *PTDS_HANDLE_OP_DATA;

typedef struct _TDS_REGISTRY_EVENT_DATA {
    uint32_t Type; // REG_SZ, etc.
    uint32_t KeyPathOffset;
    uint32_t ValueNameOffset;
    uint32_t DataOffset;
    uint32_t DataSize;
} TDS_REGISTRY_EVENT_DATA, *PTDS_REGISTRY_EVENT_DATA;

typedef struct _TDS_THREAT_LOG {
    uint32_t ThreatId;
    TDS_THREAT_SEVERITY Severity;
    TDS_THREAT_CATEGORY Category;
    char Description[512];
    char Ioc[256];
    uint64_t Timestamp; 
    uint32_t AssociatedPid;
} TDS_THREAT_LOG, *PTDS_THREAT_LOG;

typedef struct _TDS_REMEDIATION_RESULT {
    TDS_REMEDIATION_ACTION ActionType;
    char Target[260];
    uint8_t Success;
    uint32_t ErrorCode;
    char StatusMessage[256];
} TDS_REMEDIATION_RESULT, *PTDS_REMEDIATION_RESULT;

#pragma pack(pop)

#ifndef _KERNEL_MODE
inline const char* GetTDSCategoryName(TDS_THREAT_CATEGORY category) {
    static const char* category_names[] = {
        "PROCESS_BEHAVIOR", "DLL_INJECTION", "MEMORY_ANOMALY", "FILE_ANOMALY",
        "REGISTRY_ANOMALY", "NETWORK_ANOMALY", "PRIVILEGE_ESC", "DKOM_DETECTION",
        "ANTI_ANALYSIS", "CREDENTIAL_THEFT", "HOOK_DETECTION", "LOLBIN_ABUSE",
        "PERSISTENCE", "C2_COMMUNICATION", "KERNEL_ANOMALY", "ROOTKIT_INDICATOR",
        "EVASION"
    };
    if ((int)category >= 0 && (int)category < (int)TDS_MAX_THREAT_CATEGORY) {
        return category_names[category];
    }
    return "UNKNOWN_CATEGORY";
}

inline const char* GetTDSSeverityName(TDS_THREAT_SEVERITY severity) {
    if (severity >= TDS_SEVERITY_CRITICAL) return "CRITICAL";
    if (severity >= TDS_SEVERITY_HIGH)     return "HIGH";
    if (severity >= TDS_SEVERITY_MEDIUM)   return "MEDIUM";
    return "INFO";
}
#endif

#define MAX_EVENT_BUFFER_SIZE 4096
#define EVENT_QUEUE_LIMIT 5000 
#define TDS_TERMINATION_EXIT_CODE 0xDEAD

