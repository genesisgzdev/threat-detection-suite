#pragma once

#include <cstdint>
#include <cstring>

namespace TDS {

enum TDS_THREAT_SEVERITY : uint32_t {
    TDS_SEVERITY_INFO = 0,
    TDS_SEVERITY_LOW = 1,
    TDS_SEVERITY_MEDIUM = 2,
    TDS_SEVERITY_HIGH = 3,
    TDS_SEVERITY_CRITICAL = 4
};

enum TDS_THREAT_CATEGORY : uint32_t {
    CAT_PROCESS_BEHAVIOR = 1,
    CAT_LOLBIN_ABUSE,
    CAT_DLL_INJECTION,
    CAT_CREDENTIAL_THEFT,
    CAT_C2_COMMUNICATION,
    CAT_NETWORK_ANOMALY,
    CAT_REGISTRY_ANOMALY,
    CAT_PERSISTENCE,
    CAT_MEMORY_ANOMALY,
    CAT_HOOK_DETECTION
};

struct TDS_THREAT_LOG {
    uint32_t ThreatId;
    TDS_THREAT_SEVERITY Severity;
    TDS_THREAT_CATEGORY Category;
    uint64_t Timestamp;
    uint32_t AssociatedPid;
    char Description[512];
    char Ioc[1024];
};

inline const char* GetTDSSeverityName(TDS_THREAT_SEVERITY severity) {
    switch (severity) {
    case TDS_SEVERITY_INFO: return "INFO";
    case TDS_SEVERITY_LOW: return "LOW";
    case TDS_SEVERITY_MEDIUM: return "MEDIUM";
    case TDS_SEVERITY_HIGH: return "HIGH";
    case TDS_SEVERITY_CRITICAL: return "CRITICAL";
    default: return "UNKNOWN";
    }
}

inline const char* GetTDSCategoryName(TDS_THREAT_CATEGORY category) {
    switch (category) {
    case CAT_PROCESS_BEHAVIOR: return "PROCESS_BEHAVIOR";
    case CAT_LOLBIN_ABUSE: return "LOLBIN_ABUSE";
    case CAT_DLL_INJECTION: return "DLL_INJECTION";
    case CAT_CREDENTIAL_THEFT: return "CREDENTIAL_THEFT";
    case CAT_C2_COMMUNICATION: return "C2_COMMUNICATION";
    case CAT_NETWORK_ANOMALY: return "NETWORK_ANOMALY";
    case CAT_REGISTRY_ANOMALY: return "REGISTRY_ANOMALY";
    case CAT_PERSISTENCE: return "PERSISTENCE";
    case CAT_MEMORY_ANOMALY: return "MEMORY_ANOMALY";
    case CAT_HOOK_DETECTION: return "HOOK_DETECTION";
    default: return "UNKNOWN";
    }
}

} // namespace TDS
