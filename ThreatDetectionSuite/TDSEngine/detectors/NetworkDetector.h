#pragma once
#include <windows.h>
#include <string>
#include <unordered_map>
#include <deque>
#include <mutex>
#include "../TDSCommon/TDSCommon.h"

namespace TDS {

struct ConnectionProfile {
    std::deque<uint64_t> timestamps; // Rolling window for beaconing detection
    uint32_t totalConnections;
    uint32_t bytesTransferred; // If available
};

class NetworkDetector {
public:
    static bool IsSuspiciousPort(USHORT port);
    static void AnalyzeConnection(uint32_t pid, const TDS_NETWORK_EVENT_DATA& data);
    static std::wstring GetProcessNameFromPid(uint32_t pid);
    static bool IsAnomalousNetworkProcess(const std::wstring& processName);

private:
    static double CalculateShannonEntropy(const std::string& data);
    static void DetectBeaconing(uint32_t pid, const std::string& remoteIp);

    // Global state for C2 beaconing analysis
    // Key: "PID_IP"
    static std::unordered_map<std::string, ConnectionProfile> s_ConnectionProfiles;
    static std::mutex s_ProfileLock;
};

} // namespace TDS
