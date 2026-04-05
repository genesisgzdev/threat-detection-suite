#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "../../TDSCommon/TDSCommon.h"

namespace TDS {

class NetworkDetector {
public:
    static bool IsSuspiciousPort(USHORT port);
    static void AnalyzeConnection(uint32_t pid, const TDS_NETWORK_EVENT_DATA& data);

private:
    static std::wstring GetProcessNameFromPid(uint32_t pid);
    static bool IsAnomalousNetworkProcess(const std::wstring& processName);
};

} // namespace TDS
