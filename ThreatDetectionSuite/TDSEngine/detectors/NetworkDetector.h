#pragma once
#include <windows.h>
#include <vector>
#include <string>

namespace TDS {

class NetworkDetector {
public:
    static bool IsSuspiciousPort(USHORT port);
    static void AnalyzeConnection(uint32_t pid, uint32_t remoteIp, uint16_t remotePort);
};

} // namespace TDS
