#include "NetworkDetector.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../Logger.h"

#pragma comment(lib, "ws2_32.lib")

namespace TDS {

void NetworkDetector::AnalyzeConnection(uint32_t pid, uint32_t remoteIp, uint16_t remotePort) {
    if (IsSuspiciousPort(remotePort)) {
        IN_ADDR addr;
        addr.S_un.S_addr = remoteIp;
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
        
        std::string desc = "Suspicious C2 connection on port " + std::to_string(remotePort);
        Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_C2_COMMUNICATION, desc, ipStr, pid);
    }
}

bool NetworkDetector::IsSuspiciousPort(USHORT port) {
    static const std::vector<USHORT> suspiciousPorts = {
        4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 666, 1337
    };
    for (USHORT p : suspiciousPorts) {
        if (port == p) return true;
    }
    return false;
}

} // namespace TDS
