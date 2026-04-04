#include "NetworkDetector.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../Logger.h"

#pragma comment(lib, "ws2_32.lib")

namespace TDS {

void NetworkDetector::AnalyzeConnection(uint32_t pid, const TDS_NETWORK_EVENT_DATA& data) {
    if (IsSuspiciousPort(data.RemotePort)) {
        char ipStr[INET6_ADDRSTRLEN] = {0};

        // FIX: IPv6 Support (Issue 48)
        if (data.AddressFamily == AF_INET) {
            IN_ADDR addr;
            addr.S_un.S_addr = data.Ipv4Address;
            inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
        } else if (data.AddressFamily == AF_INET6) {
            IN6_ADDR addr;
            memcpy(addr.u.Byte, data.Ipv6Address, 16);
            inet_ntop(AF_INET6, &addr, ipStr, sizeof(ipStr));
        }
        
        std::string desc = "Suspicious C2 connection on port " + std::to_string(data.RemotePort);
        Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_C2_COMMUNICATION, desc, ipStr, pid);
    }
}

bool NetworkDetector::IsSuspiciousPort(USHORT port) {
    // FIX: Include standard C2 ports (80, 443) and remove script-kiddie only ports (Issue 47)
    static const std::vector<USHORT> suspiciousPorts = {
        80, 443, 8080, 8443, 4444, 8888
    };
    for (USHORT p : suspiciousPorts) {
        if (port == p) return true;
    }
    return false;
}

} // namespace TDS
