#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include "NetworkDetector.h"
#include "../Logger.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace TDS {

bool NetworkDetector::IsSuspiciousPort(USHORT port) {
    return (port == 4444 || port == 8888 || port == 1337);
}

void NetworkDetector::AnalyzeConnection(uint32_t pid, const TDS_NETWORK_EVENT_DATA& data) {
    if (data.AddressFamily == AF_INET) {
        IN_ADDR addr;
        addr.S_un.S_addr = data.Ipv4Address;
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);

        if (IsSuspiciousPort(data.RemotePort)) {
            Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_NETWORK_ANOMALY, "Suspicious outbound port detected", ipStr, pid);
        }
    }
}

std::wstring NetworkDetector::GetProcessNameFromPid(uint32_t pid) {
    UNREFERENCED_PARAMETER(pid);
    return L"";
}

bool NetworkDetector::IsAnomalousNetworkProcess(const std::wstring& processName) {
    UNREFERENCED_PARAMETER(processName);
    return false;
}

} // namespace TDS
