#include "NetworkDetector.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <algorithm>
#include "../Logger.h"

#pragma comment(lib, "ws2_32.lib")

namespace TDS {

std::wstring NetworkDetector::GetProcessNameFromPid(uint32_t pid) {
    std::wstring name = L"Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        WCHAR path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            name = path;
            size_t pos = name.find_last_of(L"\\/");
            if (pos != std::wstring::npos) name = name.substr(pos + 1);
        }
        CloseHandle(hProcess);
    }
    return name;
}

bool NetworkDetector::IsAnomalousNetworkProcess(const std::wstring& processName) {
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    static const std::vector<std::wstring> anomalous = {
        L"notepad.exe", L"calc.exe", L"rundll32.exe", L"regsvr32.exe", L"cmd.exe",
        L"wscript.exe", L"cscript.exe", L"mshta.exe", L"certutil.exe"
    };
    for (const auto& a : anomalous) {
        if (lower == a) return true;
    }
    return false;
}

void NetworkDetector::AnalyzeConnection(uint32_t pid, const TDS_NETWORK_EVENT_DATA& data) {
    bool alert = false;
    std::string context = "";

    if (data.RemotePort == 80 || data.RemotePort == 443) {
        std::wstring procName = GetProcessNameFromPid(pid);
        if (IsAnomalousNetworkProcess(procName)) {
            alert = true;
            context = "Anomalous process making HTTP/HTTPS connection";
        }
    } else if (IsSuspiciousPort(data.RemotePort)) {
        alert = true;
        context = "Suspicious C2 connection on port " + std::to_string(data.RemotePort);
    }

    if (alert) {
        char ipStr[INET6_ADDRSTRLEN] = {0};

        if (data.AddressFamily == AF_INET) {
            IN_ADDR addr;
            addr.S_un.S_addr = data.Ipv4Address;
            inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
        } else if (data.AddressFamily == AF_INET6) {
            IN6_ADDR addr;
            memcpy(addr.u.Byte, data.Ipv6Address, 16);
            inet_ntop(AF_INET6, &addr, ipStr, sizeof(ipStr));
        }
        
        Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_C2_COMMUNICATION, context, ipStr, pid);
    }
}

bool NetworkDetector::IsSuspiciousPort(USHORT port) {
    static const std::vector<USHORT> suspiciousPorts = {
        8080, 8443, 4444, 8888, 31337, 5555
    };
    for (USHORT p : suspiciousPorts) {
        if (port == p) return true;
    }
    return false;
}

} // namespace TDS

