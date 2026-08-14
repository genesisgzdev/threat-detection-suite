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
#include <cmath>
#include <sstream>
#include "NetworkDetector.h"
#include "../Logger.h"
#include "../ips/IPSManager.h"
#include "../ThreatIntelManager.h"
#include "../ResponsePolicy.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace TDS {

std::unordered_map<std::string, ConnectionProfile> NetworkDetector::s_ConnectionProfiles;
std::mutex NetworkDetector::s_ProfileLock;

bool NetworkDetector::IsSuspiciousPort(USHORT port) {
    // Industrial check: Not just 4444, but typical malware default ports
    const std::vector<USHORT> badPorts = { 4444, 8888, 1337, 31337, 666, 6667, 4445, 9999 };
    return std::find(badPorts.begin(), badPorts.end(), port) != badPorts.end();
}

double NetworkDetector::CalculateShannonEntropy(const std::string& data) {
    if (data.empty()) return 0.0;
    std::unordered_map<char, int> freq;
    for (char c : data) freq[c]++;
    double entropy = 0.0;
    double len = (double)data.length();
    for (auto const& pair : freq) {
        double p = pair.second / len;
        entropy -= p * log2(p);
    }
    return entropy;
}

void NetworkDetector::DetectBeaconing(uint32_t pid, const std::string& remoteIp) {
    std::lock_guard<std::mutex> lock(s_ProfileLock);
    
    std::stringstream keyStream;
    keyStream << pid << "_" << remoteIp;
    std::string key = keyStream.str();

    if (s_ConnectionProfiles.size() >= 10000 && s_ConnectionProfiles.find(key) == s_ConnectionProfiles.end()) {
        s_ConnectionProfiles.erase(s_ConnectionProfiles.begin());
    }

    uint64_t now = GetTickCount64();
    auto& profile = s_ConnectionProfiles[key];
    
    profile.timestamps.push_back(now);
    profile.totalConnections++;

    // Maintain a 60-second sliding window
    while (!profile.timestamps.empty() && (now - profile.timestamps.front() > 60000)) {
        profile.timestamps.pop_front();
    }

    // Heuristic: More than 30 connections to the same IP within 60 seconds indicates aggressive beaconing or tunneling
    if (profile.timestamps.size() > 30) {
        Logger::Instance().LogThreat(
            TDS_SEVERITY_CRITICAL, 
            CAT_C2_COMMUNICATION, 
            "Aggressive C2 Beaconing Detected (Sliding Window Volume Anomaly)", 
            remoteIp, 
            pid
        );
        
        ResponsePolicy policy = ResponsePolicy::FromEnvironment();
        if (policy.AllowsTermination(95) || policy.AllowsContainment(95)) {
            IPSManager::TerminateNetworkConnection(pid, remoteIp);
        }
        
        // Clear the profile to prevent log spam
        profile.timestamps.clear();
    }
}

void NetworkDetector::AnalyzeConnection(uint32_t pid, const TDS_NETWORK_EVENT_DATA& data) {
    std::string ipStr;
    
    if (data.AddressFamily == 2) { // AF_INET
        IN_ADDR addr;
        addr.S_un.S_addr = data.Ipv4Address;
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
        ipStr = buffer;
    } else if (data.AddressFamily == 23) { // AF_INET6
        IN6_ADDR addr;
        memcpy(addr.u.Byte, data.Ipv6Address, 16);
        char buffer[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr, buffer, INET6_ADDRSTRLEN);
        ipStr = buffer;
    }

    if (ipStr.empty()) return;

    if (IsSuspiciousPort(data.RemotePort)) {
        Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_NETWORK_ANOMALY, "Suspicious outbound port connectivity", ipStr, pid);
    }

    std::wstring processName = GetProcessNameFromPid(pid);
    if (IsAnomalousNetworkProcess(processName)) {
        Logger::Instance().LogThreat(TDS_SEVERITY_MEDIUM, CAT_NETWORK_ANOMALY,
            "Script or LOLBin process opened an outbound connection", ipStr, pid);
    }

    // Apply real-time beaconing heuristics
    DetectBeaconing(pid, ipStr);
    
    // Optional enrichment is deliberately outside the detection critical path.
    ThreatIntelManager::Instance().EnrichIoC(ipStr);
}

std::wstring NetworkDetector::GetProcessNameFromPid(uint32_t pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return L"";
    WCHAR path[MAX_PATH] = {};
    DWORD size = ARRAYSIZE(path);
    std::wstring result;
    if (QueryFullProcessImageNameW(process, 0, path, &size)) result.assign(path, size);
    CloseHandle(process);
    return result;
}

bool NetworkDetector::IsAnomalousNetworkProcess(const std::wstring& processName) {
    if (processName.empty()) return false;
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    static const wchar_t* suspicious[] = {
        L"\\powershell.exe", L"\\mshta.exe", L"\\rundll32.exe",
        L"\\regsvr32.exe", L"\\certutil.exe", L"\\bitsadmin.exe"
    };
    for (const auto* suffix : suspicious) {
        if (lower.size() >= wcslen(suffix) && lower.compare(lower.size() - wcslen(suffix), wcslen(suffix), suffix) == 0) return true;
    }
    return false;
}

} // namespace TDS
