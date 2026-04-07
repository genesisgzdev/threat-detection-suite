#include "TDSEngine.h"
#include <iostream>
#include <chrono>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <winternl.h>
#include <unordered_set>
#include <amsi.h>
#include "Logger.h"
#include "detectors/NetworkDetector.h"
#include "ips/IPSManager.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "amsi.lib")
#pragma comment(lib, "version.lib")

namespace TDS {

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

TDSEngine::TDSEngine() {
    m_lolbasBinaries = {
        L"certutil.exe", L"powershell.exe", L"mshta.exe", L"regsvr32.exe", 
        L"rundll32.exe", L"msiexec.exe", L"csc.exe", L"bitsadmin.exe",
        L"wmic.exe", L"schtasks.exe", L"at.exe", L"sc.exe"
    };
    
    m_eventBus = std::make_unique<EventBus>();
    m_correlator = std::make_unique<SequenceCorrelator>();
}

TDSEngine::~TDSEngine() {
    Shutdown();
}

void TDSEngine::Start() {
    if (m_running) return;
    m_running = true;
    m_analysisThread = std::thread(&TDSEngine::AnalysisLoop, this);
}

void TDSEngine::Shutdown() {
    m_running = false;
    if (m_eventBus) m_eventBus->Stop();
    if (m_analysisThread.joinable()) {
        m_analysisThread.join();
    }
}

void TDSEngine::PushEvent(const Event& event) {
    m_eventBus->Push(event);
}

void TDSEngine::AnalysisLoop() {
    while (m_running) {
        auto eventOpt = m_eventBus->WaitAndPop(500);
        if (eventOpt) {
            EvaluateThreat(*eventOpt);
            m_correlator->Analyze(*eventOpt);
        }
    }
}

void TDSEngine::EvaluateThreat(const Event& event) {
    switch (event.Type) {
        case TDSEventProcessCreate: {
            if (auto data = std::get_if<ProcessEvent>(&event.Data)) {
                if (IsLolbasBinary(data->ImagePath)) {
                    int score = CalculateLOLBinRiskScore(data->CommandLine);
                    if (score >= 85) {
                        std::string cmd;
                        for (auto c : data->CommandLine) cmd += (char)c;
                        Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_LOLBIN_ABUSE, "Critical LOLBin abuse detected", cmd, event.Pid);
                        
                        IPSManager::ContainProcess(event.Pid);
                        IPSManager::TerminateMaliciousProcess(event.Pid);
                    } else if (score >= 50) {
                        std::string cmd;
                        for (auto c : data->CommandLine) cmd += (char)c;
                        Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_LOLBIN_ABUSE, "Suspicious LOLBin execution", cmd, event.Pid);
                    }
                }
            }
            break;
        }
        case TDSEventRemoteThread: {
            if (auto data = std::get_if<RemoteThreadEvent>(&event.Data)) {
                Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_DLL_INJECTION, "Remote thread injection detected", "Target PID: " + std::to_string(data->TargetPid), event.Pid);
                
                IPSManager::ContainProcess(event.Pid);
                IPSManager::TerminateMaliciousProcess(event.Pid);
            }
            break;
        }
        case TDSEventHandleOp: {
            if (auto data = std::get_if<HandleOpEvent>(&event.Data)) {
                if (data->DesiredAccess & PROCESS_VM_READ) {
                    Logger::Instance().LogThreat(TDS_SEVERITY_MEDIUM, CAT_CREDENTIAL_THEFT, "Suspicious handle to sensitive process", "Target PID: " + std::to_string(data->TargetPid), event.Pid);
                }
            }
            break;
        }
        case TDSEventNetworkConnect: {
            if (auto data = std::get_if<NetworkEvent>(&event.Data)) {
                TDS_NETWORK_EVENT_DATA netData = {};
                netData.AddressFamily = AF_INET; 
                netData.Ipv4Address = data->RemoteAddress;
                netData.RemotePort = data->RemotePort;
                netData.Protocol = data->Protocol;
                NetworkDetector::AnalyzeConnection(event.Pid, netData);
            }
            break;
        }
        default:
            break;
    }
}

bool TDSEngine::IsLolbasBinary(const std::wstring& path) {
    size_t lastSlash = path.find_last_of(L"\\");
    std::wstring filename = (lastSlash == std::wstring::npos) ? path : path.substr(lastSlash + 1);
    std::wstring lower = filename;
    for (auto& c : lower) c = towlower(c);
    
    if (m_lolbasBinaries.find(lower) != m_lolbasBinaries.end()) return true;

    // Check OriginalFilename from PE Version Info to prevent renaming evasions
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size > 0) {
        std::vector<BYTE> versionData(size);
        if (GetFileVersionInfoW(path.c_str(), handle, size, versionData.data())) {
            LPVOID buffer = nullptr;
            UINT len = 0;
            
            struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *lpTranslate;
            if (VerQueryValueW(versionData.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &len) && len >= sizeof(LANGANDCODEPAGE)) {
                WCHAR subBlock[256];
                swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\OriginalFilename", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
                
                if (VerQueryValueW(versionData.data(), subBlock, &buffer, &len) && buffer) {
                    std::wstring origName = (LPCWSTR)buffer;
                    std::transform(origName.begin(), origName.end(), origName.begin(), ::towlower);
                    if (m_lolbasBinaries.find(origName) != m_lolbasBinaries.end()) return true;
                }
            }
        }
    }
    return false;
}

int TDSEngine::CalculateLOLBinRiskScore(const std::wstring& commandLine) {
    int score = 0;
    std::wstring lowerCmd = commandLine;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::towlower);

    if (lowerCmd.find(L"http") != std::wstring::npos || lowerCmd.find(L"ftp") != std::wstring::npos) score += 40;
    if (lowerCmd.find(L"bypass") != std::wstring::npos || lowerCmd.find(L"hidden") != std::wstring::npos) score += 30;
    if (lowerCmd.find(L"enc") != std::wstring::npos || lowerCmd.find(L"base64") != std::wstring::npos) score += 50;
    if (lowerCmd.find(L"downloadstring") != std::wstring::npos || lowerCmd.find(L"invoke-webrequest") != std::wstring::npos) score += 45;

    return (std::min)(score, 100);
}

std::wstring TDSEngine::GetProcessCommandLine(DWORD pid) {
    UNREFERENCED_PARAMETER(pid);
    return L""; // Handled by driver telemetry in v5.0.0
}

void TDSEngine::UpdateNetworkStats(DWORD pid, double latency) {
    std::lock_guard<std::mutex> lock(m_engineMutex);
    m_networkMetrics[pid].Push(latency);

    // C2 Beaconing heuristic (Coefficient of Variation)
    if (m_networkMetrics[pid].m_n > 20 && m_networkMetrics[pid].CoV() < 0.1) {
        Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_C2_COMMUNICATION, "Potential C2 Beaconing (Low Jitter)", "Target PID: " + std::to_string(pid), pid);
    }
}

void TDSEngine::ScanLOLBins() {
    // Legacy polling method, replaced by Event-Driven evaluation
}

void TDSEngine::ScanProcessBehaviors() {
    // Legacy polling method, replaced by Event-Driven evaluation
}

} // namespace TDS
