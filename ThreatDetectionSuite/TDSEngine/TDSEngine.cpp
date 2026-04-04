#include "TDSEngine.h"
#include <iostream>
#include <chrono>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <winternl.h>
#include "Logger.h"
#include "detectors/NetworkDetector.h"

namespace TDS {

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

TDSEngine::TDSEngine() {
    m_lolbasBinaries = {
        L"certutil.exe", L"powershell.exe", L"mshta.exe", L"regsvr32.exe", 
        L"rundll32.exe", L"msiexec.exe", L"csc.exe", L"bitsadmin.exe",
        L"wmic.exe", L"schtasks.exe", L"at.exe", L"sc.exe"
    };
    
    m_eventBus = std::make_unique<EventBus>();
    m_contextManager = std::make_unique<ProcessContextManager>();
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
            m_contextManager->HandleEvent(*eventOpt);
            m_correlator->HandleEvent(eventOpt->Pid, eventOpt->Type);
        }
    }
}

void TDSEngine::EvaluateThreat(const Event& event) {
    auto context = m_contextManager->GetContext(event.Pid);
    
    switch (event.Type) {
        case TDSEventProcessCreate: {
            auto data = std::get<ProcessEvent>(event.Data);
            if (IsLolbasBinary(data.ImagePath)) {
                int score = CalculateLOLBinRiskScore(data.CommandLine);
                if (score >= 85) {
                    std::string cmd(data.CommandLine.begin(), data.CommandLine.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_LOLBIN_ABUSE, "Critical LOLBin abuse detected", cmd, event.Pid);
                    m_contextManager->UpdateScore(event.Pid, score);
                } else if (score >= 50) {
                    std::string cmd(data.CommandLine.begin(), data.CommandLine.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_LOLBIN_ABUSE, "Suspicious LOLBin execution", cmd, event.Pid);
                    m_contextManager->UpdateScore(event.Pid, score);
                }
            }
            break;
        }
        case TDSEventRemoteThread: {
            auto data = std::get<RemoteThreadEvent>(event.Data);
            Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_DLL_INJECTION, "Remote thread injection detected", "Target PID: " + std::to_string(data.TargetPid), event.Pid);
            m_contextManager->UpdateScore(data.TargetPid, 50);
            break;
        }
        case TDSEventHandleOp: {
            auto data = std::get<HandleOpEvent>(event.Data);
            if (data.DesiredAccess & PROCESS_VM_READ) {
                Logger::Instance().LogThreat(TDS_SEVERITY_MEDIUM, CAT_CREDENTIAL_THEFT, "Suspicious handle to sensitive process", "Target PID: " + std::to_string(data.TargetPid), event.Pid);
                m_contextManager->UpdateScore(event.Pid, 15);
            }
            break;
        }
        case TDSEventNetworkConnect: {
            auto data = std::get<NetworkEvent>(event.Data);
            NetworkDetector::AnalyzeConnection(event.Pid, data.RemoteAddress, data.RemotePort);
            break;
        }
    }
}

bool TDSEngine::IsLolbasBinary(const std::wstring& path) {
    size_t lastSlash = path.find_last_of(L"\\");
    std::wstring filename = (lastSlash == std::wstring::npos) ? path : path.substr(lastSlash + 1);
    std::wstring lower = filename;
    for (auto& c : lower) c = towlower(c);
    return m_lolbasBinaries.find(lower) != m_lolbasBinaries.end();
}

int TDSEngine::CalculateLOLBinRiskScore(const std::wstring& commandLine) {
    int score = 0;
    std::wstring lower = commandLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    if (lower.find(L"-encodedcommand") != std::wstring::npos) score += 30;
    else if (lower.find(L"-encode") != std::wstring::npos || lower.find(L"-enc ") != std::wstring::npos) score += 25;

    if (lower.find(L"iex") != std::wstring::npos || lower.find(L"invoke-expression") != std::wstring::npos) score += 40;
    if (lower.find(L"downloadstring") != std::wstring::npos || lower.find(L"downloadfile") != std::wstring::npos) score += 40;
    if (lower.find(L"http") != std::wstring::npos) score += 15;

    if (lower.find(L"regsvr32") != std::wstring::npos && lower.find(L"/i:http") != std::wstring::npos) score += 85;

    if (lower.find(L"-noprofile") != std::wstring::npos) score += 10;
    if (lower.find(L"hidden") != std::wstring::npos) score += 20;

    return min(score, 100);
}

void TDSEngine::ScanLOLBins() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            std::wstring exeName = pe32.szExeFile;
            std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);
            
            if (exeName == L"certutil.exe" || exeName == L"powershell.exe" || exeName == L"wmic.exe" || exeName == L"regsvr32.exe") {
                std::string sExe(exeName.begin(), exeName.end());
                Logger::Instance().LogThreat(TDS_SEVERITY_INFO, CAT_LOLBIN_ABUSE, "LOLBin instance found in memory snapshot (command line handled via kernel)", sExe, pe32.th32ProcessID);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

void TDSEngine::ScanProcessBehaviors() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            std::wstring exeName = pe32.szExeFile;
            std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);

            if (exeName.find(L"svchost") != std::wstring::npos || exeName.find(L"audio") != std::wstring::npos) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                if (hProc) {
                    DWORD needed = 0;
                    EnumProcessModules(hProc, NULL, 0, &needed);
                    int dll_count = needed / sizeof(HMODULE);

                    int threshold = (exeName.find(L"svchost") != std::wstring::npos) ? 150 : 80;
                    if (dll_count > threshold) {
                        std::string sExe(exeName.begin(), exeName.end());
                        Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_DLL_INJECTION, "Abnormally high DLL count in core process", sExe, pe32.th32ProcessID);
                    }
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

void TDSEngine::UpdateNetworkStats(DWORD pid, double latency) {
    std::lock_guard<std::mutex> lock(m_engineMutex);
    m_networkMetrics[pid].Push(latency);
    if (m_networkMetrics[pid].Variance() < 0.05 && m_networkMetrics[pid].m_n > 5) {
        Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_C2_COMMUNICATION, "Network beaconing patterns detected", "Low Variance", pid);
        m_contextManager->UpdateScore(pid, 30);
    }
}

} // namespace TDS
