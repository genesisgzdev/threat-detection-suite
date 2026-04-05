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
            m_contextManager->HandleEvent(*eventOpt);
            m_correlator->HandleEvent(eventOpt->Pid, eventOpt->Type);
        }
    }
}

void TDSEngine::EvaluateThreat(const Event& event) {
    auto context = m_contextManager->GetContext(event.Pid);
    
    switch (event.Type) {
        case TDSEventProcessCreate: {
            if (auto data = std::get_if<ProcessEvent>(&event.Data)) {
                if (IsLolbasBinary(data->ImagePath)) {
                    int score = CalculateLOLBinRiskScore(data->CommandLine);
                    if (score >= 85) {
                        std::string cmd(data->CommandLine.begin(), data->CommandLine.end());
                        Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_LOLBIN_ABUSE, "Critical LOLBin abuse detected", cmd, event.Pid);
                        m_contextManager->UpdateScore(event.Pid, score);
                        
                        IPSManager::ContainProcess(event.Pid);
                        IPSManager::TerminateMaliciousProcess(event.Pid);
                    } else if (score >= 50) {
                        std::string cmd(data->CommandLine.begin(), data->CommandLine.end());
                        Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_LOLBIN_ABUSE, "Suspicious LOLBin execution", cmd, event.Pid);
                        m_contextManager->UpdateScore(event.Pid, score);
                    }
                }
            }
            break;
        }
        case TDSEventRemoteThread: {
            if (auto data = std::get_if<RemoteThreadEvent>(&event.Data)) {
                Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_DLL_INJECTION, "Remote thread injection detected", "Target PID: " + std::to_string(data->TargetPid), event.Pid);
                m_contextManager->UpdateScore(data->TargetPid, 50);
                
                IPSManager::ContainProcess(event.Pid);
                IPSManager::TerminateMaliciousProcess(event.Pid);
            }
            break;
        }
        case TDSEventHandleOp: {
            if (auto data = std::get_if<HandleOpEvent>(&event.Data)) {
                if (data->DesiredAccess & PROCESS_VM_READ) {
                    Logger::Instance().LogThreat(TDS_SEVERITY_MEDIUM, CAT_CREDENTIAL_THEFT, "Suspicious handle to sensitive process", "Target PID: " + std::to_string(data->TargetPid), event.Pid);
                    m_contextManager->UpdateScore(event.Pid, 15);
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
            
            // \VarFileInfo\Translation to get the language and code page
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
    std::wstring lower = commandLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    if (lower.find(L"-encodedcommand") != std::wstring::npos) score += 30;
    else if (lower.find(L"-encode") != std::wstring::npos || lower.find(L"-enc ") != std::wstring::npos) score += 25;

    if (lower.find(L"iex") != std::wstring::npos || lower.find(L"invoke-expression") != std::wstring::npos) score += 40;
    if (lower.find(L"downloadstring") != std::wstring::npos || lower.find(L"downloadfile") != std::wstring::npos) score += 40;
    if (lower.find(L"http") != std::wstring::npos) score += 15;

    if (lower.find(L"regsvr32") != std::wstring::npos && (lower.find(L"/i:http") != std::wstring::npos || lower.find(L"/i:") != std::wstring::npos)) score += 85;

    if (lower.find(L"-noprofile") != std::wstring::npos) score += 10;
    if (lower.find(L"hidden") != std::wstring::npos) score += 20;

    // Inspect deobfuscated payload using AMSI
    HAMSICONTEXT amsiContext;
    if (SUCCEEDED(AmsiInitialize(L"TDSEngine", &amsiContext))) {
        AMSI_RESULT result;
        if (SUCCEEDED(AmsiScanString(amsiContext, commandLine.c_str(), L"LOLBinCmdline", NULL, &result))) {
            if (AmsiResultIsMalware(result)) {
                score += 85; 
            }
        }
        AmsiUninitialize(amsiContext);
    }

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
                Logger::Instance().LogThreat(TDS_SEVERITY_INFO, CAT_LOLBIN_ABUSE, "LOLBin instance found in snapshot", sExe, pe32.th32ProcessID);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

void TDSEngine::ScanProcessBehaviors() {
    std::unordered_set<DWORD> snapshotPids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                snapshotPids.insert(pe32.th32ProcessID);
                
                std::wstring exeName = pe32.szExeFile;
                std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);

                if (exeName.find(L"svchost") != std::wstring::npos || 
                    exeName.find(L"audio") != std::wstring::npos ||
                    exeName.find(L"explorer") != std::wstring::npos ||
                    exeName.find(L"lsass") != std::wstring::npos ||
                    exeName.find(L"spoolsv") != std::wstring::npos ||
                    exeName.find(L"winlogon") != std::wstring::npos) {
                    
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

    // 2. Query SystemProcessInformation for cross-check (DKOM detection)
    static pNtQuerySystemInformation NtQuerySysInfo = (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (NtQuerySysInfo) {
        ULONG size = 0;
        NtQuerySysInfo(SystemProcessInformation, NULL, 0, &size);
        std::vector<BYTE> buffer(size);
        if (NT_SUCCESS(NtQuerySysInfo(SystemProcessInformation, buffer.data(), size, NULL))) {
            PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer.data();
            while (true) {
                DWORD pid = (DWORD)(ULONG_PTR)pInfo->UniqueProcessId;
                if (pid != 0 && snapshotPids.find(pid) == snapshotPids.end()) {
                    std::wstring name = pInfo->ImageName.Buffer ? std::wstring(pInfo->ImageName.Buffer, pInfo->ImageName.Length / sizeof(WCHAR)) : L"Unknown";
                    std::string sName(name.begin(), name.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_DKOM_DETECTION, "Process hidden from standard APIs (DKOM)", sName, pid);
                }
                if (pInfo->NextEntryOffset == 0) break;
                pInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pInfo + pInfo->NextEntryOffset);
            }
        }
    }
}

void TDSEngine::UpdateNetworkStats(DWORD pid, double latency) {
    std::lock_guard<std::mutex> lock(m_engineMutex);
    m_networkMetrics[pid].Push(latency);
    if (m_networkMetrics[pid].CoV() < 0.3 && m_networkMetrics[pid].m_n > 5) {
        Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_C2_COMMUNICATION, "Network beaconing patterns detected", "Low Variance", pid);
        m_contextManager->UpdateScore(pid, 30);
    }
}

} // namespace TDS
