#include "EtwCollector.h"
#include <iostream>
#include <system_error>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")

namespace TDS {

EtwCollector* EtwCollector::s_instance = nullptr;

EtwCollector::EtwCollector(const std::wstring& sessionName) 
    : m_sessionName(sessionName) {
    s_instance = this;
}

EtwCollector::~EtwCollector() {
    Stop();
    if (s_instance == this) s_instance = nullptr;
}

void EtwCollector::SetEventCallback(EventCallback cb) {
    m_callback = std::move(cb);
}

bool EtwCollector::Start(const std::vector<EtwProvider>& providers) {
    if (m_active) return true;

    // Verify necessary privileges for ETW
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_SYSTEM_PROFILE_NAME, &luid)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                std::cerr << "[!] Warning: Failed to enable SE_SYSTEM_PROFILE_NAME. ETW might fail." << std::endl;
            }
        }
        CloseHandle(hToken);
    }

    ULONG bufferSize = sizeof(EVENT_TRACE_LOG_PROPERTIES) + (m_sessionName.length() + 1) * sizeof(WCHAR) + 1024;
    EVENT_TRACE_LOG_PROPERTIES* pProperties = (EVENT_TRACE_LOG_PROPERTIES*)malloc(bufferSize);
    if (!pProperties) return false;

    RtlZeroMemory(pProperties, bufferSize);
    pProperties->Wnode.BufferSize = bufferSize;
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProperties->Wnode.ClientContext = 1; // QPC
    pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_LOG_PROPERTIES);

    // Stop existing session if any
    ControlTraceW(0, m_sessionName.c_str(), pProperties, EVENT_TRACE_CONTROL_STOP);

    ULONG status = StartTraceW(&m_hSession, m_sessionName.c_str(), pProperties);
    if (status != ERROR_SUCCESS) {
        free(pProperties);
        return false;
    }

    for (const auto& prov : providers) {
        EnableTraceEx2(m_hSession, &prov.Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, 
                       prov.Level, prov.MatchAnyKeyword, prov.MatchAllKeyword, 0, NULL);
    }

    EVENT_TRACE_LOGFILEW logFile = {0};
    logFile.LoggerName = (LPWSTR)m_sessionName.c_str();
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;

    m_hTrace = OpenTraceW(&logFile);
    if (m_hTrace == INVALID_PROCESSTRACE_HANDLE) {
        free(pProperties);
        Stop();
        return false;
    }

    m_active = true;
    m_workerThread = std::thread(&EtwCollector::ProcessLoop, this);
    
    free(pProperties);
    return true;
}

void EtwCollector::Stop() {
    if (!m_active) return;
    m_active = false;

    if (m_hSession) {
        ULONG bufferSize = sizeof(EVENT_TRACE_LOG_PROPERTIES) + (m_sessionName.length() + 1) * sizeof(WCHAR);
        EVENT_TRACE_LOG_PROPERTIES* pProperties = (EVENT_TRACE_LOG_PROPERTIES*)malloc(bufferSize);
        if (pProperties) {
            RtlZeroMemory(pProperties, bufferSize);
            pProperties->Wnode.BufferSize = bufferSize;
            pProperties->Wnode.Guid = {0};
            pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_LOG_PROPERTIES);
            ControlTraceW(m_hSession, m_sessionName.c_str(), pProperties, EVENT_TRACE_CONTROL_STOP);
            free(pProperties);
        }
        m_hSession = 0;
    }

    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }

    if (m_hTrace) {
        CloseTrace(m_hTrace);
        m_hTrace = 0;
    }
}

void EtwCollector::ProcessLoop() {
    ULONG status = ProcessTrace(&m_hTrace, 1, 0, 0);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        std::cerr << "[-] ProcessTrace failed: " << status << std::endl;
    }
}

void WINAPI EtwCollector::EventRecordCallback(PEVENT_RECORD pEvent) {
    if (s_instance && s_instance->m_callback) {
        // TdhGetEventInformation implementation to parse payload
        DWORD bufferSize = 0;
        DWORD status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (pInfo) {
                status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize);
                if (status == ERROR_SUCCESS) {
                    // Robust parsing skeleton: Properties can be read here via TdhFormatProperty
                    // and pInfo->TopLevelPropertyCount. 
                }
                free(pInfo);
            }
        }
        
        s_instance->m_callback(pEvent);
    }
}

} // namespace TDS
