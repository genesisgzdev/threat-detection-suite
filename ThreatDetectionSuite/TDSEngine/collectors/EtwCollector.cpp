#include "EtwCollector.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <utility>

namespace TDS {
static const GUID Microsoft_Windows_Threat_Intelligence = { 0xf4e1897c, 0xbb5d, 0x5668, { 0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44 } };

EtwCollector::EtwCollector(EventHandler handler) : m_traceHandle(INVALID_PROCESSTRACE_HANDLE), m_sessionHandle(0), m_isRunning(false), m_handler(std::move(handler)) {
    m_sessionName = "TDS_ETW_TI_Session";
}

EtwCollector::~EtwCollector() { Stop(); }

bool EtwCollector::Start() {
    ULONG bufferSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + m_sessionName.length() + 1);
    EVENT_TRACE_PROPERTIES* traceProp = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!traceProp) return false;
    ZeroMemory(traceProp, bufferSize);
    traceProp->Wnode.BufferSize = bufferSize;
    traceProp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    traceProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceA(0, m_sessionName.c_str(), traceProp, EVENT_TRACE_CONTROL_STOP);
    if (StartTraceA(&m_sessionHandle, m_sessionName.c_str(), traceProp) != ERROR_SUCCESS) { free(traceProp); return false; }
    if (EnableTraceEx2(m_sessionHandle, &Microsoft_Windows_Threat_Intelligence, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL) != ERROR_SUCCESS) {
        Stop(); free(traceProp); return false;
    }

    EVENT_TRACE_LOGFILEA logFile = {0};
    logFile.LoggerName = (LPSTR)m_sessionName.c_str();
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;
    logFile.Context = this;

    m_traceHandle = OpenTraceA(&logFile);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) { Stop(); free(traceProp); return false; }

    m_isRunning = true;
    m_traceThread = std::thread([this]() { ProcessTrace(&m_traceHandle, 1, 0, 0); });
    free(traceProp);
    return true;
}

void EtwCollector::Stop() {
    if (m_isRunning || m_sessionHandle != 0 || m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        m_isRunning = false;
        if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(m_traceHandle); m_traceHandle = INVALID_PROCESSTRACE_HANDLE; }
        ULONG bufferSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + m_sessionName.length() + 1);
        EVENT_TRACE_PROPERTIES* traceProp = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
        if (traceProp) {
            ZeroMemory(traceProp, bufferSize); traceProp->Wnode.BufferSize = bufferSize; traceProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceA(m_sessionHandle, m_sessionName.c_str(), traceProp, EVENT_TRACE_CONTROL_STOP);
            free(traceProp);
        }
        m_sessionHandle = 0;
    }
    if (m_traceThread.joinable()) m_traceThread.join();
}

void WINAPI EtwCollector::EventRecordCallback(PEVENT_RECORD pEvent) {
    if (!pEvent || !pEvent->UserContext) return;
    static_cast<EtwCollector*>(pEvent->UserContext)->HandleEvent(pEvent);
}

void EtwCollector::HandleEvent(PEVENT_RECORD pEvent) {
    if (!m_handler || !pEvent) return;
    if (pEvent->EventHeader.EventDescriptor.Id != 5) return;
    Event event{};
    event.Type = TDSEventEtwTiApcInjection;
    event.Pid = pEvent->EventHeader.ProcessId;
    event.Tid = pEvent->EventHeader.ThreadId;
    event.Timestamp = pEvent->EventHeader.TimeStamp.QuadPart;
    event.Data = RemoteThreadEvent{event.Pid};
    m_handler(event);
}
}
