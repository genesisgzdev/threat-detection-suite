#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <iostream>
#include <guiddef.h>

// Provider GUIDs
// {F4E1897C-BB5D-566A-9179-06EE528C10FF} Microsoft-Windows-Threat-Intelligence
static const GUID TI_PROVIDER_GUID = { 0xF4E1897C, 0xBB5D, 0x566A, { 0x91, 0x79, 0x06, 0xEE, 0x52, 0x8C, 0x10, 0xFF } };

class EtwCollector {
    TRACEHANDLE hTrace;
    EVENT_TRACE_LOG_PROPERTIES* pProperties;
    HANDLE hThread;

public:
    static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
        // High-level event parsing
        if (IsEqualGUID(pEvent->EventHeader.ProviderId, TI_PROVIDER_GUID)) {
            // Process Threat-Intelligence events (VirtualAlloc, etc.)
            // std::cout << "[ETW] Threat Intel Event: " << pEvent->EventHeader.EventDescriptor.Id << std::endl;
        }
    }

    bool Start() {
        ULONG bufferSize = sizeof(EVENT_TRACE_LOG_PROPERTIES) + sizeof(L"TDSTrace") + 2;
        pProperties = (EVENT_TRACE_LOG_PROPERTIES*)malloc(bufferSize);
        memset(pProperties, 0, bufferSize);
        pProperties->Wnode.BufferSize = bufferSize;
        pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pProperties->Wnode.ClientContext = 1;
        pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_LOG_PROPERTIES);

        ControlTraceW(NULL, L"TDSTrace", pProperties, EVENT_TRACE_CONTROL_STOP); // Stop previous if any
        ULONG status = StartTraceW(&hTrace, L"TDSTrace", pProperties);
        if (status != ERROR_SUCCESS) return false;

        status = EnableTraceEx2(hTrace, &TI_PROVIDER_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, 
                                 TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
        
        // Start processing thread...
        return true;
    }

    void Stop() {
        ControlTraceW(hTrace, L"TDSTrace", pProperties, EVENT_TRACE_CONTROL_STOP);
        free(pProperties);
    }
};
