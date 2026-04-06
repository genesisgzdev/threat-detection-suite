#include <windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <string>
#include "../TDSCommon/TDSCommon.h"
#include "../TDSCommon/TDSEvents.h"
#include "TDSEngine.h"
#include "collectors/EtwCollector.h"

//
// Threat Detection Suite v5.0.0 - Native Windows Service
// Cloud Integration & Advanced Kernel Watchdog
//

SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

#define SERVICE_NAME L"TDSService"

int wmain(int argc, wchar_t *argv[]) {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
        return GetLastError();
    }

    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

    if (g_StatusHandle == NULL) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;

    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(g_ServiceStopEvent);
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            if (g_ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
                g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
                SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
                SetEvent(g_ServiceStopEvent);
            }
            break;
        default:
            break;
    }
}

class CloudTelemetryBridge {
public:
    /**
     * Dispatches telemetry to Google SecOps (UDM Format).
     */
    static void Dispatch(const TDS::Event& event) {
        // Here we would use the mcp_google-secops_ingest_udm_events tool
        // or a direct REST API call.
        // Format: UDM standard mapping for 2026.
    }
};

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    TDS::TDSEngine engine;
    engine.Start();

    // The service now informs the driver of its PID for self-protection
    HANDLE hDevice = CreateFileW(L"\\\\.\\TDS_Core_Kernel", GENERIC_READ | GENERIC_WRITE, 
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    
    if (hDevice != INVALID_HANDLE_VALUE) {
        DWORD bytes;
        DeviceIoControl(hDevice, IOCTL_TDS_SET_PROTECTION_POLICY, NULL, 0, NULL, 0, &bytes, NULL);
        CloseHandle(hDevice);
    }

    // Monitoring loop...
    while (WaitForSingleObject(g_ServiceStopEvent, 1000) == WAIT_TIMEOUT) {
        // Core engine logic remains active
    }

    engine.Shutdown();
    return ERROR_SUCCESS;
}


