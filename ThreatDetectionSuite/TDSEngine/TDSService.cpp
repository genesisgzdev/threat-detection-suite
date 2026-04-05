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
// Threat Detection Suite v4.3.5 - Native Windows Service
// Professional Lifecycle Management & Watchdog
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

    // Report SERVICE_START_PENDING
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    // Start the worker thread
    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    
    // Report SERVICE_RUNNING
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

class DriverInterface {
    HANDLE m_hDevice;
    OVERLAPPED m_ov;

public:
    DriverInterface() : m_hDevice(INVALID_HANDLE_VALUE) {
        RtlZeroMemory(&m_ov, sizeof(m_ov));
        m_ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    }

    bool Connect() {
        m_hDevice = CreateFileW(L"\\\\.\\ThreatDetectionSuite", GENERIC_READ | GENERIC_WRITE, 
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (m_hDevice == INVALID_HANDLE_VALUE) return false;

        DWORD bytes;
        return DeviceIoControl(m_hDevice, IOCTL_TDS_SET_PROTECTION_POLICY, NULL, 0, NULL, 0, &bytes, NULL);
    }

    void ListenForEvents(TDS::TDSEngine& engine) {
        BYTE buffer[MAX_EVENT_BUFFER_SIZE];
        DWORD bytesReturned;

        while (WaitForSingleObject(g_ServiceStopEvent, 0) == WAIT_TIMEOUT) {
            ResetEvent(m_ov.hEvent);
            BOOL success = DeviceIoControl(m_hDevice, IOCTL_TDS_GET_NEXT_EVENT, 
                                           NULL, 0, buffer, sizeof(buffer), 
                                           &bytesReturned, &m_ov);

            if (!success && GetLastError() == ERROR_IO_PENDING) {
                HANDLE waitHandles[] = { m_ov.hEvent, g_ServiceStopEvent };
                DWORD wait = WaitForMultipleObjects(2, waitHandles, FALSE, 2000);
                if (wait == WAIT_OBJECT_0) {
                    if (GetOverlappedResult(m_hDevice, &m_ov, &bytesReturned, FALSE)) {
                        NormalizeAndPush(buffer, bytesReturned, engine);
                    }
                }
            } else if (success) {
                NormalizeAndPush(buffer, bytesReturned, engine);
            } else {
                Sleep(100);
            }
        }
    }

    void NormalizeAndPush(BYTE* buffer, DWORD size, TDS::TDSEngine& engine) {
        if (size < sizeof(TDS_EVENT_HEADER)) return;
        PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)buffer;
        
        TDS::Event unified;
        unified.Timestamp = header->Timestamp;
        unified.Pid = header->ProcessId;
        unified.Tid = header->ThreadId;
        unified.Type = header->Type;

        switch (header->Type) {
            case TDSEventProcessCreate: {
                PTDS_PROCESS_EVENT_DATA pData = (PTDS_PROCESS_EVENT_DATA)(header + 1);
                TDS::ProcessEvent ev;
                ev.ParentPid = pData->ParentProcessId;
                ev.Created = (pData->Create != 0);
                if (pData->ImagePathOffset > 0) ev.ImagePath = std::wstring((WCHAR*)((BYTE*)header + pData->ImagePathOffset));
                if (pData->CommandLineOffset > 0) ev.CommandLine = std::wstring((WCHAR*)((BYTE*)header + pData->CommandLineOffset));
                unified.Data = ev;
                break;
            }
            case TDSEventImageLoad: {
                PTDS_IMAGE_LOAD_DATA iData = (PTDS_IMAGE_LOAD_DATA)(header + 1);
                TDS::ImageLoadEvent ev;
                ev.LoadAddress = iData->LoadAddress;
                ev.ImageSize = iData->ImageSize;
                if (iData->ImagePathOffset > 0) ev.ImagePath = std::wstring((WCHAR*)((BYTE*)header + iData->ImagePathOffset));
                unified.Data = ev;
                break;
            }
            case TDSEventRemoteThread: {
                PTDS_REMOTE_THREAD_DATA tData = (PTDS_REMOTE_THREAD_DATA)(header + 1);
                TDS::RemoteThreadEvent ev;
                ev.TargetPid = tData->TargetProcessId;
                unified.Data = ev;
                break;
            }
            case TDSEventNetworkConnect: {
                PTDS_NETWORK_EVENT_DATA nData = (PTDS_NETWORK_EVENT_DATA)(header + 1);
                TDS::NetworkEvent ev;
                ev.RemoteAddress = nData->Ipv4Address;
                ev.RemotePort = nData->RemotePort;
                ev.Protocol = nData->Protocol;
                unified.Data = ev;
                break;
            }
        }
        engine.PushEvent(unified);
    }

    ~DriverInterface() {
        if (m_hDevice != INVALID_HANDLE_VALUE) CloseHandle(m_hDevice);
        if (m_ov.hEvent) CloseHandle(m_ov.hEvent);
    }
};

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    TDS::TDSEngine engine;
    engine.Start();

    DriverInterface driver;
    TDS::EtwCollector etw(L"TDSTrace");

    static const GUID TI_PROVIDER_GUID = { 0xF4E1897C, 0xBB5D, 0x566A, { 0x91, 0x79, 0x06, 0xEE, 0x52, 0x8C, 0x10, 0xFF } };

    etw.SetEventCallback([&](PEVENT_RECORD pEvent) {
        if (IsEqualGUID(pEvent->EventHeader.ProviderId, TI_PROVIDER_GUID)) {
            TDS::Event unified;
            unified.Timestamp = pEvent->EventHeader.TimeStamp.QuadPart;
            unified.Pid = pEvent->EventHeader.ProcessId;
            unified.Tid = pEvent->EventHeader.ThreadId;
            unified.Type = TDSEventHandleOp;
            TDS::HandleOpEvent hOp;
            hOp.TargetPid = 0;
            hOp.DesiredAccess = 0;
            unified.Data = hOp;
            engine.PushEvent(unified);
        }
    });

    std::vector<TDS::EtwProvider> providers = {
        { TI_PROVIDER_GUID, TRACE_LEVEL_VERBOSE, 0, 0 }
    };

    etw.Start(providers);
    if (driver.Connect()) {
        driver.ListenForEvents(engine);
    }

    etw.Stop();
    engine.Shutdown();

    return ERROR_SUCCESS;
}
