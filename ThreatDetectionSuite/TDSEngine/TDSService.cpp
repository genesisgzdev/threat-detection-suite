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
#include "../TDSScanner/MemoryScanner.h"

std::atomic<bool> g_Running{ false };

SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

static const GUID TI_PROVIDER_GUID = { 0xF4E1897C, 0xBB5D, 0x566A, { 0x91, 0x79, 0x06, 0xEE, 0x52, 0x8C, 0x10, 0xFF } };
static const GUID DNS_PROVIDER_GUID = { 0x22FB2AD3, 0xE18E, 0x418B, { 0x82, 0xC7, 0x47, 0x21, 0x19, 0x50, 0xE8, 0xC0 } };
static const GUID FILE_PROVIDER_GUID = { 0xEDD08927, 0x9CC4, 0x4E65, { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };

class DriverInterface {
    HANDLE m_hDevice;
    OVERLAPPED m_ov;

public:
    DriverInterface() : m_hDevice(INVALID_HANDLE_VALUE) {
        RtlZeroMemory(&m_ov, sizeof(m_ov));
        m_ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    }

    bool Connect() {
        m_hDevice = CreateFileW(L"\\\\.\\ThreatDetectionKernel", GENERIC_READ | GENERIC_WRITE, 
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (m_hDevice == INVALID_HANDLE_VALUE) return false;

        DWORD bytes;
        return DeviceIoControl(m_hDevice, IOCTL_TDS_SET_PROTECTION_POLICY, NULL, 0, NULL, 0, &bytes, NULL);
    }

    void ListenForEvents(TDS::TDSEngine& engine) {
        BYTE buffer[MAX_EVENT_BUFFER_SIZE];
        DWORD bytesReturned;

        while (g_Running) {
            ResetEvent(m_ov.hEvent);
            BOOL success = DeviceIoControl(m_hDevice, IOCTL_TDS_GET_NEXT_EVENT, 
                                           NULL, 0, buffer, sizeof(buffer), 
                                           &bytesReturned, &m_ov);

            if (!success && GetLastError() == ERROR_IO_PENDING) {
                if (WaitForSingleObject(m_ov.hEvent, 2000) == WAIT_OBJECT_0) {
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
                PTDS_PROCESS_EVENT_DATA pData = (PTDS_PROCESS_EVENT_DATA)((BYTE*)header + sizeof(TDS_EVENT_HEADER));
                TDS::ProcessEvent ev;
                ev.ParentPid = pData->ParentProcessId;
                ev.Created = (pData->Create != 0);
                if (pData->ImagePathOffset > 0) ev.ImagePath = std::wstring((WCHAR*)((BYTE*)pData + pData->ImagePathOffset));
                if (pData->CommandLineOffset > 0) ev.CommandLine = std::wstring((WCHAR*)((BYTE*)pData + pData->CommandLineOffset));
                unified.Data = ev;
                break;
            }
            case TDSEventImageLoad: {
                PTDS_IMAGE_LOAD_DATA iData = (PTDS_IMAGE_LOAD_DATA)((BYTE*)header + sizeof(TDS_EVENT_HEADER));
                TDS::ImageLoadEvent ev;
                ev.LoadAddress = iData->LoadAddress;
                ev.ImageSize = iData->ImageSize;
                if (iData->ImagePathOffset > 0) ev.ImagePath = std::wstring((WCHAR*)((BYTE*)iData + iData->ImagePathOffset));
                unified.Data = ev;
                break;
            }
            case TDSEventRemoteThread: {
                PTDS_REMOTE_THREAD_DATA tData = (PTDS_REMOTE_THREAD_DATA)((BYTE*)header + sizeof(TDS_EVENT_HEADER));
                TDS::RemoteThreadEvent ev;
                ev.TargetPid = tData->TargetProcessId;
                unified.Data = ev;
                break;
            }
            case TDSEventNetworkConnect: {
                PTDS_NETWORK_EVENT_DATA nData = (PTDS_NETWORK_EVENT_DATA)((BYTE*)header + sizeof(TDS_EVENT_HEADER));
                TDS::NetworkEvent ev;
                // Use union IPv4 for backward compatibility with existing engine
                ev.RemoteAddress = nData->Ipv4Address;
                ev.RemotePort = nData->RemotePort;
                ev.Protocol = nData->Protocol;
                unified.Data = ev;
                break;
            }
            case TDSEventHandleOp: {
                PTDS_HANDLE_OP_DATA hData = (PTDS_HANDLE_OP_DATA)((BYTE*)header + sizeof(TDS_EVENT_HEADER));
                TDS::HandleOpEvent ev;
                ev.TargetPid = hData->TargetProcessId;
                ev.DesiredAccess = hData->DesiredAccess;
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

int wmain(int argc, wchar_t* argv[]) {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { (LPWSTR)L"TDSService", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcherW(ServiceTable) == FALSE) {
        return GetLastError();
    }

    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerW(L"TDSService", ServiceCtrlHandler);

    if (g_StatusHandle == NULL) {
        return;
    }

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        return;
    }

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        return;
    }

    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    CloseHandle(g_ServiceStopEvent);

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwCheckPoint = 0;
            g_ServiceStatus.dwWaitHint = 5000;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

            g_Running = false;
            SetEvent(g_ServiceStopEvent);
            break;
        default:
            break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    g_Running = true;

    // Initialize YARA Memory Engine
    TDS::MemoryScanner::InitializeYara("C:\\TDS\\rules\\apt_payloads.yar");

    TDS::TDSEngine engine;
    engine.Start();

    DriverInterface driver;
    TDS::EtwCollector etw(L"TDSTrace");

    etw.SetEventCallback([&](PEVENT_RECORD pEvent) {
        TDS::Event unified;
        unified.Timestamp = pEvent->EventHeader.TimeStamp.QuadPart;
        unified.Pid = pEvent->EventHeader.ProcessId;
        unified.Tid = pEvent->EventHeader.ThreadId;

        if (IsEqualGUID(pEvent->EventHeader.ProviderId, TI_PROVIDER_GUID)) {
            unified.Type = TDSEventHandleOp; 
            TDS::HandleOpEvent hOp;
            hOp.TargetPid = 0;
            hOp.DesiredAccess = 0;
            unified.Data = hOp;
            engine.PushEvent(unified);
        } else if (IsEqualGUID(pEvent->EventHeader.ProviderId, DNS_PROVIDER_GUID)) {
            // Future DNS event logic
        }
    });

    std::vector<TDS::EtwProvider> providers = {
        { TI_PROVIDER_GUID, TRACE_LEVEL_VERBOSE, 0, 0 },
        { DNS_PROVIDER_GUID, TRACE_LEVEL_VERBOSE, 0, 0 },
        { FILE_PROVIDER_GUID, TRACE_LEVEL_VERBOSE, 0, 0 }
    };

    if (!etw.Start(providers)) {
        // ETW start failed
    }

    if (!driver.Connect()) {
        // Driver connect failed
    }

    std::thread driverThread([&]() {
        driver.ListenForEvents(engine);
    });

    // Implement a watchdog / self-healing loop
    while (g_Running) {
        if (WaitForSingleObject(g_ServiceStopEvent, 1000) == WAIT_OBJECT_0) {
            break;
        }
    }

    etw.Stop();
    engine.Shutdown();
    if (driverThread.joinable()) driverThread.join();
    TDS::MemoryScanner::ShutdownYara();

    return ERROR_SUCCESS;
}
