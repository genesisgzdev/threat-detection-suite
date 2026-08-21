#include <windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <string>
#include <cstring>
#include <optional>
#include <cstdlib>
#include <utility>
#include "../TDSCommon/TDSCommon.h"
#include "../TDSCommon/TDSEvents.h"
#include "TDSEngine.h"
#include "collectors/EtwCollector.h"

// Threat Detection Suite v5.6.6 - Native Windows Service

SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

#define SERVICE_NAME L"TDSService"

static bool ReadWideString(const BYTE* data, ULONG dataSize, ULONG offset, std::wstring& value) {
    if (offset >= dataSize || (dataSize - offset) < sizeof(wchar_t)) return false;
    const wchar_t* start = reinterpret_cast<const wchar_t*>(data + offset);
    ULONG remaining = (dataSize - offset) / sizeof(wchar_t);
    ULONG length = 0;
    while (length < remaining && start[length] != L'\0') ++length;
    if (length == remaining) return false;
    value.assign(start, length);
    return true;
}

static std::optional<TDS::Event> DecodeKernelEvent(const BYTE* buffer, DWORD bytes) {
    if (!buffer || bytes < sizeof(TDS_EVENT_HEADER)) return std::nullopt;
    const auto* header = reinterpret_cast<const TDS_EVENT_HEADER*>(buffer);
    if (header->DataSize > MAX_EVENT_BUFFER_SIZE - sizeof(TDS_EVENT_HEADER) ||
        bytes < sizeof(TDS_EVENT_HEADER) + header->DataSize) return std::nullopt;

    TDS::Event event{};
    event.Type = header->Type;
    event.Pid = header->ProcessId;
    event.Tid = header->ThreadId;
    event.Timestamp = static_cast<uint64_t>(header->Timestamp.QuadPart);
    const BYTE* data = buffer + sizeof(TDS_EVENT_HEADER);

    switch (header->Type) {
    case TDSEventProcessCreate:
    case TDSEventProcessTerminate: {
        if (header->DataSize < sizeof(TDS_PROCESS_EVENT_DATA)) break;
        const auto* raw = reinterpret_cast<const TDS_PROCESS_EVENT_DATA*>(data);
        TDS::ProcessEvent process{};
        process.Created = raw->Create != FALSE;
        process.ParentPid = raw->ParentProcessId;
        ReadWideString(data, header->DataSize, raw->ImagePathOffset, process.ImagePath);
        ReadWideString(data, header->DataSize, raw->CommandLineOffset, process.CommandLine);
        event.Data = std::move(process);
        break;
    }
    case TDSEventNetworkConnect: {
        if (header->DataSize < sizeof(TDS_NETWORK_EVENT_DATA)) break;
        const auto* raw = reinterpret_cast<const TDS_NETWORK_EVENT_DATA*>(data);
        TDS::NetworkEvent network{};
        network.AddressFamily = static_cast<uint8_t>(raw->AddressFamily);
        network.Protocol = raw->Protocol;
        network.RemotePort = raw->RemotePort;
        network.RemoteAddress = raw->Ipv4Address;
        memcpy(network.Ipv6Address, raw->Ipv6Address, sizeof(network.Ipv6Address));
        event.Data = std::move(network);
        break;
    }
    case TDSEventRemoteThread:
    case TDSEventApcInjection:
    case TDSEventEtwTiApcInjection: {
        if (header->DataSize >= sizeof(TDS_REMOTE_THREAD_DATA)) {
            const auto* raw = reinterpret_cast<const TDS_REMOTE_THREAD_DATA*>(data);
            event.Data = TDS::RemoteThreadEvent{raw->TargetProcessId};
        }
        break;
    }
    default:
        break;
    }
    return event;
}

int wmain(int argc, wchar_t *argv[]) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcherW(ServiceTable) == FALSE) {
        return GetLastError();
    }

    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    g_StatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);

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
    if (hThread == NULL) {
        CloseHandle(g_ServiceStopEvent);
        g_ServiceStopEvent = INVALID_HANDLE_VALUE;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }
    
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    
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

static bool ApplyProtectionPolicy(HANDLE hDevice, const TDS_PROTECTION_POLICY& policy) {
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDevice, IOCTL_TDS_SET_PROTECTION_POLICY,
                           const_cast<TDS_PROTECTION_POLICY*>(&policy), sizeof(policy),
                           NULL, 0, &bytesReturned, NULL) != FALSE;
}

static HANDLE OpenDriverWithPolicy(const TDS_PROTECTION_POLICY& policy) {
    HANDLE hDevice = CreateFileW(L"\\\\.\\TDS_Core_Link", GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    if (!ApplyProtectionPolicy(hDevice, policy)) {
        CloseHandle(hDevice);
        return INVALID_HANDLE_VALUE;
    }
    return hDevice;
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);
    TDS::TDSEngine engine;
    engine.Start();
    TDS::EtwCollector etw([&engine](const TDS::Event& event) { engine.PushEvent(event); });
    etw.Start();

    TDS_PROTECTION_POLICY policy = {};
    policy.Version = 1;
    policy.Size = sizeof(policy);
    policy.Flags = TDS_POLICY_FLAG_PROTECT_SERVICE;
    policy.ObserveOnly = 1;
    policy.AllowProcessTermination = 0;
    policy.AllowNetworkContainment = 0;
    char responseMode[32] = {};
    size_t responseModeSize = 0;
    if (getenv_s(&responseModeSize, responseMode, sizeof(responseMode), "TDS_RESPONSE_MODE") == 0) {
        if (strcmp(responseMode, "contain") == 0) {
            policy.ObserveOnly = 0;
            policy.AllowNetworkContainment = 1;
        } else if (strcmp(responseMode, "terminate") == 0) {
            policy.ObserveOnly = 0;
            policy.AllowNetworkContainment = 1;
            policy.AllowProcessTermination = 1;
        }
    }
    // Opening the driver and applying policy are one operation so reconnects
    // cannot resume event collection with stale or missing protection.
    HANDLE hDevice = OpenDriverWithPolicy(policy);

    BYTE buffer[MAX_EVENT_BUFFER_SIZE];
    DWORD bytesReturned = 0;
    while (WaitForSingleObject(g_ServiceStopEvent, 1000) == WAIT_TIMEOUT) {
        if (hDevice == INVALID_HANDLE_VALUE) {
            hDevice = OpenDriverWithPolicy(policy);
            if (hDevice == INVALID_HANDLE_VALUE) {
                WaitForSingleObject(g_ServiceStopEvent, 1000);
            }
            continue;
        }
        while (DeviceIoControl(hDevice, IOCTL_TDS_GET_NEXT_EVENT, NULL, 0,
                               buffer, sizeof(buffer), &bytesReturned, NULL)) {
            if (auto event = DecodeKernelEvent(buffer, bytesReturned)) engine.PushEvent(*event);
        }
        DWORD error = GetLastError();
        if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }

    if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
    etw.Stop();
    engine.Shutdown();
    return ERROR_SUCCESS;
}
