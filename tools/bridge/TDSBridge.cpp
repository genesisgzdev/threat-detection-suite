#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>
#include <memory>
#include <string>
#include <iostream>
#include <iomanip>
#include <mutex>

// Common Headers
#include "../../ThreatDetectionSuite/TDSCommon/TDSCommon.h"
#include "../../ThreatDetectionSuite/TDSScanner/MemoryScanner.h"
#include "../../ThreatDetectionSuite/TDSEngine/detectors/RegistryDetector.h"
#include "../../ThreatDetectionSuite/TDSEngine/detectors/NetworkDetector.h"
#include "../../ThreatDetectionSuite/TDSEngine/detectors/PersistenceDetector.h"
#include "../../ThreatDetectionSuite/TDSEngine/TDSEngine.h"

#pragma comment(lib, "advapi32.lib")

#define TDS_DRIVER_DEVICE_NAME "\\\\.\\ThreatDetectionKernel"

static std::atomic<bool> global_monitoring_active{true};

class TDSBridge {
public:
    TDSBridge() : m_hDevice(INVALID_HANDLE_VALUE) {}
    ~TDSBridge() { Disconnect(); }

    bool Connect() {
        m_hDevice = CreateFileA(TDS_DRIVER_DEVICE_NAME,
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (m_hDevice == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            if (err == ERROR_SHARING_VIOLATION) {
                std::cerr << "[!] Sharing violation: Another service instance is already connected to the driver." << std::endl;
            } else {
                std::cerr << "[!] Failed to connect to ThreatDetectionKernel (Error: " << err << ")" << std::endl;
            }
            return false;
        }
        std::cout << "[+] Connected to TDS Kernel Driver" << std::endl;
        return true;
    }

    void Disconnect() {
        if (m_hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
        }
    }

    void ProcessEvents() {
        std::cout << "[*] Monitoring real-time system events..." << std::endl;
        
        BYTE buffer[MAX_EVENT_BUFFER_SIZE];
        DWORD bytesReturned;

        while (global_monitoring_active) {
            if (DeviceIoControl(m_hDevice, IOCTL_TDS_GET_NEXT_EVENT, 
                                NULL, 0, buffer, sizeof(buffer), 
                                &bytesReturned, NULL)) {
                
                PTDS_EVENT_HEADER header = (PTDS_EVENT_HEADER)buffer;
                DisplayEvent(header);
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_NO_MORE_ITEMS || err == ERROR_IO_INCOMPLETE || err == WAIT_TIMEOUT) {
                    Sleep(100);
                    continue;
                }
                
                if (err == ERROR_INVALID_HANDLE || err == ERROR_DEVICE_REMOVED || err == ERROR_GEN_FAILURE) {
                    std::cerr << "[!] Critical communication failure: " << err << std::endl;
                    break;
                }
                Sleep(100);
            }
        }
    }

private:
    HANDLE m_hDevice;

    void DisplayEvent(PTDS_EVENT_HEADER header) {
        const char* typeStr = "UNKNOWN";
        switch (header->Type) {
            case TDSEventProcessCreate:    typeStr = "PROC_CREATE"; break;
            case TDSEventProcessTerminate: typeStr = "PROC_TERM"; break;
            case TDSEventThreadCreate:     typeStr = "THREAD_CREATE"; break;
            case TDSEventImageLoad:        typeStr = "IMAGE_LOAD"; break;
            case TDSEventRegistryOp:       typeStr = "REGISTRY_OP"; break;
            case TDSEventFileOp:           typeStr = "FILE_OP"; break;
            case TDSEventHandleOp:         typeStr = "HANDLE_OP"; break;
            case TDSEventRemoteThread:     typeStr = "REMOTE_THREAD"; break;
            case TDSEventNetworkConnect:   typeStr = "NET_CONNECT"; break;
        }

        printf("[%12s] PID: %6u TID: %6u ", typeStr, header->ProcessId, header->ThreadId);

        if (header->Type == TDSEventProcessCreate) {
            PTDS_PROCESS_EVENT_DATA ev = (PTDS_PROCESS_EVENT_DATA)((BYTE*)header + sizeof(TDS_EVENT_HEADER));
            if (ev->ImagePathOffset) {
                wprintf(L"Path: %s ", (WCHAR*)((BYTE*)ev + ev->ImagePathOffset));
            }
        } else if (header->Type == TDSEventImageLoad) {
            PTDS_IMAGE_LOAD_DATA ev = (PTDS_IMAGE_LOAD_DATA)((BYTE*)header + sizeof(TDS_EVENT_HEADER));
            if (ev->ImagePathOffset) {
                wprintf(L"Module: %s ", (WCHAR*)((BYTE*)ev + ev->ImagePathOffset));
            }
        }
        printf("\n");
    }
};

BOOL RemediateFileQuarantine(LPCWSTR filePath) {
    WCHAR quarantinePath[MAX_PATH];
    swprintf_s(quarantinePath, L"%s.QUARANTINE", filePath);

    if (MoveFileExW(filePath, quarantinePath, MOVEFILE_REPLACE_EXISTING)) {
        return TRUE;
    }

    DWORD err = GetLastError();
    if (err == ERROR_SHARING_VIOLATION || err == ERROR_ACCESS_DENIED) {
        return MoveFileExW(filePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    return FALSE;
}

void RunUserlandScans() {
    std::cout << "\n[*] Executing behavioral analysis..." << std::endl;
    
    TDS::MemoryScanner::ScanAllProcesses();
    TDS::RegistryDetector::ScanAutoRunKeys();
    // Network connections handled via WFP Kernel Event pipeline now
    
    TDS::PersistenceDetector persistence;
    persistence.ScanWmiSubscriptions();
    persistence.ScanScheduledTasks();
    persistence.ScanTempPersistence();

    TDS::TDSEngine::ScanLOLBins();
    TDS::TDSEngine::ScanProcessBehaviors();

    std::cout << "[+] Behavioral verification phase completed." << std::endl;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        std::cout << "\n[!] Interruption signal received. Shutting down TDS Bridge safely to prevent Kernel IRP leaks..." << std::endl;
        global_monitoring_active = false;
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char* argv[]) {
    std::cout << "TDS Integration Bridge" << std::endl;
    std::cout << "----------------------" << std::endl;

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    TDSBridge bridge;
    bool connected = bridge.Connect();

    RunUserlandScans();

    if (connected && argc > 1 && strcmp(argv[1], "--monitor") == 0) {
        bridge.ProcessEvents();
    } else if (connected) {
        std::cout << "\n[INFO] Use '--monitor' flag to subscribe to real-time kernel events." << std::endl;
    }

    return 0;
}
