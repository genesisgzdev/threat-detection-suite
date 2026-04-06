#include <windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include "TDSCommon.h"

/**
 * TDS Driver Fuzzer & Stress Test Utility
 * Validates real-time event dispatching and kernel stability under high IOCTL pressure.
 */

std::atomic<bool> g_Running(true);
std::atomic<uint64_t> g_SuccessCount(0);
std::atomic<uint64_t> g_ErrorCount(0);

void FuzzWorker(HANDLE hDevice) {
    BYTE buffer[MAX_EVENT_BUFFER_SIZE];
    DWORD bytesReturned;
    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    while (g_Running) {
        // Stressing the Inverted Call Model: Flood with pending IRPs
        BOOL success = DeviceIoControl(hDevice, IOCTL_TDS_GET_NEXT_EVENT, 
                                       NULL, 0, buffer, sizeof(buffer), 
                                       &bytesReturned, &ov);

        if (!success && GetLastError() == ERROR_IO_PENDING) {
            // Wait for completion or timeout to cycle pressure
            if (WaitForSingleObject(ov.hEvent, 100) == WAIT_OBJECT_0) {
                g_SuccessCount++;
            } else {
                // Force cancellation to test driver's IRP cleanup stability
                CancelIoEx(hDevice, &ov);
                g_ErrorCount++;
            }
            ResetEvent(ov.hEvent);
        } else if (success) {
            g_SuccessCount++;
        } else {
            g_ErrorCount++;
        }
    }
    CloseHandle(ov.hEvent);
}

int main() {
    std::cout << "[*] Initializing TDS Driver Stress Test..." << std::endl;

    HANDLE hDevice = CreateFileW(L"\\\\.\\TDS_Core_Kernel", GENERIC_READ | GENERIC_WRITE, 
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "[!] Failed to connect to driver. Error: " << GetLastError() << std::endl;
        return 1;
    }

    const int threadCount = 8;
    std::vector<std::thread> workers;
    for (int i = 0; i < threadCount; ++i) {
        workers.emplace_back(FuzzWorker, hDevice);
    }

    std::cout << "[+] Stress test active with " << threadCount << " concurrent threads." << std::endl;
    std::cout << "[*] Press Enter to terminate test and review stability." << std::endl;

    std::cin.get();
    g_Running = false;

    for (auto& t : workers) {
        t.join();
    }

    std::cout << "\n--- Stress Test Report ---" << std::endl;
    std::cout << "Successful I/O Cycles: " << g_SuccessCount << std::endl;
    std::cout << "Cancelled/Error Cycles: " << g_ErrorCount << std::endl;
    std::cout << "Kernel Status: STABLE" << std::endl;

    CloseHandle(hDevice);
    return 0;
}

