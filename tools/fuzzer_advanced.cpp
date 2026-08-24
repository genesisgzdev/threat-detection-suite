#include <windows.h>
#include <iostream>
#include <vector>
#include <random>
#include "../ThreatDetectionSuite/TDSCommon/TDSCommon.h"

// Function to generate random bytes for fuzzing payload
void GenerateRandomBytes(std::vector<uint8_t>& buffer) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    for (auto& byte : buffer) {
        byte = static_cast<uint8_t>(distrib(gen));
    }
}

int main() {
    std::cout << "[*] Starting TDS EDR Fuzzer..." << std::endl;
    
    // Open handle to the device using the obfuscated symlink
    HANDLE hDevice = CreateFileA(
        "\\\\.\\TDS_Core_Link",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open handle to \\\\.\\TDS_Core_Link. Error: " << GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "[+] Successfully opened handle to the driver." << std::endl;

    // Define boundary values and oversized buffers for testing
    std::vector<size_t> boundary_sizes = {
        0,                  // Minimum size
        1,                  // Off-by-one
        4,                  // Standard 32-bit integer size
        8,                  // Standard 64-bit integer size
        256,                // Small buffer
        1024,               // Medium buffer
        4096,               // PAGE_SIZE
        8192,               // 2 * PAGE_SIZE
        65536,              // Large buffer
        1048576,            // Oversized buffer (1MB)
        1048576 * 10,       // Very large buffer (10MB)
        0x7FFFFFFF,         // Near max positive 32-bit integer
        0xFFFFFFFF          // Maximum 32-bit integer (causes integer overflow vulnerabilities)
    };

    std::vector<DWORD> ioctls = {
        IOCTL_TDS_GET_NEXT_EVENT,
        IOCTL_TDS_SET_PROTECTION_POLICY
    };

    const int iterations = 100; // Number of iterations per IOCTL per boundary size

    for (DWORD ioctl : ioctls) {
        std::cout << "[*] Fuzzing IOCTL: 0x" << std::hex << ioctl << std::dec << std::endl;
        
        for (size_t target_size : boundary_sizes) {
            std::cout << "    [*] Testing Buffer Size: " << target_size << " bytes." << std::endl;
            
            for (int i = 0; i < iterations; ++i) {
                // Determine allocation size to prevent crashing the fuzzer itself
                // Limit maximum real allocation to 10MB to avoid OOM in user-mode
                size_t alloc_size = (target_size > 1048576 * 10) ? 1048576 * 10 : target_size;
                
                std::vector<uint8_t> inBuffer;
                if (alloc_size > 0) {
                    try {
                        inBuffer.resize(alloc_size);
                        GenerateRandomBytes(inBuffer);
                    } catch (const std::bad_alloc&) {
                        std::cerr << "    [-] Allocation failed for size " << alloc_size << ". Skipping." << std::endl;
                        continue;
                    }
                }

                std::vector<uint8_t> outBuffer;
                if (alloc_size > 0) {
                    try {
                        outBuffer.resize(alloc_size);
                    } catch (const std::bad_alloc&) {
                        // Ignore allocation failures for output buffer and pass NULL
                    }
                }

                DWORD bytesReturned = 0;
                
                // Never pass a length larger than the backing allocation. The
                // Win32 API validates user buffers before the driver sees the
                // request; claiming 0xFFFFFFFF with a tiny vector only crashes
                // this harness and tells us nothing about the driver.
                const DWORD input_length = static_cast<DWORD>(alloc_size);
                const DWORD output_length = static_cast<DWORD>(outBuffer.size());
                BOOL result = DeviceIoControl(
                    hDevice,
                    ioctl,
                    inBuffer.empty() ? NULL : inBuffer.data(),
                    input_length,
                    outBuffer.empty() ? NULL : outBuffer.data(),
                    output_length,
                    &bytesReturned,
                    NULL
                );

                // We don't necessarily care about the result, we are looking for crashes (BSOD)
                if (result && target_size >= 0x7FFFFFFF) {
                    std::cout << "    [!] Warning: IOCTL succeeded with capped allocation for oversized request." << std::endl;
                }
            }
        }
    }

    std::cout << "[+] Fuzzing complete." << std::endl;
    CloseHandle(hDevice);
    return 0;
}
