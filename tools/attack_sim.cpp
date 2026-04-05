#include <windows.h>
#include <iostream>
#include <string>

/**
 * Industrial Attack Simulator (Refined)
 * Attempts to acquire high-privilege handles to validate EDR handle stripping.
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: attack_sim.exe <target_pid>" << std::endl;
        return 1;
    }

    DWORD targetPid = (DWORD)std::stoul(argv[1]);
    std::cout << "[*] Attempting to acquire high-privilege handle to PID: " << targetPid << std::endl;

    // Dangerous access mask: Terminate + Write + Thread Creation + DUP
    ACCESS_MASK dangerousMask = PROCESS_TERMINATE | PROCESS_VM_WRITE | 
                                 PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | 
                                 PROCESS_DUP_HANDLE;

    HANDLE hProcess = OpenProcess(dangerousMask, FALSE, targetPid);

    if (hProcess == NULL) {
        std::cout << "[!] OpenProcess failed. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] Handle acquired. Attempting dangerous operation (TerminateProcess)..." << std::endl;
    
    if (!TerminateProcess(hProcess, 0x1337)) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            std::cout << "[SUCCESS] EDR Blocked TerminateProcess! Handle was stripped (Error: Access Denied)" << std::endl;
        } else {
            std::cout << "[!] Operation failed with unexpected error: " << err << std::endl;
        }
    } else {
        std::cout << "[FAILURE] EDR Failed to protect the process. Process terminated." << std::endl;
    }

    CloseHandle(hProcess);
    return 0;
}
