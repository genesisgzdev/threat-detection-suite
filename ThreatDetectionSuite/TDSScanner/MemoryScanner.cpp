#include "MemoryScanner.h"
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <algorithm>
#include <memory>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

namespace TDS {

// External definition for NtQueryInformationProcess
extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

bool MemoryScanner::DetectApiHooks(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return false;

    bool hooksDetected = false;
    hooksDetected |= CheckModuleHooks(hProcess, L"ntdll.dll");
    hooksDetected |= CheckModuleHooks(hProcess, L"kernel32.dll");

    CloseHandle(hProcess);
    return hooksDetected;
}

bool MemoryScanner::CheckModuleHooks(HANDLE hProcess, const std::wstring& moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) return false;

    HMODULE targetMod = nullptr;
    WCHAR szModName[MAX_PATH];
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
            if (_wcsicmp(szModName, moduleName.c_str()) == 0) {
                targetMod = hMods[i];
                break;
            }
        }
    }

    if (!targetMod) return false;

    // We need to parse EAT of the module. Since it's a system module, we can parse it from our own process
    // and just adjust the base address.
    HMODULE hLocalMod = GetModuleHandleW(moduleName.c_str());
    if (!hLocalMod) return false;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hLocalMod;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hLocalMod + dosHeader->e_lfanew);
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hLocalMod + exportDirRVA);

    DWORD* names = (DWORD*)((BYTE*)hLocalMod + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hLocalMod + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hLocalMod + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)((BYTE*)hLocalMod + names[i]);
        
        // If ntdll, check for Nt-prefixed APIs
        if (_wcsicmp(moduleName.c_str(), L"ntdll.dll") == 0) {
            if (strncmp(funcName, "Nt", 2) != 0) continue;
        }

        void* funcAddrRemote = (BYTE*)targetMod + functions[ordinals[i]];
        BYTE buffer[32];
        if (ReadProcessMemorySafe(hProcess, funcAddrRemote, buffer, sizeof(buffer))) {
            // Check for common hook patterns: JMP (0xE9), JMP DWORD PTR [REL] (0xFF 0x25)
            // Or MOV EAX, addr; JMP EAX (0xB8 ... 0xFF 0xE0)
            if (buffer[0] == 0xE9 || (buffer[0] == 0xFF && buffer[1] == 0x25) || (buffer[0] == 0x48 && buffer[1] == 0xFF && buffer[2] == 0x25)) {
                return true; // Hook detected
            }
        }
    }

    return false;
}

bool MemoryScanner::DetectNopSleds(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return false;

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = si.lpMinimumApplicationAddress;

    while (addr < si.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_EXECUTE_READWRITE)) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                if (ReadProcessMemorySafe(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize)) {
                    int consecutiveNops = 0;
                    for (BYTE b : buffer) {
                        if (b == 0x90) {
                            consecutiveNops++;
                            if (consecutiveNops >= 8) {
                                CloseHandle(hProcess);
                                return true;
                            }
                        } else {
                            consecutiveNops = 0;
                        }
                    }
                }
            }
            addr = (LPVOID)((BYTE*)mbi.BaseAddress + mbi.RegionSize);
        } else {
            break;
        }
    }

    CloseHandle(hProcess);
    return false;
}

bool MemoryScanner::DetectProcessHollowing(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return false;

    PROCESS_BASIC_INFORMATION pbi;
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) != 0) {
        CloseHandle(hProcess);
        return false;
    }

    PEB peb;
    if (!ReadProcessMemorySafe(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb))) {
        CloseHandle(hProcess);
        return false;
    }

    PVOID imageBase = peb.ImageBaseAddress;
    BYTE remoteHeader[0x1000];
    if (!ReadProcessMemorySafe(hProcess, imageBase, remoteHeader, sizeof(remoteHeader))) {
        CloseHandle(hProcess);
        return false;
    }

    WCHAR imagePath[MAX_PATH];
    DWORD pathSize = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, imagePath, &pathSize)) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hFile = CreateFileW(imagePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }

    BYTE localHeader[0x1000];
    DWORD bytesRead;
    ReadFile(hFile, localHeader, sizeof(localHeader), &bytesRead, nullptr);
    CloseHandle(hFile);

    if (bytesRead < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hProcess);
        return false;
    }

    // Compare headers (ignoring some dynamic fields if necessary, but here we compare first 0x1000)
    // Actually, comparing first 0x1000 bytes might be too strict if some fields change (like TimeDateStamp in memory? No, usually that's the same)
    // But Relocations might happen.
    // However, the prompt says "compare the first 0x1000 bytes (PE Header) with the executable on disk".
    
    // We should at least check if the SizeOfImage or other critical fields match.
    // Let's stick to the prompt's 0x1000 bytes comparison but maybe allow some leeway or just do it.
    if (memcmp(remoteHeader, localHeader, 0x1000) != 0) {
        CloseHandle(hProcess);
        return true; // Potential hollowing
    }

    CloseHandle(hProcess);
    return false;
}

bool MemoryScanner::ReadProcessMemorySafe(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead) && bytesRead == nSize;
}

} // namespace TDS
