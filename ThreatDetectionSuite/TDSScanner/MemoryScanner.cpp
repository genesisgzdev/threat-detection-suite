#include "MemoryScanner.h"
#include <iostream>
#include <algorithm>
#include <tlhelp32.h>
#include "../TDSEngine/Logger.h"

namespace TDS {

bool MemoryScanner::DetectNopSleds(HANDLE hProcess, LPVOID startAddress, SIZE_T regionSize) {
    const SIZE_T CHUNK_SIZE = 4096; 
    BYTE buffer[CHUNK_SIZE + 32];
    SIZE_T bytesRead = 0;
    
    std::vector<SIZE_T> offsets = { 0 };
    if (regionSize > CHUNK_SIZE * 2) {
        offsets.push_back(regionSize / 2);
        offsets.push_back(regionSize - CHUNK_SIZE);
    }

    for (SIZE_T offset : offsets) {
        SIZE_T toRead = min(CHUNK_SIZE, regionSize - offset);
        if (ReadProcessMemory(hProcess, (LPVOID)((SIZE_T)startAddress + offset), buffer, toRead, &bytesRead)) {
            int consecutiveNops = 0;
            for (SIZE_T i = 0; i < bytesRead; i++) {
                if (buffer[i] == 0x90) {
                    consecutiveNops++;
                    if (consecutiveNops >= 16) return true; 
                } else {
                    consecutiveNops = 0;
                }
            }
        }
    }
    return false;
}

void MemoryScanner::ScanProcessHooks(HANDLE hProcess) {
    LPVOID address = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE) {
            BYTE sample[64];
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, sample, 64, NULL)) {
                bool hookFound = false;
                std::string hookType = "";
                
                if (sample[0] == 0xE9) { hookFound = true; hookType = "JMP Relative"; }
                else if (sample[0] == 0xFF && sample[1] == 0x25) { hookFound = true; hookType = "JMP Indirect"; }
                else if (sample[0] == 0x48 && sample[1] == 0xB8) { hookFound = true; hookType = "MOV RAX, Abs"; }

                if (hookFound) {
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_HOOK_DETECTION, "Inline hook detected in module: " + hookType, "Memory", GetProcessId(hProcess));
                }
            }
        }
        
        LPVOID nextAddr = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
        if ((ULONG_PTR)nextAddr <= (ULONG_PTR)mbi.BaseAddress) break;
        address = nextAddr;
    }
}

void MemoryScanner::ScanAllProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == GetCurrentProcessId() || pe32.th32ProcessID == 0) continue;
            AnalyzeProcessMemory(pe32.th32ProcessID, pe32.szExeFile);
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

bool MemoryScanner::IsJitEnabledProcess(const std::wstring& processName) {
    static const std::unordered_set<std::wstring> jitProcesses = {
        L"chrome.exe", L"firefox.exe", L"msedge.exe", L"brave.exe", L"opera.exe", L"vivaldi.exe", L"node.exe"
    };
    std::wstring lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    return jitProcesses.find(lowerName) != jitProcesses.end();
}

void MemoryScanner::AnalyzeProcessMemory(DWORD pid, const std::wstring& processName) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            // Protected process, skipping
        }
        return;
    }

    bool isJit = IsJitEnabledProcess(processName);
    LPVOID addr = NULL;
    MEMORY_BASIC_INFORMATION mbi;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
            if (mbi.State == MEM_COMMIT) {
                if (isJit && mbi.RegionSize < 0x100000) goto next_region;

                if (DetectNopSleds(hProcess, mbi.BaseAddress, mbi.RegionSize)) {
                    std::string sName(processName.begin(), processName.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_MEMORY_ANOMALY, "Shellcode NOP sled in RWX region", sName, pid);
                }
            }
        }

    next_region:
        LPVOID nextAddr = (LPVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        if ((ULONG_PTR)nextAddr <= (ULONG_PTR)mbi.BaseAddress) break;
        addr = nextAddr;
    }

    ScanProcessHooks(hProcess);
    CloseHandle(hProcess);
}

} // namespace TDS
