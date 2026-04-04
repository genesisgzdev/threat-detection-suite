#include "MemoryScanner.h"
#include <iostream>
#include <algorithm>
#include <tlhelp32.h>
#include <psapi.h>
#include "../TDSEngine/Logger.h"

namespace TDS {

bool MemoryScanner::DetectNopSleds(HANDLE hProcess, LPVOID startAddress, SIZE_T regionSize) {
    const SIZE_T CHUNK_SIZE = 4096; 
    BYTE buffer[CHUNK_SIZE + 32];
    SIZE_T bytesRead = 0;
    
    // FIX: Proportional sampling for large regions (Issue 28)
    std::vector<SIZE_T> offsets = { 0 };
    if (regionSize > CHUNK_SIZE * 2) {
        offsets.push_back(regionSize / 2);
        offsets.push_back(regionSize - CHUNK_SIZE);
        
        // Add more samples for very large regions (> 1MB)
        if (regionSize > 1024 * 1024) {
            for (SIZE_T i = 512 * 1024; i < regionSize - CHUNK_SIZE; i += 512 * 1024) {
                offsets.push_back(i);
            }
        }
    }

    for (SIZE_T offset : offsets) {
        SIZE_T toRead = min(CHUNK_SIZE, regionSize - offset);
        if (ReadProcessMemory(hProcess, (LPVOID)((SIZE_T)startAddress + offset), buffer, toRead, &bytesRead)) {
            int consecutiveNops = 0;
            int consecutiveInt3 = 0;
            int consecutiveRet = 0;
            for (SIZE_T i = 0; i < bytesRead; i++) {
                if (buffer[i] == 0x90) consecutiveNops++; else consecutiveNops = 0;
                if (buffer[i] == 0xCC) consecutiveInt3++; else consecutiveInt3 = 0;
                if (buffer[i] == 0xC3) consecutiveRet++;  else consecutiveRet = 0;

                if (consecutiveNops >= 16 || consecutiveInt3 >= 16 || consecutiveRet >= 16) {
                    return true; 
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
        // FIX: Include MEM_PRIVATE and Executable regions for reflective loading (Issue 26)
        if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_PRIVATE)) {
            if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_WRITECOPY) {
                // FIX: Scan larger chunk of the region (Issue 27)
                const SIZE_T SCAN_SIZE = 4096;
                BYTE sample[SCAN_SIZE];
                SIZE_T toRead = min(SCAN_SIZE, mbi.RegionSize);
                
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, sample, toRead, NULL)) {
                    bool hookFound = false;
                    std::string hookType = "";
                    
                    for (SIZE_T i = 0; i < toRead - 2; i++) {
                        if (sample[i] == 0xE9) { hookFound = true; hookType = "JMP Relative"; break; }
                        else if (sample[i] == 0xFF && sample[i+1] == 0x25) { hookFound = true; hookType = "JMP Indirect"; break; }
                        else if (sample[i] == 0x48 && sample[i+1] == 0xB8) { hookFound = true; hookType = "MOV RAX, Abs"; break; }
                    }

                    if (hookFound) {
                        Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_HOOK_DETECTION, "Inline hook detected in module: " + hookType, "Memory", GetProcessId(hProcess));
                    }
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
        LPVOID nextAddr = (LPVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        bool addressOverflow = ((ULONG_PTR)nextAddr <= (ULONG_PTR)mbi.BaseAddress);

        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
            if (mbi.State == MEM_COMMIT) {
                // FIX: Remove goto, use continue properly (Issue 25)
                if (isJit && mbi.RegionSize < 0x100000) {
                    addr = nextAddr;
                    if (addressOverflow) break;
                    continue;
                }

                if (DetectNopSleds(hProcess, mbi.BaseAddress, mbi.RegionSize)) {
                    std::string sName(processName.begin(), processName.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_MEMORY_ANOMALY, "Shellcode NOP sled in RWX region", sName, pid);
                }
            }
        }

        if (addressOverflow) break;
        addr = nextAddr;
    }

    ScanProcessHooks(hProcess);
    CloseHandle(hProcess);
}

} // namespace TDS
