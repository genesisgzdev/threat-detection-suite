#include "MemoryScanner.h"
#include <iostream>
#include <algorithm>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include "../TDSEngine/Logger.h"
#include "../TDSEngine/ips/IPSManager.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "yara.lib")

namespace TDS {

YR_RULES* MemoryScanner::s_yaraRules = nullptr;

bool MemoryScanner::InitializeYara(const std::string& rulePath) {
    if (yr_initialize() != ERROR_SUCCESS) return false;

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return false;

    FILE* ruleFile = nullptr;
    fopen_s(&ruleFile, rulePath.c_str(), "r");
    if (!ruleFile) {
        yr_compiler_destroy(compiler);
        return false;
    }

    if (yr_compiler_add_file(compiler, ruleFile, NULL, rulePath.c_str()) != 0) {
        fclose(ruleFile);
        yr_compiler_destroy(compiler);
        return false;
    }

    yr_compiler_get_rules(compiler, &s_yaraRules);
    fclose(ruleFile);
    yr_compiler_destroy(compiler);
    
    Logger::Instance().LogThreat(TDS_SEVERITY_INFO, CAT_PROCESS_BEHAVIOR, "YARA Memory Engine Initialized", rulePath, 0);
    return true;
}

void MemoryScanner::ShutdownYara() {
    if (s_yaraRules) {
        yr_rules_destroy(s_yaraRules);
        s_yaraRules = nullptr;
    }
    yr_finalize();
}

int MemoryScanner::YaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        DWORD pid = *(DWORD*)user_data;
        
        std::string ruleName = rule->identifier;
        Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_MEMORY_ANOMALY, "YARA Rule Match in Memory: " + ruleName, "Memory Payload", pid);
        
        // IPS Intervention
        IPSManager::ContainProcess(pid);
        IPSManager::TerminateMaliciousProcess(pid);
    }
    return CALLBACK_CONTINUE;
}

bool MemoryScanner::DetectNopSleds(HANDLE hProcess, LPVOID startAddress, SIZE_T regionSize) {
    const SIZE_T CHUNK_SIZE = 4096; 
    BYTE buffer[CHUNK_SIZE + 32];
    SIZE_T bytesRead = 0;
    
    // Proportional sampling for large regions
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
    // 1. Deep Hooking Scanner: Compare memory module against disk file
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
                std::wstring modNameStr = szModName;
                std::transform(modNameStr.begin(), modNameStr.end(), modNameStr.begin(), ::towlower);
                
                // Optimize: only scan critical core DLLs for deep mid-function hooks
                if (modNameStr.find(L"ntdll.dll") != std::wstring::npos || 
                    modNameStr.find(L"kernel32.dll") != std::wstring::npos ||
                    modNameStr.find(L"kernelbase.dll") != std::wstring::npos) {
                    
                    HANDLE hFile = CreateFileW(szModName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
                        if (hMap) {
                            LPVOID pMapped = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
                            if (pMapped) {
                                PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pMapped;
                                PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pMapped + pDos->e_lfanew);
                                PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
                                
                                // Parse Relocations to avoid ASLR False Positives
                                std::unordered_set<SIZE_T> relocatedRVAs;
                                PIMAGE_DATA_DIRECTORY relocDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
                                if (relocDir->VirtualAddress && relocDir->Size) {
                                    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pMapped + relocDir->VirtualAddress);
                                    while (pReloc->VirtualAddress != 0) {
                                        DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                                        PWORD pEntry = (PWORD)(pReloc + 1);
                                        for (DWORD e = 0; e < numEntries; e++) {
                                            int type = pEntry[e] >> 12;
                                            // Filter x64 and x86 relocation types
                                            if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW) {
                                                SIZE_T rva = pReloc->VirtualAddress + (pEntry[e] & 0xFFF);
                                                // Relocations affect up to 8 bytes (pointers)
                                                for (int off = 0; off < 8; off++) relocatedRVAs.insert(rva + off);
                                            }
                                        }
                                        pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
                                    }
                                }

                                for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
                                    // Scan .text and executable sections
                                    if (memcmp(pSec[s].Name, ".text", 5) == 0 || (pSec[s].Characteristics & IMAGE_SCN_CNT_CODE)) {
                                        SIZE_T size = pSec[s].Misc.VirtualSize;
                                        std::vector<BYTE> memBuffer(size);
                                        
                                        if (ReadProcessMemory(hProcess, (PBYTE)hMods[i] + pSec[s].VirtualAddress, memBuffer.data(), size, NULL)) {
                                            PBYTE diskBuffer = (PBYTE)pMapped + pSec[s].VirtualAddress;
                                            
                                            for (SIZE_T b = 0; b < size; b++) {
                                                SIZE_T currentRva = pSec[s].VirtualAddress + b;
                                                
                                                // Skip bytes modified legitimately by the OS loader (ASLR)
                                                if (relocatedRVAs.find(currentRva) != relocatedRVAs.end()) continue;

                                                if (memBuffer[b] != diskBuffer[b]) {
                                                    // ANY non-relocation change is a guaranteed modification (Hook/Patch)
                                                    std::string sModName(modNameStr.begin(), modNameStr.end());
                                                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_HOOK_DETECTION, 
                                                        "Deep Inline/Mid-function Hook detected: Unrelocated memory-disk byte mismatch", sModName, GetProcessId(hProcess));
                                                    break; // Alert once per section to avoid flood
                                                }
                                            }
                                        }
                                    }
                                }
                                UnmapViewOfFile(pMapped);
                            }
                            CloseHandle(hMap);
                        }
                        CloseHandle(hFile);
                    }
                }
            }
        }
    }

    // 2. Scan standalone unbacked anomalous memory pages for JMP/CALL stubs
    LPVOID address = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_WRITECOPY) {
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
                        Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_MEMORY_ANOMALY, "Suspicious opcodes in unbacked memory region: " + hookType, "Memory", GetProcessId(hProcess));
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
                if (isJit && mbi.RegionSize < 0x100000) {
                    addr = nextAddr;
                    if (addressOverflow) break;
                    continue;
                }

                if (DetectNopSleds(hProcess, mbi.BaseAddress, mbi.RegionSize)) {
                    std::string sName(processName.begin(), processName.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_MEMORY_ANOMALY, "Shellcode NOP sled in RWX region", sName, pid);
                }

                // YARA Memory Scanning on Anonymous/Private Executable Pages
                if (s_yaraRules && mbi.Type == MEM_PRIVATE) {
                    SIZE_T toRead = min(mbi.RegionSize, (SIZE_T)(10 * 1024 * 1024)); // Cap at 10MB per region to prevent lockups
                    std::vector<uint8_t> buffer(toRead);
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), toRead, NULL)) {
                        yr_rules_scan_mem(
                            s_yaraRules, buffer.data(), toRead, 
                            0, YaraCallback, &pid, 0
                        );
                    }
                }
            }
        }

        if (addressOverflow) break;
        addr = nextAddr;
    }

    ScanProcessHooks(hProcess);

    wchar_t fullPath[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, fullPath, &size)) {
        DetectProcessHollowing(hProcess, fullPath);
    } else {
        DetectProcessHollowing(hProcess, processName);
    }

    CloseHandle(hProcess);
}

void MemoryScanner::DetectProcessHollowing(HANDLE hProcess, const std::wstring& processName) {
    // 1. Get ImageBaseAddress from PEB
    PROCESS_BASIC_INFORMATION pbi = {0};
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    
    if (NtQueryInformationProcess && NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
        PEB peb;
        if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
            LPVOID imageBase = peb.ImageBaseAddress;
            
            // 2. Architecture-Agnostic PE Header Parsing (WOW64 Safe)
            IMAGE_DOS_HEADER dosHeader;
            if (ReadProcessMemory(hProcess, imageBase, &dosHeader, sizeof(dosHeader), NULL)) {
                if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                    DWORD signature = 0;
                    if (ReadProcessMemory(hProcess, (PBYTE)imageBase + dosHeader.e_lfanew, &signature, sizeof(signature), NULL) && signature == IMAGE_NT_SIGNATURE) {
                        IMAGE_FILE_HEADER fileHeader;
                        if (ReadProcessMemory(hProcess, (PBYTE)imageBase + dosHeader.e_lfanew + sizeof(DWORD), &fileHeader, sizeof(fileHeader), NULL)) {
                            
                            SIZE_T optionalHeaderOffset = (SIZE_T)imageBase + dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
                            SIZE_T sectionsOffset = optionalHeaderOffset + fileHeader.SizeOfOptionalHeader;
                            std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
                            
                            if (ReadProcessMemory(hProcess, (LPCVOID)sectionsOffset, sections.data(), sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections, NULL)) {
                                for (const auto& sec : sections) {
                                    if (memcmp(sec.Name, ".text", 5) == 0 || (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                                        MEMORY_BASIC_INFORMATION mbi;
                                        if (VirtualQueryEx(hProcess, (PBYTE)imageBase + sec.VirtualAddress, &mbi, sizeof(mbi))) {
                                            if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) {
                                                std::string sName(processName.begin(), processName.end());
                                                Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_PROCESS_BEHAVIOR, 
                                                    "Process Hollowing: .text section has modified RWX/WriteCopy permissions", sName, GetProcessId(hProcess));
                                            }
                                        }
                                    }
                                }
                            }

                            DWORD memoryTimeStamp = fileHeader.TimeDateStamp;
                            
                            // 3. Read same PE file from disk and compare
                            HANDLE hFile = CreateFileW(processName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                            if (hFile != INVALID_HANDLE_VALUE) {
                                IMAGE_DOS_HEADER diskDos;
                                DWORD read;
                                if (ReadFile(hFile, &diskDos, sizeof(diskDos), &read, NULL) && diskDos.e_magic == IMAGE_DOS_SIGNATURE) {
                                    SetFilePointer(hFile, diskDos.e_lfanew + sizeof(DWORD), NULL, FILE_BEGIN);
                                    IMAGE_FILE_HEADER diskFileHeader;
                                    if (ReadFile(hFile, &diskFileHeader, sizeof(diskFileHeader), &read, NULL)) {
                                        if (memoryTimeStamp != diskFileHeader.TimeDateStamp) {
                                            std::string sName(processName.begin(), processName.end());
                                            Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_PROCESS_BEHAVIOR, 
                                                "Process Hollowing detected: Memory TimeDateStamp mismatch", sName, GetProcessId(hProcess));
                                        }
                                    }
                                }
                                CloseHandle(hFile);
                            }
                        }
                    }
                }
            }
        }
    }
}

} // namespace TDS

