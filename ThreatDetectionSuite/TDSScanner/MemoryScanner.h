#pragma once

#include "../TDSCommon/TDSCommon.h"
#include <vector>
#include <string>
#include <winternl.h>

namespace TDS {

class MemoryScanner {
public:
    MemoryScanner() = default;
    ~MemoryScanner() = default;

    // Detects inline API hooks in ntdll.dll and kernel32.dll
    bool DetectApiHooks(DWORD processId);

    // Scans RWX memory regions for NOP sleds (8+ consecutive 0x90)
    bool DetectNopSleds(DWORD processId);

    // Detects process hollowing by comparing PE headers
    bool DetectProcessHollowing(DWORD processId);

private:
    bool CheckModuleHooks(HANDLE hProcess, const std::wstring& moduleName);
    bool IsNtApi(const std::string& functionName);
    
    // Helper to read process memory
    bool ReadProcessMemorySafe(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize);
};

} // namespace TDS
