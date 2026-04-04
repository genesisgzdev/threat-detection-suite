#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_set>
#include "../TDSCommon/TDSCommon.h"

namespace TDS {

class MemoryScanner {
public:
    static bool DetectNopSleds(HANDLE hProcess, LPVOID startAddress, SIZE_T regionSize);
    static void ScanProcessHooks(HANDLE hProcess);
    static void DetectProcessHollowing(HANDLE hProcess, const std::wstring& processName);
    static void ScanAllProcesses();

private:
    static void AnalyzeProcessMemory(DWORD pid, const std::wstring& processName);
    static bool IsJitEnabledProcess(const std::wstring& processName);
};

} // namespace TDS
