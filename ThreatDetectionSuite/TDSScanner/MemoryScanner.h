#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_set>
#include "../TDSCommon/TDSCommon.h"
#include <yara.h>

namespace TDS {

class MemoryScanner {
public:
    static bool InitializeYara(const std::string& rulePath);
    static void ShutdownYara();

    static bool DetectNopSleds(HANDLE hProcess, LPVOID startAddress, SIZE_T regionSize);
    static bool DetectDirectSyscalls(HANDLE hProcess, LPVOID baseAddress, SIZE_T regionSize);
    static bool DetectStackPivoting(HANDLE hProcess, HANDLE hThread);
    static void ScanProcessHooks(HANDLE hProcess);
    static void DetectProcessHollowing(HANDLE hProcess, const std::wstring& processName);
    static void ScanAllProcesses();

private:
    static int YaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);
    static void AnalyzeProcessMemory(DWORD pid, const std::wstring& processName);
    static bool IsJitEnabledProcess(const std::wstring& processName);

    static YR_RULES* s_yaraRules;
};

} // namespace TDS

