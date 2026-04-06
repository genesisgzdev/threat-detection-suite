#pragma once
#include <windows.h>
#include <string>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

namespace TDS {

/**
 * ForensicManager: Orchestrates automated evidence collection.
 * Utilizes MiniDumpWriteDump for process memory capture upon critical detection.
 */
class ForensicManager {
public:
    static ForensicManager& Instance() {
        static ForensicManager instance;
        return instance;
    }

    /**
     * Captures a full memory dump of a target process.
     * @param pid - Target Process ID.
     * @param threatType - Name of the detected threat for naming convention.
     * @returns boolean - True if the evidence was successfully persisted.
     */
    bool CaptureProcessDump(DWORD pid, const std::string& threatType) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess == INVALID_HANDLE_VALUE) return false;

        char dumpPath[MAX_PATH];
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        sprintf_s(dumpPath, "C:\\ProgramData\\TDS\\Evidence_%s_%lu_%04d%02d%02d_%02d%02d%02d.dmp", 
                  threatType.c_str(), pid, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        // Ensure directory exists
        CreateDirectoryA("C:\\ProgramData\\TDS", NULL);

        HANDLE hFile = CreateFileA(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            CloseHandle(hProcess);
            return false;
        }

        // production dump: Full memory for deep inspection
        MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | 
                                                 MiniDumpWithHandleData | 
                                                 MiniDumpWithUnloadedModules | 
                                                 MiniDumpWithProcessThreadData);

        BOOL result = MiniDumpWriteDump(hProcess, pid, hFile, dumpType, NULL, NULL, NULL);

        CloseHandle(hFile);
        CloseHandle(hProcess);
        return result != FALSE;
    }

private:
    ForensicManager() = default;
};

} // namespace TDS

