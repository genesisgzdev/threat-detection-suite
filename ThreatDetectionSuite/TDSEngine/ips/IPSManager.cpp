#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <cwchar>
#include "IPSManager.h"
#include "../Logger.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#ifndef MIB_TCP_STATE_DELETE
#define MIB_TCP_STATE_DELETE 12
#endif

namespace TDS {

bool IPSManager::IsProtectedProcess(DWORD pid) {
    // This is a user-mode fail-safe in addition to the kernel handle policy.
    // A basename match is deliberately deny-only: it never grants trust.
    if (pid <= 4) return true;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return true;

    wchar_t path[32768] = {};
    DWORD length = static_cast<DWORD>(sizeof(path) / sizeof(path[0]));
    const bool queried = QueryFullProcessImageNameW(hProcess, 0, path, &length) != FALSE;
    CloseHandle(hProcess);
    if (!queried) return true;

    const wchar_t* basename = wcsrchr(path, L'\\');
    basename = basename ? basename + 1 : path;
    return _wcsicmp(basename, L"lsass.exe") == 0 ||
           _wcsicmp(basename, L"TDSService.exe") == 0;
}

typedef NTSTATUS(NTAPI *pfnNtSuspendProcess)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI *pfnNtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

bool IPSManager::ContainProcess(DWORD pid) {
    if (IsProtectedProcess(pid)) {
        Logger::Instance().LogThreat(TDS_SEVERITY_INFO, CAT_PROCESS_BEHAVIOR, "IPS: protected process response suppressed", "deny-only safeguard", pid);
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    pfnNtSuspendProcess NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");
    
    bool success = false;
    if (NtSuspendProcess) {
        NTSTATUS status = NtSuspendProcess(hProcess);
        success = NT_SUCCESS(status);
        if (success) {
            Logger::Instance().LogThreat(TDS_SEVERITY_INFO, CAT_PROCESS_BEHAVIOR, "IPS: Atomic Process Containment (Suspended)", "PID Frozen", pid);
        }
    }
    CloseHandle(hProcess);
    return success;
}

bool IPSManager::TerminateMaliciousProcess(DWORD pid) {
    if (IsProtectedProcess(pid)) {
        Logger::Instance().LogThreat(TDS_SEVERITY_INFO, CAT_PROCESS_BEHAVIOR, "IPS: protected process termination suppressed", "deny-only safeguard", pid);
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return false;

    pfnNtTerminateProcess NtTerminateProcess = (pfnNtTerminateProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTerminateProcess");
    
    bool success = false;
    if (NtTerminateProcess) {
        NTSTATUS status = NtTerminateProcess(hProcess, (NTSTATUS)0xC0000022);
        success = NT_SUCCESS(status);
        if (success) {
            Logger::Instance().LogThreat(TDS_SEVERITY_INFO, CAT_PROCESS_BEHAVIOR, "IPS: Process Terminated successfully", "Process Killed", pid);
        }
    }
    CloseHandle(hProcess);
    return success;
}

bool IPSManager::TerminateNetworkConnection(DWORD pid, const std::string& remoteIp) {
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return false;
    }

    PMIB_TCPTABLE_OWNER_PID pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    
    IN_ADDR targetIp;
    if (inet_pton(AF_INET, remoteIp.c_str(), &targetIp) != 1) return false;

    bool connectionKilled = false;
    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        if (pTcpTable->table[i].dwOwningPid == pid && pTcpTable->table[i].dwRemoteAddr == targetIp.S_un.S_addr) {
            MIB_TCPROW row;
            row.dwState = MIB_TCP_STATE_DELETE; 
            row.dwLocalAddr = pTcpTable->table[i].dwLocalAddr;
            row.dwLocalPort = pTcpTable->table[i].dwLocalPort;
            row.dwRemoteAddr = pTcpTable->table[i].dwRemoteAddr;
            row.dwRemotePort = pTcpTable->table[i].dwRemotePort;
            
            if (SetTcpEntry(&row) == NO_ERROR) {
                connectionKilled = true;
                Logger::Instance().LogThreat(TDS_SEVERITY_INFO, CAT_PROCESS_BEHAVIOR, "IPS: TCP Connection forcefully reset", remoteIp, pid);
            }
        }
    }
    
    // IPv6 support depends on SDK availability. 
    // We will use dynamic lookup or focus on v4 for the v5.0.0 release build if v6 headers are conflicting.
    
    return connectionKilled;
}

} // namespace TDS
