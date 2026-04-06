#include "IPSManager.h"
#include <winternl.h>
#include <iostream>
#include <tcpmib.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include "../Logger.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace TDS {

typedef NTSTATUS(NTAPI *pfnNtSuspendProcess)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI *pfnNtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

bool IPSManager::ContainProcess(DWORD pid) {
    if (pid == 0 || pid == 4) return false; // Never touch Idle or System

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
    if (pid == 0 || pid == 4) return false;

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return false;

    pfnNtTerminateProcess NtTerminateProcess = (pfnNtTerminateProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTerminateProcess");
    
    bool success = false;
    if (NtTerminateProcess) {
        // 0xC0000022 is STATUS_ACCESS_DENIED, a standard termination code for EDR interventions
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
            row.dwState = MIB_TCP_STATE_DELETE; // Forcefully null-route (send RST)
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
    
    // IPv6 Support for C2 Null-Routing
    DWORD size6 = 0;
    GetExtendedTcpTable(NULL, &size6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> buffer6(size6);
    if (GetExtendedTcpTable(buffer6.data(), &size6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        PMIB_TCP6TABLE_OWNER_PID pTcp6Table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer6.data());
        IN6_ADDR targetIp6;
        if (inet_pton(AF_INET6, remoteIp.c_str(), &targetIp6) == 1) {
            for (DWORD i = 0; i < pTcp6Table->dwNumEntries; i++) {
                if (pTcp6Table->table[i].dwOwningPid == pid && memcmp(pTcp6Table->table[i].ucRemoteAddr, targetIp6.s6_addr, 16) == 0) {
                    MIB_TCP6ROW row;
                    row.dwState = MIB_TCP_STATE_DELETE;
                    memcpy(row.ucLocalAddr, pTcp6Table->table[i].ucLocalAddr, 16);
                    row.dwLocalScopeId = pTcp6Table->table[i].dwLocalScopeId;
                    row.dwLocalPort = pTcp6Table->table[i].dwLocalPort;
                    memcpy(row.ucRemoteAddr, pTcp6Table->table[i].ucRemoteAddr, 16);
                    row.dwRemoteScopeId = pTcp6Table->table[i].dwRemoteScopeId;
                    row.dwRemotePort = pTcp6Table->table[i].dwRemotePort;
                    
                    if (SetTcp6Entry(&row) == NO_ERROR) {
                        connectionKilled = true;
                        Logger::Instance().LogThreat(TDS_SEVERITY_INFO, CAT_PROCESS_BEHAVIOR, "IPS: IPv6 TCP Connection forcefully reset", remoteIp, pid);
                    }
                }
            }
        }
    }

    return connectionKilled;
}

} // namespace TDS
