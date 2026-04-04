#include "NetworkDetector.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../Logger.h"

#pragma comment(lib, "ws2_32.lib")

namespace TDS {

void NetworkDetector::ScanActiveConnections() {
    PMIB_TCPTABLE2 pTcpTable = nullptr;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    int retryCount = 0;
    do {
        dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE);
        if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
            if (pTcpTable) free(pTcpTable);
            pTcpTable = (PMIB_TCPTABLE2)malloc(dwSize);
            if (!pTcpTable) return;
        } else {
            break;
        }
        retryCount++;
    } while (dwRetVal != NO_ERROR && retryCount < 3);

    if (dwRetVal == NO_ERROR && pTcpTable) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            if (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
                USHORT remotePort = ntohs(static_cast<USHORT>(pTcpTable->table[i].dwRemotePort));
                if (IsSuspiciousPort(remotePort)) {
                    IN_ADDR addr;
                    addr.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
                    char ipStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
                    
                    std::string desc = "Suspicious C2 connection on port " + std::to_string(remotePort);
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_C2_COMMUNICATION, desc, ipStr, pTcpTable->table[i].dwOwningPid);
                }
            }
        }
    }

    if (pTcpTable) free(pTcpTable);
}

bool NetworkDetector::IsSuspiciousPort(USHORT port) {
    static const std::vector<USHORT> suspiciousPorts = {
        4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 666, 1337
    };
    for (USHORT p : suspiciousPorts) {
        if (port == p) return true;
    }
    return false;
}

} // namespace TDS
