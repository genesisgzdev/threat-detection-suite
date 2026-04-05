#pragma once
#include <windows.h>
#include <string>

namespace TDS {

class IPSManager {
public:
    // Prevents Race Conditions by atomically suspending all threads of the process via NTAPI
    static bool ContainProcess(DWORD pid);
    
    // Forcefully kills the process after containment
    static bool TerminateMaliciousProcess(DWORD pid);
    
    // Null-routes specific C2 connections at the TCP stack level using extended APIs
    static bool TerminateNetworkConnection(DWORD pid, const std::string& remoteIp);
};

} // namespace TDS