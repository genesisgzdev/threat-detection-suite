#include.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <map>
#include <vector>
#include <algorithm>
#include <shlobj.h>
#include <winternl.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cmath>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")

#define MAX_THREAT_DESC 512
#define MAX_IOC_LEN 256
#define CRITICAL_THREAT_THRESHOLD 75
#define HIGH_THREAT_THRESHOLD 50

typedef enum {
    SEVERITY_CRITICAL = 80,
    SEVERITY_HIGH = 50,
    SEVERITY_MEDIUM = 25,
    SEVERITY_INFO = 10
} ThreatSeverity;

typedef enum {
    CAT_PROCESS, CAT_DLL_INJECTION, CAT_MEMORY, CAT_FILE,
    CAT_REGISTRY, CAT_NETWORK, CAT_PRIVILEGE_ESC, CAT_ANTI_ANALYSIS,
    CAT_CREDENTIALS, CAT_HOOK, CAT_LOLBIN, CAT_PERSISTENCE,
    CAT_C2, CAT_KERNEL, CAT_ROOTKIT, CAT_EVASION
} ThreatCategory;

typedef struct {
    DWORD threat_id;
    ThreatSeverity severity;
    ThreatCategory category;
    CHAR description[MAX_THREAT_DESC];
    CHAR ioc[MAX_IOC_LEN];
    time_t timestamp;
    DWORD associated_pid;
} ThreatLog;

std::vector<ThreatLog> global_threat_log;
CRITICAL_SECTION global_threat_lock;
int global_threat_counter = 0;
volatile BOOL global_monitoring_active = TRUE;

void InitializeGlobalResources() {
    InitializeCriticalSection(&global_threat_lock);
    global_threat_counter = 0;
}

void CleanupGlobalResources() {
    DeleteCriticalSection(&global_threat_lock);
}

LPCSTR GetCategoryName(ThreatCategory cat) {
    static const CHAR* names[] = {
        "PROCESS", "DLL_INJECTION", "MEMORY", "FILE", "REGISTRY", "NETWORK",
        "PRIVILEGE_ESC", "ANTI_ANALYSIS", "CREDENTIALS", "HOOK", "LOLBIN",
        "PERSISTENCE", "C2", "KERNEL", "ROOTKIT", "EVASION"
    };
    return names[cat];
}

LPCSTR GetSeverityName(ThreatSeverity sev) {
    if (sev == SEVERITY_CRITICAL) return "CRITICAL";
    if (sev == SEVERITY_HIGH) return "HIGH";
    if (sev == SEVERITY_MEDIUM) return "MEDIUM";
    return "INFO";
}

void LogThreat(ThreatSeverity severity, ThreatCategory category,
               LPCSTR description, LPCSTR ioc, DWORD pid) {
    EnterCriticalSection(&global_threat_lock);

    ThreatLog threat;
    threat.threat_id = global_threat_counter++;
    threat.severity = severity;
    threat.category = category;
    threat.timestamp = time(NULL);
    threat.associated_pid = pid;

    strncpy_s(threat.description, sizeof(threat.description), description, _TRUNCATE);
    strncpy_s(threat.ioc, sizeof(threat.ioc), ioc, _TRUNCATE);

    global_threat_log.push_back(threat);

    printf("[%s] [%s] %s\n", GetSeverityName(severity), GetCategoryName(category), description);

    LeaveCriticalSection(&global_threat_lock);
}

typedef NTSTATUS(__stdcall *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

BOOL GetProcessCommandLine(DWORD pid, LPSTR buffer, DWORD buffer_size) {
    if (!buffer || buffer_size == 0) return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        CloseHandle(hProcess);
        return FALSE;
    }

    PROCESS_BASIC_INFORMATION pbi = {0};
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    if (!NT_SUCCESS(status)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    PEB peb = {0};
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    RTL_USER_PROCESS_PARAMETERS params = {0};
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    WCHAR cmd_line[2048] = {0};
    if (!ReadProcessMemory(hProcess, params.CommandLine.Buffer, cmd_line, min(params.CommandLine.Length, sizeof(cmd_line) - 2), NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    WideCharToMultiByte(CP_ACP, 0, cmd_line, -1, buffer, buffer_size, NULL, NULL);
    CloseHandle(hProcess);
    return TRUE;
}

void ScanLOLBins() {
    printf("\n[*] Scanning Living-of-the-Land binaries\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 entry = {sizeof(PROCESSENTRY32)};

    if (Process32First(snapshot, &entry)) {
        do {
            CHAR cmdline[2048] = {0};
            BOOL should_check = FALSE;

            if (_stricmp(entry.szExeFile, "certutil.exe") == 0 ||
                _stricmp(entry.szExeFile, "wmic.exe") == 0 ||
                strstr(entry.szExeFile, "powershell") != NULL) {
                should_check = TRUE;
            }

            if (should_check && GetProcessCommandLine(entry.th32ProcessID, cmdline, sizeof(cmdline))) {
                int risk_score = 0;

                if (strstr(cmdline, "-encode") || strstr(cmdline, "-decode")) risk_score += 30;
                if (strstr(cmdline, "-urlcache") || strstr(cmdline, "-download")) risk_score += 45;
                if (strstr(cmdline, "http://") || strstr(cmdline, "https://")) risk_score += 50;
                if (strstr(cmdline, "-enc") || strstr(cmdline, "-encodedCommand")) risk_score += 45;
                if (strstr(cmdline, "-nop") || strstr(cmdline, "-NoProfile")) risk_score += 30;
                if ((strstr(cmdline, "-w") && strstr(cmdline, "hidden")) ||
                    strstr(cmdline, "-WindowStyle") && strstr(cmdline, "Hidden")) risk_score += 40;
                if (strstr(cmdline, "IEX") || strstr(cmdline, "Invoke-Expression")) risk_score += 50;
                if (strstr(cmdline, "DownloadString") || strstr(cmdline, "FromBase64String")) risk_score += 60;
                if (strstr(cmdline, "process") && strstr(cmdline, "call")) risk_score += 50;

                if (risk_score > CRITICAL_THREAT_THRESHOLD) {
                    LogThreat(SEVERITY_CRITICAL, CAT_LOLBIN, entry.szExeFile, entry.szExeFile, entry.th32ProcessID);
                } else if (risk_score > HIGH_THREAT_THRESHOLD) {
                    LogThreat(SEVERITY_HIGH, CAT_LOLBIN, entry.szExeFile, entry.szExeFile, entry.th32ProcessID);
                }
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

void ScanAPIHooks() {
    printf("\n[*] Scanning for API hooks\n");

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) return;

    const CHAR* critical_apis[] = {
        "CreateProcessA", "CreateProcessW", "CreateRemoteThread", "WriteProcessMemory",
        "VirtualAllocEx", "VirtualProtect", "GetProcAddress", "LoadLibraryA",
        "LoadLibraryW", "SetWindowsHookExA", "SetWindowsHookExW", NULL
    };

    for (int i = 0; critical_apis[i]; i++) {
        FARPROC func = GetProcAddress(kernel32, critical_apis[i]);
        if (!func) continue;

        BYTE first_bytes[16] = {0};
        if (!ReadProcessMemory(GetCurrentProcess(), func, first_bytes, sizeof(first_bytes), NULL))
            continue;

        BOOL hook_detected = FALSE;

        if (first_bytes[0] == 0xEB || first_bytes[0] == 0xE9 ||
            (first_bytes[0] == 0x68 && first_bytes[5] == 0xC3) ||
            (first_bytes[0] == 0x49 && first_bytes[1] == 0xBB) ||
            (first_bytes[0] == 0xFF && first_bytes[1] == 0x25) ||
            (first_bytes[0] == 0xFF && first_bytes[1] == 0x15)) {
            hook_detected = TRUE;
        }

        if (hook_detected) {
            LogThreat(SEVERITY_CRITICAL, CAT_HOOK, critical_apis[i], critical_apis[i], 0);
        }
    }
}

void ScanMemoryAnomalies() {
    printf("\n[*] Scanning for memory anomalies\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 entry = {sizeof(PROCESSENTRY32)};

    if (Process32First(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == GetCurrentProcessId()) continue;

            HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            if (!proc) continue;

            MEMORY_BASIC_INFORMATION mbi = {0};
            LPVOID addr = NULL;

            while (VirtualQueryEx(proc, addr, &mbi, sizeof(mbi)) && mbi.RegionSize) {
                if ((mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_WRITECOPY) &&
                    mbi.State == MEM_COMMIT && mbi.RegionSize > 0x1000) {

                    BYTE sample[256] = {0};
                    DWORD bytes_read = 0;
                    if (ReadProcessMemory(proc, mbi.BaseAddress, sample, sizeof(sample), &bytes_read)) {
                        int nop_count = 0;
                        for (int i = 0; i < 50 && i < bytes_read; i++) {
                            if (sample[i] == 0x90) nop_count++;
                            else break;
                        }

                        if (nop_count >= 10) {
                            LogThreat(SEVERITY_CRITICAL, CAT_MEMORY, entry.szExeFile, entry.szExeFile, entry.th32ProcessID);
                        }
                    }
                }

                addr = (LPVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
                if (addr < mbi.BaseAddress) break;
            }

            CloseHandle(proc);
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

float CalculateEntropy(LPCVOID data, DWORD size) {
    if (!data || size < 16) return 0.0f;

    unsigned int freq[256] = {0};
    for (DWORD i = 0; i < size; i++) {
        freq[((BYTE*)data)[i]]++;
    }

    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / size;
            entropy -= p * log2f(p);
        }
    }

    return entropy;
}

BOOL IsFileEncrypted(LPCSTR file_path) {
    HANDLE file = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;

    BYTE buffer[512] = {0};
    DWORD bytes_read = 0;

    if (!ReadFile(file, buffer, sizeof(buffer), &bytes_read, NULL)) {
        CloseHandle(file);
        return FALSE;
    }

    CloseHandle(file);

    float entropy = CalculateEntropy(buffer, bytes_read);
    return entropy > 7.2f;
}

void ScanPersistenceFiles() {
    printf("\n[*] Scanning for persistence files\n");

    CHAR temp_path[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, temp_path);

    CHAR search_path[MAX_PATH] = {0};
    snprintf(search_path, sizeof(search_path), "%s*.*", temp_path);

    WIN32_FIND_DATAA find_data = {0};
    HANDLE find_handle = FindFirstFileA(search_path, &find_data);

    if (find_handle == INVALID_HANDLE_VALUE) return;

    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (find_data.nFileSizeLow > 512) {
                CHAR full_path[MAX_PATH] = {0};
                snprintf(full_path, sizeof(full_path), "%s%s", temp_path, find_data.cFileName);

                DWORD attrs = find_data.dwFileAttributes;
                BOOL is_hidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
                BOOL is_system = (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;

                if (is_hidden && is_system) {
                    LogThreat(SEVERITY_CRITICAL, CAT_PERSISTENCE, find_data.cFileName, full_path, 0);
                }

                if (IsFileEncrypted(full_path)) {
                    if (is_hidden || strstr(find_data.cFileName, ".dat") || strstr(find_data.cFileName, ".enc")) {
                        LogThreat(SEVERITY_CRITICAL, CAT_PERSISTENCE, find_data.cFileName, full_path, 0);
                    }
                }
            }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
}

void ScanRegistry() {
    printf("\n[*] Scanning registry\n");

    HKEY hkey = NULL;
    const CHAR* registry_paths[] = {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        NULL
    };

    for (int r = 0; registry_paths[r]; r++) {
        if (RegOpenKeyExA(HKEY_CURRENT_USER, registry_paths[r], 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
            DWORD index = 0;
            CHAR value_name[256] = {0};
            DWORD name_len = sizeof(value_name);
            BYTE value_data[1024] = {0};
            DWORD data_len = sizeof(value_data);

            while (RegEnumValueA(hkey, index, value_name, &name_len, NULL, NULL, value_data, &data_len) == ERROR_SUCCESS) {
                if (strstr(value_name, "Audio") || strstr(value_name, "MSAudio") ||
                    strstr(value_name, "Media") || strstr(value_name, "WindowsUpdate") ||
                    strstr(value_name, "svchost") || strstr(value_name, "driver")) {
                    LogThreat(SEVERITY_CRITICAL, CAT_REGISTRY, value_name, value_name, 0);
                }

                index++;
                name_len = sizeof(value_name);
                data_len = sizeof(value_data);
            }

            RegCloseKey(hkey);
        }

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry_paths[r], 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
            DWORD index = 0;
            CHAR value_name[256] = {0};
            DWORD name_len = sizeof(value_name);

            while (RegEnumValueA(hkey, index, value_name, &name_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                if (strstr(value_name, "Audio") || strstr(value_name, "MSAudio") ||
                    strstr(value_name, "Spy") || strstr(value_name, "Monitor")) {
                    LogThreat(SEVERITY_CRITICAL, CAT_REGISTRY, value_name, value_name, 0);
                }

                index++;
                name_len = sizeof(value_name);
            }

            RegCloseKey(hkey);
        }
    }
}

void ScanNetwork() {
    printf("\n[*] Scanning network connections\n");

    PMIB_TCPTABLE2 tcp_table = NULL;
    DWORD table_size = 0;

    if (GetTcpTable2(NULL, &table_size, TRUE) != ERROR_INSUFFICIENT_BUFFER) return;

    tcp_table = (PMIB_TCPTABLE2)malloc(table_size);
    if (!tcp_table) return;

    if (GetTcpTable2(tcp_table, &table_size, TRUE) == NO_ERROR) {
        const USHORT suspicious_ports[] = {
            4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 666, 1337, 8080, 8443, 0
        };

        for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
            PMIB_TCPROW2 row = &tcp_table->table[i];

            if (row->dwState == MIB_TCP_STATE_ESTAB) {
                IN_ADDR addr = {0};
                addr.S_un.S_addr = row->dwRemoteAddr;
                USHORT remote_port = ntohs((USHORT)row->dwRemotePort);

                for (int j = 0; suspicious_ports[j]; j++) {
                    if (remote_port == suspicious_ports[j]) {
                        LogThreat(SEVERITY_CRITICAL, CAT_C2, inet_ntoa(addr), inet_ntoa(addr), row->dwOwningPid);
                        break;
                    }
                }

                unsigned char first_octet = (unsigned char)(row->dwRemoteAddr & 0xFF);
                if ((first_octet == 192 || first_octet == 172 || first_octet == 10) &&
                    (remote_port > 10000 || remote_port < 1024)) {
                    LogThreat(SEVERITY_HIGH, CAT_C2, inet_ntoa(addr), inet_ntoa(addr), row->dwOwningPid);
                }
            }
        }
    }

    free(tcp_table);
}

void ScanProcessBehavior() {
    printf("\n[*] Scanning process behavior\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 entry = {sizeof(PROCESSENTRY32)};

    if (Process32First(snapshot, &entry)) {
        do {
            if (strstr(entry.szExeFile, "audio") || strstr(entry.szExeFile, "media") ||
                strstr(entry.szExeFile, "svchost") || strstr(entry.szExeFile, "sound")) {

                HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
                if (proc) {
                    HMODULE modules[512] = {0};
                    DWORD needed = 0;

                    if (EnumProcessModules(proc, modules, sizeof(modules), &needed)) {
                        int dll_count = needed / sizeof(HMODULE);

                        if (dll_count > 100) {
                            LogThreat(SEVERITY_HIGH, CAT_DLL_INJECTION, entry.szExeFile, entry.szExeFile, entry.th32ProcessID);
                        }

                        for (int i = 0; i < dll_count && i < 512; i++) {
                            CHAR dll_name[MAX_PATH] = {0};
                            if (GetModuleFileNameExA(proc, modules[i], dll_name, sizeof(dll_name))) {
                                if (strstr(dll_name, ".dat") || strstr(dll_name, ".enc") ||
                                    strstr(dll_name, ".tmp") || strstr(dll_name, "amsi")) {
                                    LogThreat(SEVERITY_CRITICAL, CAT_DLL_INJECTION, dll_name, dll_name, entry.th32ProcessID);
                                }
                            }
                        }
                    }

                    CloseHandle(proc);
                }
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

bool CheckAdminPrivileges() {
    BOOL is_elevated = FALSE;
    HANDLE token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation = {0};
        DWORD size = sizeof(elevation);

        if (GetTokenInformation(token, TokenElevation, &elevation, size, &size)) {
            is_elevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }

    if (!is_elevated) {
        printf("[!] Administrator privileges required\n");
        return false;
    }

    return true;
}

BOOL WINAPI ConsoleHandler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT) {
        printf("\n[*] Shutting down\n");
        global_monitoring_active = FALSE;
        Sleep(2000);
        return TRUE;
    }
    return FALSE;
}

int main() {
    if (!CheckAdminPrivileges()) {
        return 1;
    }

    InitializeGlobalResources();
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    printf("THREAT DETECTION SUITE v5.0\n\n");

    ScanProcessBehavior();
    ScanAPIHooks();
    ScanMemoryAnomalies();
    ScanRegistry();
    ScanNetwork();
    ScanPersistenceFiles();
    ScanLOLBins();

    printf("\n\nTHREAT ANALYSIS REPORT\n");
    printf("Total threats detected: %zu\n\n", global_threat_log.size());

    int critical_count = 0;
    for (size_t i = 0; i < global_threat_log.size(); i++) {
        if (global_threat_log[i].severity == SEVERITY_CRITICAL) critical_count++;
    }
    printf("Critical threats: %d\n", critical_count);

    printf("\nDetailed Log:\n");
    for (size_t i = 0; i < global_threat_log.size(); i++) {
        ThreatLog& threat = global_threat_log[i];
        printf("[%s] %s\n", GetSeverityName(threat.severity), threat.description);
    }

    CleanupGlobalResources();
    return 0;
}
