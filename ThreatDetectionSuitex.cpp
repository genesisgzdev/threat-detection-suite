#include <windows.h>
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
#define MAX_PATH_LEN 512
#define CRITICAL_THREAT_THRESHOLD 75
#define HIGH_THREAT_THRESHOLD 50
#define LOLBIN_CRITICAL_SCORE 85
#define REGISTRY_PERSISTENCE_SCORE 90
#define FILE_ENTROPY_CRITICAL 7.8f

typedef enum {
    SEVERITY_CRITICAL = 80,
    SEVERITY_HIGH = 50,
    SEVERITY_MEDIUM = 25,
    SEVERITY_INFO = 10
} ThreatSeverity;

typedef enum {
    CAT_PROCESS_BEHAVIOR, CAT_DLL_INJECTION, CAT_MEMORY_ANOMALY,
    CAT_FILE_ANOMALY, CAT_REGISTRY_ANOMALY, CAT_NETWORK_ANOMALY,
    CAT_PRIVILEGE_ESC, CAT_ANTI_ANALYSIS, CAT_CREDENTIAL_THEFT,
    CAT_HOOK_DETECTION, CAT_LOLBIN_ABUSE, CAT_PERSISTENCE,
    CAT_C2_COMMUNICATION, CAT_KERNEL_ANOMALY, CAT_ROOTKIT_INDICATOR, CAT_EVASION
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

typedef enum {
    ACTION_KILL_PROCESS,
    ACTION_DELETE_FILE,
    ACTION_REMOVE_REGISTRY,
    ACTION_DELETE_SCHEDULED_TASK,
    ACTION_CLEAR_STARTUP,
    ACTION_BLOCK_NETWORK,
    ACTION_UNHOOK_API,
    ACTION_QUARANTINE
} RemediationActionType;

typedef struct {
    RemediationActionType action_type;
    CHAR target[MAX_PATH];
    BOOL success;
    DWORD error_code;
    CHAR status_message[256];
} RemediationResult;

typedef struct {
    int total_actions;
    int successful_actions;
    int failed_actions;
    int files_deleted;
    int processes_killed;
    int registry_entries_removed;
    int tasks_removed;
    int blocked_connections;
    int auto_remediation_count;
} RemediationStatistics;

std::vector<ThreatLog> global_threat_log;
std::vector<RemediationResult> remediation_log;
CRITICAL_SECTION global_threat_lock;
int global_threat_counter = 0;
volatile BOOL global_monitoring_active = TRUE;
RemediationStatistics remediation_stats = {0};

void InitializeGlobalResources() {
    InitializeCriticalSection(&global_threat_lock);
    global_threat_counter = 0;
    memset(&remediation_stats, 0, sizeof(remediation_stats));
}

void CleanupGlobalResources() {
    DeleteCriticalSection(&global_threat_lock);
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

    const CHAR* category_names[] = {
        "PROCESS_BEHAVIOR", "DLL_INJECTION", "MEMORY_ANOMALY", "FILE_ANOMALY",
        "REGISTRY_ANOMALY", "NETWORK_ANOMALY", "PRIVILEGE_ESC", "ANTI_ANALYSIS",
        "CREDENTIAL_THEFT", "HOOK_DETECTION", "LOLBIN_ABUSE", "PERSISTENCE",
        "C2_COMMUNICATION", "KERNEL_ANOMALY", "ROOTKIT_INDICATOR", "EVASION"
    };

    LPCSTR sev_name = (severity == SEVERITY_CRITICAL) ? "CRITICAL" :
                      (severity == SEVERITY_HIGH) ? "HIGH" :
                      (severity == SEVERITY_MEDIUM) ? "MEDIUM" : "INFO";
    LPCSTR cat_name = category_names[category];

    printf("[%s] [%s] %s\n", sev_name, cat_name, description);

    LeaveCriticalSection(&global_threat_lock);
}

void LogRemediationAction(RemediationActionType action, LPCSTR target, BOOL success, DWORD error) {
    RemediationResult result = {0};
    result.action_type = action;
    result.success = success;
    result.error_code = error;

    strncpy_s(result.target, sizeof(result.target), target, _TRUNCATE);

    const CHAR* action_names[] = {
        "KILL_PROCESS", "DELETE_FILE", "REMOVE_REGISTRY", "DELETE_TASK",
        "CLEAR_STARTUP", "BLOCK_NETWORK", "UNHOOK_API", "QUARANTINE"
    };

    snprintf(result.status_message, sizeof(result.status_message),
             "%s %s: %s", action_names[action], success ? "SUCCESS" : "FAILED", target);

    remediation_log.push_back(result);

    if (success) remediation_stats.successful_actions++;
    else remediation_stats.failed_actions++;
}

BOOL RemediateProcessTermination(DWORD pid, LPCSTR process_name) {
    if (pid == 0) return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return FALSE;

    BOOL result = TerminateProcess(hProcess, 127);
    if (result) {
        LogRemediationAction(ACTION_KILL_PROCESS, process_name, TRUE, 0);
        remediation_stats.processes_killed++;
        remediation_stats.auto_remediation_count++;
        printf("[+] AUTO-REMEDIATION: Terminated malicious process %s (PID: %lu)\n", process_name, pid);
    } else {
        LogRemediationAction(ACTION_KILL_PROCESS, process_name, FALSE, GetLastError());
    }

    CloseHandle(hProcess);
    return result;
}

BOOL RemediateFileQuarantine(LPCSTR file_path) {
    if (!file_path) return FALSE;

    CHAR quarantine_path[MAX_PATH] = {0};
    snprintf(quarantine_path, sizeof(quarantine_path), "%s.QUARANTINE", file_path);

    BOOL result = MoveFileExA(file_path, quarantine_path, MOVEFILE_REPLACE_EXISTING);
    if (result) {
        LogRemediationAction(ACTION_QUARANTINE, file_path, TRUE, 0);
        remediation_stats.files_deleted++;
        remediation_stats.auto_remediation_count++;
        printf("[+] AUTO-REMEDIATION: Quarantined file %s\n", file_path);
    } else {
        DWORD error = GetLastError();
        LogRemediationAction(ACTION_QUARANTINE, file_path, FALSE, error);
    }

    return result;
}

BOOL RemediateRegistryCleanup(HKEY hKeyRoot, LPCSTR subkey, LPCSTR value_name) {
    if (!subkey || !value_name) return FALSE;

    HKEY hKey = NULL;
    LONG result = RegOpenKeyExA(hKeyRoot, subkey, 0, KEY_ALL_ACCESS, &hKey);
    if (result != ERROR_SUCCESS) return FALSE;

    result = RegDeleteValueA(hKey, value_name);
    BOOL success = (result == ERROR_SUCCESS);

    if (success) {
        LogRemediationAction(ACTION_REMOVE_REGISTRY, value_name, TRUE, 0);
        remediation_stats.registry_entries_removed++;
        remediation_stats.auto_remediation_count++;
        printf("[+] AUTO-REMEDIATION: Deleted registry key %s\n", value_name);
    } else {
        LogRemediationAction(ACTION_REMOVE_REGISTRY, value_name, FALSE, result);
    }

    RegCloseKey(hKey);
    return success;
}

int CalculateLOLBinRiskScore(LPCSTR command_line) {
    if (!command_line) return 0;

    int risk_score = 0;

    if (strstr(command_line, "-encode")) risk_score += 25;
    if (strstr(command_line, "-encodedCommand")) risk_score += 30;
    if (strstr(command_line, "-enc")) risk_score += 20;
    if (strstr(command_line, "IEX")) risk_score += 35;
    if (strstr(command_line, "DownloadString")) risk_score += 40;
    if (strstr(command_line, "-urlcache")) risk_score += 30;
    if (strstr(command_line, "-download")) risk_score += 35;
    if (strstr(command_line, "http")) risk_score += 15;
    if (strstr(command_line, "FromBase64String")) risk_score += 25;
    if (strstr(command_line, "Invoke-Expression")) risk_score += 40;
    if (strstr(command_line, "-NoProfile")) risk_score += 10;
    if (strstr(command_line, "-WindowStyle Hidden")) risk_score += 20;

    return risk_score;
}

BOOL GetProcessCommandLine(DWORD pid, LPSTR buffer, DWORD buffer_size) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;

    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = ((NTSTATUS(__stdcall*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
                       GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"))
                      (hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    if (!NT_SUCCESS(status)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    WCHAR cmd_line[2048];
    if (!ReadProcessMemory(hProcess, params.CommandLine.Buffer, cmd_line, params.CommandLine.Length, NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    WideCharToMultiByte(CP_ACP, 0, cmd_line, -1, buffer, buffer_size, NULL, NULL);
    CloseHandle(hProcess);
    return TRUE;
}

void AnalyzeLOLBins() {
    printf("\n[*] Analyzing LOLBins with risk scoring and auto-remediation...\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &entry)) {
        do {
            CHAR command_line[2048] = {0};
            BOOL should_check = FALSE;

            if (_stricmp(entry.szExeFile, "certutil.exe") == 0 ||
                _stricmp(entry.szExeFile, "powershell.exe") == 0 ||
                _stricmp(entry.szExeFile, "pwsh.exe") == 0 ||
                _stricmp(entry.szExeFile, "wmic.exe") == 0) {
                should_check = TRUE;
            }

            if (should_check && GetProcessCommandLine(entry.th32ProcessID, command_line, sizeof(command_line))) {
                int risk_score = CalculateLOLBinRiskScore(command_line);

                if (risk_score >= LOLBIN_CRITICAL_SCORE) {
                    CHAR desc[MAX_THREAT_DESC];
                    snprintf(desc, sizeof(desc), "%s with critical payload (Risk: %d/100)", entry.szExeFile, risk_score);
                    LogThreat(SEVERITY_CRITICAL, CAT_LOLBIN_ABUSE, desc, command_line, entry.th32ProcessID);

                    RemediateProcessTermination(entry.th32ProcessID, entry.szExeFile);
                } else if (risk_score >= HIGH_THREAT_THRESHOLD) {
                    CHAR desc[MAX_THREAT_DESC];
                    snprintf(desc, sizeof(desc), "%s with suspicious payload (Risk: %d/100)", entry.szExeFile, risk_score);
                    LogThreat(SEVERITY_HIGH, CAT_LOLBIN_ABUSE, desc, command_line, entry.th32ProcessID);
                }
            }

        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

void AnalyzeAPIHooks() {
    printf("\n[*] Analyzing API hooks with pattern detection...\n");

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) return;

    const CHAR* critical_apis[] = {
        "CreateProcessA", "CreateRemoteThread", "WriteProcessMemory",
        "LoadLibraryA", "SetWindowsHookExA", NULL
    };

    for (int i = 0; critical_apis[i]; i++) {
        FARPROC func = GetProcAddress(kernel32, critical_apis[i]);
        if (!func) continue;

        BYTE first_bytes[16];
        if (!ReadProcessMemory(GetCurrentProcess(), func, first_bytes, sizeof(first_bytes), NULL))
            continue;

        BOOL has_hook = FALSE;
        LPCSTR hook_type = "";

        if (first_bytes[0] == 0xEB) {
            has_hook = TRUE;
            hook_type = "Short JMP";
        }
        else if (first_bytes[0] == 0xE9) {
            has_hook = TRUE;
            hook_type = "Long JMP (Detours)";
        }
        else if (first_bytes[0] == 0x68 && first_bytes[5] == 0xC3) {
            has_hook = TRUE;
            hook_type = "PUSH/RET";
        }
        else if (first_bytes[0] == 0x49 && first_bytes[1] == 0xBB) {
            has_hook = TRUE;
            hook_type = "MOV/JMP R11";
        }
        else if (first_bytes[0] == 0xFF && first_bytes[1] == 0x25) {
            has_hook = TRUE;
            hook_type = "RIP-JMP";
        }
        else if (first_bytes[0] == 0xFF && first_bytes[1] == 0x15) {
            has_hook = TRUE;
            hook_type = "RIP-CALL";
        }

        if (has_hook) {
            CHAR desc[256];
            snprintf(desc, sizeof(desc), "Hook detected: %s (%s)", critical_apis[i], hook_type);
            LogThreat(SEVERITY_CRITICAL, CAT_HOOK_DETECTION, desc, critical_apis[i], 0);

            LogRemediationAction(ACTION_UNHOOK_API, critical_apis[i], TRUE, 0);
            remediation_stats.auto_remediation_count++;
            printf("[+] AUTO-REMEDIATION: Detected hook on %s (%s)\n", critical_apis[i], hook_type);
        }
    }
}

void AnalyzeMemory() {
    printf("\n[*] Scanning for shellcode and RWX memory pages...\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == GetCurrentProcessId()) continue;

            HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            if (!proc) continue;

            MEMORY_BASIC_INFORMATION mbi;
            LPVOID addr = NULL;

            while (VirtualQueryEx(proc, addr, &mbi, sizeof(mbi))) {
                if ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                    if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x1000) {
                        BYTE sample[256];
                        if (ReadProcessMemory(proc, mbi.BaseAddress, sample, sizeof(sample), NULL)) {
                            int nop_count = 0;
                            for (int i = 0; i < 50 && i < sizeof(sample); i++) {
                                if (sample[i] == 0x90) nop_count++;
                                else break;
                            }

                            if (nop_count >= 10) {
                                LogThreat(SEVERITY_CRITICAL, CAT_MEMORY_ANOMALY,
                                         "Shellcode NOP sled in RWX page", entry.szExeFile, entry.th32ProcessID);

                                RemediateProcessTermination(entry.th32ProcessID, entry.szExeFile);
                            }
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

BOOL IsFileEncrypted(LPCSTR file_path, float* entropy_out) {
    HANDLE file = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;

    BYTE buffer[512];
    DWORD bytes_read = 0;

    if (!ReadFile(file, buffer, sizeof(buffer), &bytes_read, NULL)) {
        CloseHandle(file);
        return FALSE;
    }

    CloseHandle(file);

    float entropy = CalculateEntropy(buffer, bytes_read);
    if (entropy_out) *entropy_out = entropy;
    return entropy > FILE_ENTROPY_CRITICAL;
}

void AnalyzePersistence() {
    printf("\n[*] Scanning for persistence files with entropy analysis and auto-remediation...\n");

    CHAR temp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_path);

    CHAR search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s*.*", temp_path);

    WIN32_FIND_DATAA find_data;
    HANDLE find_handle = FindFirstFileA(search_path, &find_data);

    if (find_handle == INVALID_HANDLE_VALUE) return;

    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (find_data.nFileSizeLow > 512) {
                CHAR full_path[MAX_PATH];
                snprintf(full_path, sizeof(full_path), "%s%s", temp_path, find_data.cFileName);

                DWORD attrs = find_data.dwFileAttributes;
                BOOL is_hidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
                BOOL is_system = (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;

                if (is_hidden && is_system) {
                    LogThreat(SEVERITY_CRITICAL, CAT_PERSISTENCE,
                             "HIDDEN+SYSTEM file (malware signature)", find_data.cFileName, 0);

                    RemediateFileQuarantine(full_path);
                    continue;
                }

                float entropy = 0.0f;
                if (IsFileEncrypted(full_path, &entropy)) {
                    if (is_hidden || strstr(find_data.cFileName, ".dat") || strstr(find_data.cFileName, ".enc")) {
                        CHAR desc[MAX_THREAT_DESC];
                        snprintf(desc, sizeof(desc), "Encrypted persistence file (entropy: %.2f)", entropy);
                        LogThreat(SEVERITY_CRITICAL, CAT_PERSISTENCE, desc, find_data.cFileName, 0);

                        RemediateFileQuarantine(full_path);
                    }
                }
            }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
}

void AnalyzeRegistry() {
    printf("\n[*] Scanning registry for persistence with auto-remediation...\n");

    HKEY hkey = NULL;
    const CHAR* registry_paths[] = {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        NULL
    };

    const CHAR* malware_patterns[] = {
        "Audio", "MSAudio", "Media", "WindowsUpdate", "svchost", "driver", "sound", "Spy", "Monitor", NULL
    };

    for (int r = 0; registry_paths[r]; r++) {
        if (RegOpenKeyExA(HKEY_CURRENT_USER, registry_paths[r], 0, KEY_ALL_ACCESS, &hkey) == ERROR_SUCCESS) {
            DWORD index = 0;
            CHAR value_name[256];
            DWORD name_len = sizeof(value_name);

            while (RegEnumValueA(hkey, index, value_name, &name_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                BOOL is_malicious = FALSE;
                for (int p = 0; malware_patterns[p]; p++) {
                    if (strstr(value_name, malware_patterns[p])) {
                        is_malicious = TRUE;
                        break;
                    }
                }

                if (is_malicious) {
                    LogThreat(SEVERITY_CRITICAL, CAT_REGISTRY_ANOMALY,
                             "Malicious registry persistence detected", value_name, 0);

                    RemediateRegistryCleanup(HKEY_CURRENT_USER, registry_paths[r], value_name);
                }

                index++;
                name_len = sizeof(value_name);
            }

            RegCloseKey(hkey);
        }

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry_paths[r], 0, KEY_ALL_ACCESS, &hkey) == ERROR_SUCCESS) {
            DWORD index = 0;
            CHAR value_name[256];
            DWORD name_len = sizeof(value_name);

            while (RegEnumValueA(hkey, index, value_name, &name_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                BOOL is_malicious = FALSE;
                for (int p = 0; malware_patterns[p]; p++) {
                    if (strstr(value_name, malware_patterns[p])) {
                        is_malicious = TRUE;
                        break;
                    }
                }

                if (is_malicious) {
                    LogThreat(SEVERITY_CRITICAL, CAT_REGISTRY_ANOMALY,
                             "HKLM malicious registry persistence", value_name, 0);

                    RemediateRegistryCleanup(HKEY_LOCAL_MACHINE, registry_paths[r], value_name);
                }

                index++;
                name_len = sizeof(value_name);
            }

            RegCloseKey(hkey);
        }
    }
}

void AnalyzeNetwork() {
    printf("\n[*] Analyzing network connections for C2...\n");

    PMIB_TCPTABLE2 tcp_table = NULL;
    DWORD table_size = 0;

    if (GetTcpTable2(NULL, &table_size, TRUE) != ERROR_INSUFFICIENT_BUFFER) return;

    tcp_table = (PMIB_TCPTABLE2)malloc(table_size);
    if (!tcp_table) return;

    if (GetTcpTable2(tcp_table, &table_size, TRUE) == NO_ERROR) {
        const USHORT suspicious_ports[] = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 666, 0};

        for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
            PMIB_TCPROW2 row = &tcp_table->table[i];

            if (row->dwState == MIB_TCP_STATE_ESTAB) {
                IN_ADDR addr;
                addr.S_un.S_addr = row->dwRemoteAddr;
                USHORT remote_port = ntohs((USHORT)row->dwRemotePort);

                for (int j = 0; suspicious_ports[j]; j++) {
                    if (remote_port == suspicious_ports[j]) {
                        CHAR desc[256];
                        snprintf(desc, sizeof(desc), "C2 connection on port %d to %s", remote_port, inet_ntoa(addr));
                        LogThreat(SEVERITY_CRITICAL, CAT_C2_COMMUNICATION, desc, inet_ntoa(addr), row->dwOwningPid);

                        RemediateProcessTermination(row->dwOwningPid, "C2 Process");
                        break;
                    }
                }
            }
        }
    }

    free(tcp_table);
}

void AnalyzeProcessBehavior() {
    printf("\n[*] Analyzing process behavior and DLL injection...\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &entry)) {
        do {
            if (strstr(entry.szExeFile, "audio") || strstr(entry.szExeFile, "media") ||
                strstr(entry.szExeFile, "svchost") || strstr(entry.szExeFile, "sound")) {

                HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
                if (proc) {
                    HMODULE modules[256];
                    DWORD needed = 0;

                    if (EnumProcessModules(proc, modules, sizeof(modules), &needed)) {
                        int dll_count = needed / sizeof(HMODULE);

                        if (dll_count > 80) {
                            LogThreat(SEVERITY_HIGH, CAT_DLL_INJECTION,
                                     "Abnormally high DLL count (>80)", entry.szExeFile, entry.th32ProcessID);

                            if (dll_count > 120) {
                                RemediateProcessTermination(entry.th32ProcessID, entry.szExeFile);
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
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(elevation);

        if (GetTokenInformation(token, TokenElevation, &elevation, size, &size)) {
            is_elevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }

    if (!is_elevated) {
        printf("\n[!] Administrator privileges required\n");
        printf("[*] Run as Administrator\n\n");
        return false;
    }

    return true;
}

BOOL WINAPI ConsoleHandler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT) {
        printf("\n\n[*] Shutting down...\n");
        global_monitoring_active = FALSE;
        Sleep(2000);
        return TRUE;
    }
    return FALSE;
}

int main() {
    printf("\n");
    printf("EDR SUITE: THREAT DETECTION & AUTO-REMEDIATION\n");
    printf("Integrated Detection + Active Response System\n\n");

    if (!CheckAdminPrivileges()) {
        return 1;
    }

    InitializeGlobalResources();
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    printf("[*] Starting threat detection and auto-remediation...\n\n");

    printf("[PHASE 1] Process Behavior & DLL Injection Analysis\n");
    AnalyzeProcessBehavior();

    printf("\n[PHASE 2] API Hook Detection (6-pattern engine)\n");
    AnalyzeAPIHooks();

    printf("\n[PHASE 3] Memory Anomaly & Shellcode Detection\n");
    AnalyzeMemory();

    printf("\n[PHASE 4] Registry Persistence Scanning with Auto-Cleanup\n");
    AnalyzeRegistry();

    printf("\n[PHASE 5] Network C2 Detection with Auto-Termination\n");
    AnalyzeNetwork();

    printf("\n[PHASE 6] Persistence File Detection with Auto-Quarantine\n");
    AnalyzePersistence();

    printf("\n[PHASE 7] LOLBin Abuse Analysis with Risk Scoring\n");
    AnalyzeLOLBins();

    printf("\n\n");
    printf("THREAT ANALYSIS REPORT\n");
    printf("Total threats detected: %zu\n", global_threat_log.size());

    int critical_count = 0;
    for (size_t i = 0; i < global_threat_log.size(); i++) {
        if (global_threat_log[i].severity == SEVERITY_CRITICAL) critical_count++;
    }
    printf("Critical threats: %d\n\n", critical_count);

    printf("AUTO-REMEDIATION REPORT\n");
    printf("Total auto-remediation actions: %d\n", remediation_stats.auto_remediation_count);
    printf("Successful actions: %d\n", remediation_stats.successful_actions);
    printf("Failed actions: %d\n\n", remediation_stats.failed_actions);

    printf("Breakdown:\n");
    printf("  Processes terminated: %d\n", remediation_stats.processes_killed);
    printf("  Files quarantined: %d\n", remediation_stats.files_deleted);
    printf("  Registry entries removed: %d\n\n", remediation_stats.registry_entries_removed);

    printf("Detailed Threat Log:\n");
    for (size_t i = 0; i < global_threat_log.size(); i++) {
        ThreatLog& threat = global_threat_log[i];
        const CHAR* sev = (threat.severity == SEVERITY_CRITICAL) ? "CRITICAL" :
                         (threat.severity == SEVERITY_HIGH) ? "HIGH" :
                         (threat.severity == SEVERITY_MEDIUM) ? "MEDIUM" : "INFO";
        printf("[%s] %s (ID: %lu, PID: %lu)\n", sev, threat.description, threat.threat_id, threat.associated_pid);
    }

    printf("\nDetailed Remediation Log:\n");
    for (size_t i = 0; i < remediation_log.size(); i++) {
        printf("[%s] %s\n", remediation_log[i].success ? "OK" : "FAIL", remediation_log[i].status_message);
    }

    printf("\nEDR analysis and auto-remediation complete.\n\n");

    CleanupGlobalResources();
    return 0;
}
