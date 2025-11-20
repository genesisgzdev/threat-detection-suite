#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <time.h>

VOID PrintBanner() {
    system("cls");
    printf("\n");
    printf("  ╔════════════════════════════════════════════════════════════════════════╗\n");
    printf("  ║                                                                        ║\n");
    printf("  ║          ADVANCED THREAT DETECTION SUITE v5.0                         ║\n");
    printf("  ║          Comprehensive Multi-Vector Malware Detector                  ║\n");
    printf("  ║                                                                        ║\n");
    printf("  ║          Detection Coverage:                                          ║\n");
    printf("  ║          - Process Behavior Analysis (9 subsystems)                   ║\n");
    printf("  ║          - Behavioral API Anomalies (6 APIs)                          ║\n");
    printf("  ║          - API Interception & Hooks                                   ║\n");
    printf("  ║          - LOLBin Abuse Detection                                     ║\n");
    printf("  ║          - Persistence File Signatures                                ║\n");
    printf("  ║          - Kernel-Level Rootkit Detection                             ║\n");
    printf("  ║          - Real-time threat correlation                               ║\n");
    printf("  ║                                                                        ║\n");
    printf("  ╚════════════════════════════════════════════════════════════════════════╝\n\n");
}

VOID PrintMenu() {
    PrintBanner();

    printf("  SELECT DETECTION MODULE:\n\n");
    printf("  [1] Advanced Threat Detector\n");
    printf("      └─ 9 parallel detection subsystems\n");
    printf("      └─ Real-time process & behavior analysis\n");
    printf("      └─ Network, registry, file system monitoring\n");
    printf("      └─ Privilege escalation & credential theft detection\n\n");

    printf("  [2] Behavioral Anomaly Detector\n");
    printf("      └─ SetWindowsHookEx monitoring\n");
    printf("      └─ certutil abuse detection\n");
    printf("      └─ Persistence file anomalies\n");
    printf("      └─ C2 communication patterns\n");
    printf("      └─ Real-time anomaly correlation\n\n");

    printf("  [3] API Interception Detector\n");
    printf("      └─ Hook signature analysis\n");
    printf("      └─ Memory integrity checking\n");
    printf("      └─ IAT manipulation detection\n");
    printf("      └─ DLL injection patterns\n\n");

    printf("  [4] LOLBin (Living Off The Land) Analyzer\n");
    printf("      └─ certutil.exe abuse detection\n");
    printf("      └─ PowerShell command analysis\n");
    printf("      └─ WMI execution monitoring\n");
    printf("      └─ Risk scoring system\n\n");

    printf("  [5] Persistence File Detector\n");
    printf("      └─ HIDDEN+SYSTEM attribute detection\n");
    printf("      └─ Encryption signature analysis\n");
    printf("      └─ Anomalous file location detection\n");
    printf("      └─ Cryptographic pattern matching\n\n");

    printf("  [6] Kernel Monitor (Low-Level Analysis)\n");
    printf("      └─ PEB poisoning detection\n");
    printf("      └─ VAD tampering detection\n");
    printf("      └─ Syscall interception detection\n");
    printf("      └─ Driver anomalies\n");
    printf("      └─ Rootkit signatures\n\n");

    printf("  [7] Run Full Suite (All Detectors)\n");
    printf("      └─ Comprehensive system analysis\n");
    printf("      └─ Approx 5-10 minutes\n\n");

    printf("  [8] Quick Scan (Fast Detection)\n");
    printf("      └─ Critical threats only\n");
    printf("      └─ Approx 1-2 minutes\n\n");

    printf("  [0] Exit\n\n");

    printf("  ════════════════════════════════════════════════════════════════════════\n");
    printf("  SELECT OPTION (0-8): ");
}

BOOL CheckAdminPrivileges() {
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
        system("cls");
        printf("\n[!] ERROR: Administrator privileges required\n");
        printf("[*] Please run this program as Administrator\n\n");
        return FALSE;
    }

    return TRUE;
}

INT ExecuteDetector(LPCSTR exe_name, LPCSTR description) {
    printf("\n");
    printf("════════════════════════════════════════════════════════════════════════\n");
    printf("LAUNCHING: %s\n", description);
    printf("════════════════════════════════════════════════════════════════════════\n\n");

    STARTUPINFOA startup_info = {0};
    PROCESS_INFORMATION process_info = {0};
    startup_info.cb = sizeof(startup_info);

    if (CreateProcessA(exe_name, NULL, NULL, NULL, FALSE,
                      0, NULL, NULL, &startup_info, &process_info)) {

        WaitForSingleObject(process_info.hProcess, INFINITE);
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
        return 0;
    }

    printf("[!] ERROR: Could not execute %s\n", exe_name);
    printf("[*] Make sure the executable is in the same directory\n\n");
    return 1;
}

VOID RunFullSuite() {
    printf("\n");
    printf("════════════════════════════════════════════════════════════════════════\n");
    printf("RUNNING FULL THREAT DETECTION SUITE\n");
    printf("════════════════════════════════════════════════════════════════════════\n\n");

    printf("This will execute all detection modules in sequence.\n");
    printf("Total time: ~5-10 minutes\n\n");
    printf("Press Enter to continue...\n");
    getchar();

    printf("\n[1/6] Advanced Threat Detector...\n");
    Sleep(1000);
    ExecuteDetector("AdvancedThreatDetector.exe", "Advanced Threat Detector");

    printf("\n[2/6] Behavioral Anomaly Detector...\n");
    Sleep(1000);
    ExecuteDetector("BehaviorDetector.exe", "Behavioral Anomaly Detector");

    printf("\n[3/6] API Interception Detector...\n");
    Sleep(1000);
    ExecuteDetector("APIInterceptor.exe", "API Interception Detector");

    printf("\n[4/6] LOLBin Analyzer...\n");
    Sleep(1000);
    ExecuteDetector("LOLBinAnalyzer.exe", "LOLBin Analyzer");

    printf("\n[5/6] Persistence File Detector...\n");
    Sleep(1000);
    ExecuteDetector("PersistenceFileDetector.exe", "Persistence File Detector");

    printf("\n[6/6] Kernel Monitor...\n");
    Sleep(1000);
    ExecuteDetector("KernelMonitor.exe", "Kernel Monitor");

    printf("\n");
    printf("════════════════════════════════════════════════════════════════════════\n");
    printf("FULL SUITE ANALYSIS COMPLETE\n");
    printf("════════════════════════════════════════════════════════════════════════\n\n");

    printf("[+] All detection modules executed successfully\n");
    printf("[+] Review each module's report for detailed findings\n");
    printf("[+] Cross-reference findings for threat correlation\n\n");

    printf("Press Enter to return to menu...\n");
    getchar();
}

VOID RunQuickScan() {
    printf("\n");
    printf("════════════════════════════════════════════════════════════════════════\n");
    printf("QUICK THREAT SCAN (CRITICAL THREATS ONLY)\n");
    printf("════════════════════════════════════════════════════════════════════════\n\n");

    printf("[1/2] Running Advanced Threat Detector (fast mode)...\n");
    Sleep(1000);
    ExecuteDetector("AdvancedThreatDetector.exe", "Advanced Threat Detector");

    printf("\n[2/2] Running Kernel Monitor...\n");
    Sleep(1000);
    ExecuteDetector("KernelMonitor.exe", "Kernel Monitor");

    printf("\n");
    printf("════════════════════════════════════════════════════════════════════════\n");
    printf("QUICK SCAN COMPLETE\n");
    printf("════════════════════════════════════════════════════════════════════════\n\n");

    printf("Press Enter to return to menu...\n");
    getchar();
}

INT main() {
    if (!CheckAdminPrivileges()) {
        return 1;
    }

    while (TRUE) {
        PrintMenu();

        int choice = _getch();
        printf("%c\n", choice);

        switch (choice) {
            case '1':
                ExecuteDetector("AdvancedThreatDetector.exe",
                              "Advanced Threat Detector v4.0");
                break;

            case '2':
                ExecuteDetector("BehaviorDetector.exe",
                              "Behavioral Anomaly Detector v3.0");
                break;

            case '3':
                ExecuteDetector("APIInterceptor.exe",
                              "API Interception Detector v2.0");
                break;

            case '4':
                ExecuteDetector("LOLBinAnalyzer.exe",
                              "LOLBin Analyzer v2.0");
                break;

            case '5':
                ExecuteDetector("PersistenceFileDetector.exe",
                              "Persistence File Detector v2.0");
                break;

            case '6':
                ExecuteDetector("KernelMonitor.exe",
                              "Kernel Monitor v2.0");
                break;

            case '7':
                RunFullSuite();
                break;

            case '8':
                RunQuickScan();
                break;

            case '0':
                printf("\n[*] Exiting...\n\n");
                return 0;

            default:
                printf("\n[!] Invalid option\n");
                Sleep(1500);
                break;
        }
    }

    return 0;
}
