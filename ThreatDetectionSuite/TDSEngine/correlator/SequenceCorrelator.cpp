#include <windows.h>
#include <map>
#include <vector>
#include <string>
#include <time.h>
#include <iostream>

struct EventInfo {
    int Type;
    time_t Timestamp;
    std::wstring Detail;
};

class SequenceCorrelator {
    std::map<DWORD, std::vector<EventInfo>> processEvents;
    const int TIME_WINDOW = 30; // 30 seconds window

public:
    void AddEvent(DWORD pid, int type, const std::wstring& detail) {
        time_t now = time(NULL);
        processEvents[pid].push_back({type, now, detail});
        
        CheckSequences(pid);
        CleanupWindow(pid, now);
    }

private:
    void CheckSequences(DWORD pid) {
        auto& events = processEvents[pid];
        bool hasSuspiciousProcess = false;
        bool hasMemoryOp = false;
        bool hasDgaQuery = false;

        for (const auto& ev : events) {
            // 1: ProcessCreate, 2: MemoryOp (ETW), 3: DNS query (ETW)
            if (ev.Type == 1 && ev.Detail.find(L"powershell.exe") != std::wstring::npos) hasSuspiciousProcess = true;
            if (ev.Type == 2) hasMemoryOp = true;
            if (ev.Type == 3 && ev.Detail.length() > 20) hasDgaQuery = true; // Simple entropy heuristic
        }

        if (hasSuspiciousProcess && hasMemoryOp && hasDgaQuery) {
            std::wcout << L"[!!!] CRITICAL: Ransomware/Dropper sequence detected in PID: " << pid << std::endl;
        }
    }

    void CleanupWindow(DWORD pid, time_t now) {
        auto& events = processEvents[pid];
        events.erase(std::remove_if(events.begin(), events.end(), [&](const EventInfo& e) {
            return (now - e.Timestamp) > TIME_WINDOW;
        }), events.end());
    }
};
