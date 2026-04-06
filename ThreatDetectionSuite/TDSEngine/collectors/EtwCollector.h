#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include "../../TDSCommon/TDSCommon.h"

namespace TDS {

struct EtwProvider {
    GUID Guid;
    UCHAR Level;
    ULONGLONG MatchAnyKeyword;
    ULONGLONG MatchAllKeyword;
};

class EtwCollector {
public:
    EtwCollector(const std::wstring& sessionName);
    ~EtwCollector();

    bool Start(const std::vector<EtwProvider>& providers);
    void Stop();
    
    using EventCallback = std::function<void(PEVENT_RECORD)>;
    void SetEventCallback(EventCallback cb);

private:
    static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent);
    void ProcessLoop();

    std::wstring m_sessionName;
    TRACEHANDLE m_hSession{0};
    TRACEHANDLE m_hTrace{0};
    std::atomic<bool> m_active{false};
    std::thread m_workerThread;
    EventCallback m_callback;
    static EtwCollector* s_instance;
};

} // namespace TDS

