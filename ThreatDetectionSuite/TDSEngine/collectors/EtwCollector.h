#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include "../../TDSCommon/TDSEvents.h"

namespace TDS {
    class EtwCollector {
    public:
        using EventHandler = std::function<void(const Event&)>;
        explicit EtwCollector(EventHandler handler = {});
        ~EtwCollector();
        bool Start();
        void Stop();
    private:
        static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent);
        void HandleEvent(PEVENT_RECORD pEvent);
        TRACEHANDLE m_traceHandle;
        TRACEHANDLE m_sessionHandle;
        std::string m_sessionName;
        std::atomic<bool> m_isRunning;
        EventHandler m_handler;
        std::thread m_traceThread;
    };
}
