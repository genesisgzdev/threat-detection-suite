#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <string>

namespace TDS {
    class EtwCollector {
    public:
        EtwCollector();
        ~EtwCollector();
        bool Start();
        void Stop();
    private:
        static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent);
        TRACEHANDLE m_traceHandle;
        TRACEHANDLE m_sessionHandle;
        std::string m_sessionName;
        bool m_isRunning;
    };
}
