#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include "../TDSCommon/TDSCommon.h"

namespace TDS {

class Logger {
public:
    static Logger& Instance() {
        static Logger instance;
        return instance;
    }

    void LogThreat(TDS_THREAT_SEVERITY severity, TDS_THREAT_CATEGORY category, 
                   const std::string& description, const std::string& ioc, uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        TDS_THREAT_LOG log = {};
        log.ThreatId = m_counter++;
        log.Severity = severity;
        log.Category = category;
        log.Timestamp = GetTickCount64();
        log.AssociatedPid = pid;
        
        strncpy_s(log.Description, description.c_str(), _TRUNCATE);
        strncpy_s(log.Ioc, ioc.c_str(), _TRUNCATE);

        if (m_buffer.size() >= 1000) {
            FlushToDisk();
        }
        m_buffer.push_back(log);
        
        printf("[%s] [%s] %s (PID: %u)\n", 
               GetTDSSeverityName(severity), 
               GetTDSCategoryName(category), 
               description.c_str(), pid);
    }

    void FlushToDisk() {
        m_buffer.clear();
    }

private:
    Logger() : m_counter(0) {}
    std::vector<TDS_THREAT_LOG> m_buffer;
    std::mutex m_mutex;
    uint32_t m_counter;
};

} // namespace TDS
