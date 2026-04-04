#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include "../TDSCommon/TDSCommon.h"

namespace TDS {

// FIX: explicitly note C++11 thread-safe static initialization for singleton (Issue 30)
// Requires compiler supporting C++11 Magic Statics (MSVC /std:c++14 or higher)
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
            FlushToDiskInternal();
        }
        m_buffer.push_back(log);
        
        // FIX: Prevent format string injection by explicitly using %s for description (Issue 31)
        printf("[%s] [%s] %s (PID: %u)\n", 
               GetTDSSeverityName(severity), 
               GetTDSCategoryName(category), 
               description.c_str(), pid);
    }

    void FlushToDisk() {
        std::lock_guard<std::mutex> lock(m_mutex);
        FlushToDiskInternal();
    }

private:
    Logger() : m_counter(0) {}
    
    void FlushToDiskInternal() {
        // FIX: Actually write events to disk before clearing (Issue 29)
        std::ofstream ofs("tds_threat_events.jsonl", std::ios::app);
        if (ofs.is_open()) {
            for (const auto& log : m_buffer) {
                ofs << "{\"id\": " << log.ThreatId 
                    << ", \"severity\": \"" << GetTDSSeverityName(log.Severity) << "\""
                    << ", \"category\": \"" << GetTDSCategoryName(log.Category) << "\""
                    << ", \"description\": \"" << log.Description << "\""
                    << ", \"ioc\": \"" << log.Ioc << "\""
                    << ", \"timestamp\": " << log.Timestamp
                    << ", \"pid\": " << log.AssociatedPid << "}\n";
            }
        }
        m_buffer.clear();
    }

    std::vector<TDS_THREAT_LOG> m_buffer;
    std::mutex m_mutex;
    uint32_t m_counter;
};

} // namespace TDS
