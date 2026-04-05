#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <chrono>
#include "../TDSCommon/TDSCommon.h"
#include "ForensicManager.h"

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
        
        // Automated Forensics: Capture memory dump for CRITICAL alerts
        if (severity >= TDS_SEVERITY_CRITICAL && pid != 0) {
            ForensicManager::Instance().CaptureProcessDump(pid, GetTDSCategoryName(category));
        }

        TDS_THREAT_LOG log = {};
        log.ThreatId = m_counter++;
        log.Severity = severity;
        log.Category = category;
        
        // Timestamp (Epoch milliseconds)
        auto now = std::chrono::system_clock::now();
        log.Timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        
        log.AssociatedPid = pid;
        
        strncpy_s(log.Description, description.c_str(), _TRUNCATE);
        strncpy_s(log.Ioc, ioc.c_str(), _TRUNCATE);

        if (m_buffer.size() >= 1000) {
            FlushToDiskInternal();
        }
        m_buffer.push_back(log);
        
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
