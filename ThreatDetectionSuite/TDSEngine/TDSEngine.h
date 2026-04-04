#pragma once
#include <windows.h>
#include <unordered_set>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <wrl/client.h>
#include "../TDSCommon/TDSCommon.h"
#include "../TDSCommon/TDSEvents.h"
#include "EventBus.h"
#include "ProcessContextManager.h"
#include "correlator/SequenceCorrelator.h"

namespace TDS {

using Microsoft::WRL::ComPtr;

struct CaseInsensitiveHash {
    size_t operator()(const std::wstring& s) const {
        std::wstring lower = s;
        for (auto& c : lower) c = towlower(c);
        return std::hash<std::wstring>{}(lower);
    }
};

struct CaseInsensitiveEqual {
    bool operator()(const std::wstring& a, const std::wstring& b) const {
        return _wcsicmp(a.c_str(), b.c_str()) == 0;
    }
};

struct BeaconMetrics {
    double m_n = 0;
    double m_oldM = 0, m_newM = 0;
    double m_oldS = 0, m_newS = 0;

    void Push(double x) {
        m_n++;
        if (m_n == 1) {
            m_oldM = m_newM = x;
            m_oldS = 0.0;
        } else {
            m_newM = m_oldM + (x - m_oldM) / m_n;
            m_newS = m_oldS + (x - m_oldM) * (x - m_newM);
            m_oldM = m_newM;
            m_oldS = m_newS;
        }
    }

    double Variance() const { return (m_n > 1) ? m_newS / (m_n - 1) : 0.0; }
};

class TDSEngine {
public:
    TDSEngine();
    ~TDSEngine();

    void Start();
    void Shutdown();

    void PushEvent(const Event& event);

    bool IsLolbasBinary(const std::wstring& path);
    void UpdateNetworkStats(DWORD pid, double latency);
    
    static void ScanLOLBins();
    static void ScanProcessBehaviors();

private:
    void AnalysisLoop();
    void EvaluateThreat(const Event& event);
    
    static int CalculateLOLBinRiskScore(const std::wstring& commandLine);
    static std::wstring GetProcessCommandLine(DWORD pid);

    std::unordered_set<std::wstring, CaseInsensitiveHash, CaseInsensitiveEqual> m_lolbasBinaries;
    std::map<DWORD, BeaconMetrics> m_networkMetrics;
    
    std::unique_ptr<EventBus> m_eventBus;
    std::unique_ptr<ProcessContextManager> m_contextManager;
    std::unique_ptr<SequenceCorrelator> m_correlator;
    
    std::thread m_analysisThread;
    std::atomic<bool> m_running{false};
    std::mutex m_engineMutex;
};

} // namespace TDS
