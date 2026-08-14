#pragma once

#include <cstdlib>
#include <string>

namespace TDS {

enum class ResponseMode {
    Observe,
    Alert,
    Contain,
    Terminate
};

class ResponsePolicy {
public:
    static ResponsePolicy FromEnvironment() {
        const char* raw = std::getenv("TDS_RESPONSE_MODE");
        if (!raw) return {};
        std::string mode(raw);
        if (mode == "terminate") return {ResponseMode::Terminate, 95, 90};
        if (mode == "contain") return {ResponseMode::Contain, 85, 100};
        if (mode == "alert") return {ResponseMode::Alert, 70, 100};
        return {};
    }

    bool AllowsContainment(int score) const {
        return (m_mode == ResponseMode::Contain || m_mode == ResponseMode::Terminate) && score >= m_containThreshold;
    }

    bool AllowsTermination(int score) const {
        return m_mode == ResponseMode::Terminate && score >= m_terminateThreshold;
    }

    ResponseMode Mode() const { return m_mode; }

private:
    ResponsePolicy(ResponseMode mode = ResponseMode::Observe, int containThreshold = 85, int terminateThreshold = 95)
        : m_mode(mode), m_containThreshold(containThreshold), m_terminateThreshold(terminateThreshold) {}

    ResponseMode m_mode;
    int m_containThreshold;
    int m_terminateThreshold;
};

} // namespace TDS
