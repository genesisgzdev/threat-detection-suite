#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include "../TDSCommon/TDSEvents.h"

namespace TDS {

class EventBus {
public:
    void Push(const Event& event) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push(event);
        m_cv.notify_one();
    }

    std::optional<Event> WaitAndPop(int timeout_ms) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (m_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] { return !m_queue.empty() || m_stop; })) {
            if (!m_queue.empty()) {
                Event event = m_queue.front();
                m_queue.pop();
                return event;
            }
        }
        return std::nullopt;
    }

    void Stop() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stop = true;
        m_cv.notify_all();
    }

private:
    std::queue<Event> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_stop{false};
};

} // namespace TDS

