#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <chrono>
#include <unordered_map>
#include "../TDSCommon/TDSEvents.h"

namespace TDS {

class EventBus {
public:
    struct Stats {
        size_t queue_depth{0};
        size_t dropped_total{0};
        size_t high_watermark{0};
        std::unordered_map<int, size_t> dropped_by_type;
    };

    bool Push(const Event& event) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stop || m_queue.size() >= m_capacity) {
            ++m_dropped;
            ++m_dropped_by_type[static_cast<int>(event.Type)];
            return false;
        }
        m_queue.push(event);
        if (m_queue.size() > m_high_watermark) m_high_watermark = m_queue.size();
        m_cv.notify_one();
        return true;
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

    size_t Dropped() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_dropped;
    }

    Stats Snapshot() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return Stats{m_queue.size(), m_dropped, m_high_watermark, m_dropped_by_type};
    }

private:
    std::queue<Event> m_queue;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_stop{false};
    const size_t m_capacity{10000};
    size_t m_dropped{0};
    size_t m_high_watermark{0};
    std::unordered_map<int, size_t> m_dropped_by_type;
};

} // namespace TDS
