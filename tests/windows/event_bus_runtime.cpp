#include "EventBus.h"
#include <iostream>
#include <stdexcept>

void require(bool value, const char* reason) {
    if (!value) throw std::runtime_error(reason);
}
int main() {
    try {
        TDS::EventBus bus;
        TDS::Event first{}; first.Type = TDSEventProcessCreate; first.Timestamp = 10; first.Pid = 1;
        auto second = first; second.Pid = 2;
        auto earlier = first; earlier.Timestamp = 5; earlier.Pid = 3;
        require(bus.Push(first) && bus.Push(second) && bus.Push(earlier), "enqueue");
        require(bus.WaitAndPop(0)->Pid == 3, "timestamp order");
        require(bus.WaitAndPop(0)->Pid == 1, "equal timestamp insertion order");
        bus.Stop();
        require(!bus.Push(first), "stop rejects producer");
        require(bus.WaitAndPop(0)->Pid == 2, "stop preserves accepted events for draining");
        require(!bus.WaitAndPop(0), "drained queue");
        bus.Resume();
        for (int i = 0; i < 10000; ++i) require(bus.Push(first), "capacity");
        require(!bus.Push(first), "bounded capacity");
        const auto stats = bus.Snapshot();
        require(stats.queue_depth == 10000 && stats.dropped_total == 2 && stats.high_watermark == 10000, "queue metrics");
        std::cout << "Native event bus tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
