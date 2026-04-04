#pragma once
#include <windows.h>
#include <string>

namespace TDS {

class PersistenceDetector {
public:
    void ScanWmiSubscriptions();
    void ScanScheduledTasks();
    void ScanTempPersistence();

private:
    void ScanDirectory(const std::wstring& directory);
};

} // namespace TDS