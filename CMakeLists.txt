cmake_minimum_required(VERSION 3.10)
project(ThreatDetectionSuite)

set(CMAKE_CXX_STANDARD 17)

# Common headers
include_directories(ThreatDetectionSuite/TDSCommon)
include_directories(ThreatDetectionSuite/TDSEngine)
include_directories(ThreatDetectionSuite/TDSScanner)

# Userland Engine
add_executable(ThreatDetectionService 
    ThreatDetectionSuite/TDSEngine/TDSService.cpp 
    ThreatDetectionSuite/TDSEngine/TDSEngine.cpp
    ThreatDetectionSuite/TDSEngine/collectors/EtwCollector.cpp
    ThreatDetectionSuite/TDSEngine/correlator/SequenceCorrelator.cpp
    ThreatDetectionSuite/TDSEngine/detectors/PersistenceDetector.cpp
    ThreatDetectionSuite/TDSScanner/MemoryScanner.cpp
)
target_link_libraries(ThreatDetectionService wbemuuid taskschd comsuppw advapi32 ntdll)

# Legacy Bridge / Integration Utility
add_executable(ThreatDetectionSuiteUtility ThreatDetectionSuite.cpp)
target_link_libraries(ThreatDetectionSuiteUtility advapi32)
