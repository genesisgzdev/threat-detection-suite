cmake_minimum_required(VERSION 3.10)
project(ThreatDetectionSuite)

set(CMAKE_CXX_STANDARD 17)

# Common headers
include_directories(ThreatDetectionSuite/TDSCommon)

# Userland Engine
add_executable(ThreatDetectionService 
    ThreatDetectionSuite/TDSEngine/ThreatDetectionService.cpp 
    ThreatDetectionSuite/TDSEngine/collectors/EtwCollector.cpp
    ThreatDetectionSuite/TDSEngine/correlator/SequenceCorrelator.cpp
    ThreatDetectionSuite/TDSEngine/detectors/PersistenceDetector.cpp
)
target_link_libraries(ThreatDetectionService wbemuuid taskschd comsuppw advapi32)

# Driver (Conceptual - usually requires WDK MSBuild or specialized CMake toolchain)
# add_library(ThreatDetectionSuite_Driver SHARED ThreatDetectionSuite/TDSDriver/TDSDriver.c)
# set_target_properties(ThreatDetectionSuite_Driver PROPERTIES SUFFIX ".sys")
