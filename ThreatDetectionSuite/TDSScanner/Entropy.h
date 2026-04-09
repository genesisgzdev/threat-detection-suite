#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace TDS {
    class EntropyAnalyzer {
    public:
        static double CalculateShannonEntropy(const std::vector<uint8_t>& buffer);
        static bool AnalyzeFile(const std::string& filePath, double threshold = 7.5);
    };
}
