#include "Entropy.h"
#include <cmath>
#include <fstream>
#include <array>
#include <algorithm>

namespace TDS {
double EntropyAnalyzer::CalculateShannonEntropy(const std::vector<uint8_t>& buffer) {
    if (buffer.empty()) return 0.0;
    std::array<size_t, 256> frequencies = {0};
    for (uint8_t byte : buffer) { frequencies[byte]++; }
    double entropy = 0.0;
    double length = static_cast<double>(buffer.size());
    for (size_t freq : frequencies) {
        if (freq > 0) {
            double p = static_cast<double>(freq) / length;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

bool EntropyAnalyzer::AnalyzeFile(const std::string& filePath, double threshold) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    std::streamsize size = file.tellg();
    if (size == 0) return false;
    file.seekg(0, std::ios::beg);
    std::streamsize sampleSize = std::min(size, static_cast<std::streamsize>(1024 * 1024));
    std::vector<uint8_t> buffer(sampleSize);
    if (file.read(reinterpret_cast<char*>(buffer.data()), sampleSize)) {
        return CalculateShannonEntropy(buffer) > threshold;
    }
    return false;
}
}
