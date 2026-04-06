#pragma once
#include <windows.h>
#include <string>

namespace TDS {

class Entropy {
public:
    static float Calculate(const void* data, size_t size);
    static bool IsFileHighEntropy(const std::wstring& filePath, float threshold = 7.8f);

private:
    static bool IsCompressedFormat(const BYTE* header, DWORD size);
};

} // namespace TDS

