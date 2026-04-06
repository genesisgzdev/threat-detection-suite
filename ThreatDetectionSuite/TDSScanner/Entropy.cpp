#include "Entropy.h"
#include <cmath>

namespace TDS {

float Entropy::Calculate(const void* data, size_t size) {
    if (!data || size < 16) return 0.0f;

    unsigned int freq[256] = { 0 };
    const BYTE* bytes = static_cast<const BYTE*>(data);
    for (size_t i = 0; i < size; i++) freq[bytes[i]]++;

    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            float p = static_cast<float>(freq[i]) / size;
            entropy -= p * log2f(p);
        }
    }
    return entropy;
}

bool Entropy::IsCompressedFormat(const BYTE* header, DWORD size) {
    if (size < 4) return false;
    if (header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04) return true; // ZIP
    if (header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47) return true; // PNG
    if (header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF) return true; // JPG
    if (header[0] == 0x25 && header[1] == 0x50 && header[2] == 0x44 && header[3] == 0x46) return true; // PDF
    return false;
}

bool Entropy::IsFileHighEntropy(const std::wstring& filePath, float threshold) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        return false;
    }

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return false;
    }

    LPVOID pMapped = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMapped) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    BYTE* buffer = static_cast<BYTE*>(pMapped);
    size_t mapSize = static_cast<size_t>(fileSize.QuadPart);

    bool result = false;
    if (mapSize >= 16) {
        if (!IsCompressedFormat(buffer, static_cast<DWORD>(mapSize))) {
            result = (Calculate(buffer, mapSize) > threshold);
        }
    }

    UnmapViewOfFile(pMapped);
    CloseHandle(hMap);
    CloseHandle(hFile);

    return result;
}

} // namespace TDS

