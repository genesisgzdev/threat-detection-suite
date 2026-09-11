#include "Logger.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

int main() {
    try {
        char directory[MAX_PATH] = {};
        char filename[MAX_PATH] = {};
        if (!GetTempPathA(MAX_PATH, directory) || !GetTempFileNameA(directory, "tds", 0, filename)) {
            throw std::runtime_error("could not create private test file");
        }
        const std::string blocked = std::string(filename) + "\\not-a-directory.jsonl";
        _putenv_s("TDS_LOG_PATH", blocked.c_str());
        auto& logger = TDS::Logger::Instance();
        logger.LogThreat(TDS::TDS_SEVERITY_MEDIUM, TDS::CAT_DLL_INJECTION, "control\x01\ntext", "quote\"", 0);
        logger.FlushToDisk();
        _putenv_s("TDS_LOG_PATH", filename);
        logger.FlushToDisk();
        std::ifstream input(filename);
        const std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        input.close();
        std::filesystem::remove(filename);
        _putenv_s("TDS_LOG_PATH", "");
        if (content.find("control\\u0001\\ntext") == std::string::npos ||
            content.find("quote\\\"") == std::string::npos) {
            throw std::runtime_error("failed write lost buffered data or JSON escaping is invalid");
        }
        std::cout << "Buffered events survive a failed write and control characters are escaped.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
