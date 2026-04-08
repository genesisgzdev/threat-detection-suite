#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>

#pragma comment(lib, "wintrust.lib")

namespace TDS {

/**
 * Verifies the Authenticode signature of a given file.
 * Used to differentiate legitimate system binaries from spoofed ones.
 */
static bool VerifyAuthenticode(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &trustData);

    return status == ERROR_SUCCESS;
}

} // namespace TDS
