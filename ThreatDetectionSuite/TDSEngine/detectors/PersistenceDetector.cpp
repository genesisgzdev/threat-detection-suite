#include "PersistenceDetector.h"
#include <wbemidl.h>
#include <taskschd.h>
#include <comdef.h>
#include <iostream>
#include <wrl/client.h>
#include <vector>
#include "../../TDSScanner/Entropy.h"
#include "../Logger.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "taskschd.lib")

namespace TDS {

using Microsoft::WRL::ComPtr;

void PersistenceDetector::ScanWmiSubscriptions() {
    ComPtr<IWbemLocator> pLoc;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return;

    ComPtr<IWbemServices> pSvc;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) return;

    ComPtr<IEnumWbemClassObject> pEnumerator;
    hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM __EventFilter"), 
                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

    if (SUCCEEDED(hr)) {
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        while (pEnumerator) {
            hr = pEnumerator->Next(WAIT_OBJECT_0, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            if (vtProp.vt == VT_BSTR) {
                std::wstring name = vtProp.bstrVal;
                std::string sName(name.begin(), name.end());
                Logger::Instance().LogThreat(TDS_SEVERITY_MEDIUM, CAT_PERSISTENCE, "WMI Event Filter detected: " + sName, "WMI", 0);
            }
            VariantClear(&vtProp);
            pclsObj->Release();
        }
    }
}

void PersistenceDetector::ScanScheduledTasks() {
    ComPtr<ITaskService> pService;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) return;

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (SUCCEEDED(hr)) {
        ComPtr<ITaskFolder> pRootFolder;
        hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
        if (SUCCEEDED(hr)) {
            ComPtr<IRegisteredTaskCollection> pTaskCollection;
            hr = pRootFolder->GetTasks(NULL, &pTaskCollection);
            if (SUCCEEDED(hr)) {
                LONG numTasks = 0;
                pTaskCollection->get_Count(&numTasks);
                for (LONG i = 1; i <= numTasks; i++) {
                    ComPtr<IRegisteredTask> pTask;
                    if (SUCCEEDED(pTaskCollection->get_Item(_variant_t(i), &pTask))) {
                        BSTR taskName;
                        pTask->get_Name(&taskName);
                        // Process task actions for LOLBins...
                        SysFreeString(taskName);
                    }
                }
            }
        }
    }
}

void PersistenceDetector::ScanTempPersistence() {
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    ScanDirectory(tempPath);
}

void PersistenceDetector::ScanDirectory(const std::wstring& directory) {
    std::wstring searchPath = directory + L"\\*.*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        std::wstring fullPath = directory + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanDirectory(fullPath);
        } else {
            ULONGLONG fileSize = (static_cast<ULONGLONG>(findData.nFileSizeHigh) << 32) | findData.nFileSizeLow;
            
            if (fileSize > 512) {
                bool isHidden = (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
                bool isSystem = (findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0;

                if (isHidden && isSystem) {
                    std::string fPath(fullPath.begin(), fullPath.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_PERSISTENCE, "Hidden+System file detected in temp", fPath, 0);
                }

                if (Entropy::IsFileHighEntropy(fullPath)) {
                    std::string fPath(fullPath.begin(), fullPath.end());
                    Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_PERSISTENCE, "High entropy persistence file detected", fPath, 0);
                }
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

} // namespace TDS
