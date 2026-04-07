#include "PersistenceDetector.h"
#include <wbemidl.h>
#include <taskschd.h>
#include <comdef.h>
#include <iostream>
#include <wrl/client.h>
#include <vector>
#include <algorithm>
#include "../../TDSScanner/Entropy.h"
#include "../Logger.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "taskschd.lib")

namespace TDS {

using Microsoft::WRL::ComPtr;

// Professional Narrow/Wide string conversion
static std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void PersistenceDetector::ScanWmiSubscriptions() {
    ComPtr<IWbemLocator> pLoc;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return;

    ComPtr<IWbemServices> pSvc;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) return;

    const std::vector<std::wstring> classes = {
        L"__EventFilter",
        L"CommandLineEventConsumer",
        L"ActiveScriptEventConsumer",
        L"__FilterToConsumerBinding"
    };

    for (const auto& wmiClass : classes) {
        ComPtr<IEnumWbemClassObject> pEnumerator;
        std::wstring query = L"SELECT * FROM " + wmiClass;
        hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query.c_str()), 
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

        if (SUCCEEDED(hr)) {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;
            while (pEnumerator) {
                hr = pEnumerator->Next(WAIT_OBJECT_0, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;

                VARIANT vtProp;
                if (SUCCEEDED(pclsObj->Get(L"Name", 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) {
                    std::string sName = WStringToString(vtProp.bstrVal);
                    std::string className = WStringToString(wmiClass);
                    Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_PERSISTENCE, "WMI Persistence Object: " + className, sName, 0);
                    VariantClear(&vtProp);
                } else if (SUCCEEDED(pclsObj->Get(L"CommandLineTemplate", 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) {
                    std::string sCmd = WStringToString(vtProp.bstrVal);
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_PERSISTENCE, "WMI CommandLine Consumer", sCmd, 0);
                    VariantClear(&vtProp);
                }
                
                pclsObj->Release();
            }
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
                        ComPtr<ITaskDefinition> pDef;
                        if (SUCCEEDED(pTask->get_Definition(&pDef))) {
                            ComPtr<IActionCollection> pActions;
                            if (SUCCEEDED(pDef->get_Actions(&pActions))) {
                                LONG numActions = 0;
                                pActions->get_Count(&numActions);
                                
                                for (LONG j = 1; j <= numActions; j++) {
                                    ComPtr<IAction> pAction;
                                    if (SUCCEEDED(pActions->get_Item(j, &pAction))) {
                                        TASK_ACTION_TYPE type;
                                        pAction->get_Type(&type);
                                        if (type == TASK_ACTION_EXEC) {
                                            ComPtr<IExecAction> pExecAction;
                                            if (SUCCEEDED(pAction.As(&pExecAction))) {
                                                BSTR bPath, bArgs;
                                                pExecAction->get_Path(&bPath);
                                                pExecAction->get_Arguments(&bArgs);
                                                
                                                std::wstring path = bPath ? bPath : L"";
                                                std::wstring args = bArgs ? bArgs : L"";
                                                std::wstring lowerPath = path;
                                                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
                                                
                                                if (lowerPath.find(L"powershell.exe") != std::wstring::npos ||
                                                    lowerPath.find(L"cmd.exe") != std::wstring::npos ||
                                                    lowerPath.find(L"certutil.exe") != std::wstring::npos ||
                                                    lowerPath.find(L"mshta.exe") != std::wstring::npos ||
                                                    lowerPath.find(L"regsvr32.exe") != std::wstring::npos) {
                                                    
                                                    std::string sPath = WStringToString(path);
                                                    std::string sArgs = WStringToString(args);
                                                    Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_LOLBIN_ABUSE, "LOLBin Scheduled Task Execution", sPath + " " + sArgs, 0);
                                                }
                                                
                                                if (bPath) SysFreeString(bPath);
                                                if (bArgs) SysFreeString(bArgs);
                                            }
                                        }
                                    }
                                }
                            }
                        }
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

    WCHAR sysTempPath[MAX_PATH];
    if (GetEnvironmentVariableW(L"SystemRoot", sysTempPath, MAX_PATH)) {
        std::wstring winTemp = std::wstring(sysTempPath) + L"\\Temp";
        ScanDirectory(winTemp);
    }
    
    WCHAR programDataPath[MAX_PATH];
    if (GetEnvironmentVariableW(L"ProgramData", programDataPath, MAX_PATH)) {
        ScanDirectory(programDataPath);
    }
}

void PersistenceDetector::ScanDirectory(const std::wstring& directory, int depth) {
    if (depth > 8) return; 

    std::wstring searchPath = directory + L"\\*.*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        std::wstring fullPath = directory + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanDirectory(fullPath, depth + 1);
        } else {
            ULONGLONG fileSize = (static_cast<ULONGLONG>(findData.nFileSizeHigh) << 32) | findData.nFileSizeLow;
            
            if (fileSize > 512) {
                bool isHidden = (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
                bool isSystem = (findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0;

                if (isHidden && isSystem) {
                    std::string fPath = WStringToString(fullPath);
                    Logger::Instance().LogThreat(TDS_SEVERITY_CRITICAL, CAT_PERSISTENCE, "Hidden+System file detected in temp/system dir", fPath, 0);
                }

                if (Entropy::IsFileHighEntropy(fullPath)) {
                    std::string fPath = WStringToString(fullPath);
                    Logger::Instance().LogThreat(TDS_SEVERITY_HIGH, CAT_PERSISTENCE, "High entropy persistence file detected", fPath, 0);
                }
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

} // namespace TDS
