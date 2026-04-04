#include <windows.h>
#include <wbemidl.h>
#include <taskschd.h>
#include <comdef.h>
#include <iostream>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "taskschd.lib")

class PersistenceDetector {
public:
    void ScanWmiSubscriptions() {
        HRESULT hr;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;

        hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hr)) return;

        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hr)) { pLoc->Release(); return; }

        // Query for __EventFilter, __EventConsumer, and bindings
        IEnumWbemClassObject* pEnumerator = NULL;
        hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM __EventFilter"), 
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

        if (SUCCEEDED(hr)) {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;
            while (pEnumerator) {
                hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;

                VARIANT vtProp;
                pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
                std::wcout << L"[*] Found WMI Event Filter: " << vtProp.bstrVal << std::endl;
                VariantClear(&vtProp);
                pclsObj->Release();
            }
        }

        pSvc->Release();
        pLoc->Release();
    }

    void ScanScheduledTasks() {
        ITaskService* pService = NULL;
        HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
        if (FAILED(hr)) return;

        hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (SUCCEEDED(hr)) {
            ITaskFolder* pRootFolder = NULL;
            hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
            if (SUCCEEDED(hr)) {
                IRegisteredTaskCollection* pTaskCollection = NULL;
                hr = pRootFolder->GetTasks(NULL, &pTaskCollection);
                if (SUCCEEDED(hr)) {
                    LONG numTasks = 0;
                    pTaskCollection->get_Count(&numTasks);
                    std::cout << "[*] Found " << numTasks << " scheduled tasks in root folder." << std::endl;
                    pTaskCollection->Release();
                }
                pRootFolder->Release();
            }
        }
        pService->Release();
    }
};
