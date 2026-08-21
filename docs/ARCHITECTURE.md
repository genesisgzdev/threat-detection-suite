# Threat Detection Suite architecture

The repository contains a Windows kernel/user boundary plus separate SOC utilities. The Linux script does not build the Windows binaries.

~~~mermaid
flowchart LR
    subgraph K[Windows kernel]
      P[process image thread callbacks]
      R[registry callback]
      N[WFP callouts]
      F[minifilter]
      Q[bounded event queue]
      P --> Q
      R --> Q
      N --> Q
      F --> Q
      D[TDSDriver device and IOCTL ABI]
      Q --> D
    end
    S[TDSService] -->|CreateFile and GET_NEXT_EVENT| D
    S -->|SET_PROTECTION_POLICY| D
    E[TDSEngine heuristics and correlation] --> L[JSONL Logger]
    S --> E
    T[ETW-TI collector] --> E
    L --> O[OTLP exporter and SOC tools]
    B[TDSBridge] --> E
~~~

## What is actually built

- CMake builds TDSService, TDSBridge and the TDSCore object sources on Windows.
- TDSDriver.vcxproj is the WDK driver build and is not compiled by the CMake user-mode target.
- TDSService opens the TDS_Core_Link device, applies a protection policy, drains GET_NEXT_EVENT, decodes bounded event payloads and pushes valid events into TDSEngine.
- The default service policy is observe-only. TDS_RESPONSE_MODE=contain or terminate changes the policy sent to the driver; response behavior still requires isolated Windows validation.
- tools/soc, TDSWatcher.ps1 and the OTLP exporter are separate consumers of emitted telemetry. They are not a cloud connector hidden inside the service.

## Gates

build.sh runs repository and contract checks on Linux. Windows CI is the compilation boundary. Driver signing, installation, callback behavior, WFP enforcement and hostile-input handling require WDK-backed Windows tests.
