# Threat Detection Suite architecture

TDS tiene dos fronteras distintas: el driver WDK en kernel y los ejecutables CMake de user mode. Las herramientas SOC y OTLP están fuera del camino de decisión del servicio.

## Cómo leerlo

La primera figura muestra el camino de un evento. La secuencia muestra el arranque y el apagado. La última tabla indica qué se puede comprobar en Linux, qué requiere Windows y qué necesita una máquina aislada. Las líneas opcionales son integraciones separadas.

## 1. Componentes y contratos

~~~mermaid
flowchart LR
    subgraph KERNEL[Windows kernel driver]
      PROC[process image thread callbacks]
      REG[registry callback]
      NET[WFP callouts]
      MINI[minifilter callbacks]
      Q[bounded event queue]
      ABI[event and policy ABI]
      DEV[driver device]
      PROC --> Q
      REG --> Q
      NET --> Q
      MINI --> Q
      Q --> ABI --> DEV
    end
    subgraph USER[CMake user mode]
      S[TDSService Windows service]
      E[TDSEngine]
      H[heuristics and detectors]
      C[SequenceCorrelator]
      L[Logger JSONL rotation]
      S --> E --> H
      E --> C
      E --> L
    end
    DEV -->|buffered event IOCTL| S
    S -->|policy IOCTL| DEV
    ETW[ETW telemetry] --> E
    B[TDSBridge utility] --> E
    L --> SOC[SOC and OTLP tools]
~~~

Precisión de build:

- CMake compila `TDSCore`, `TDSService` y `TDSBridge` en Windows.
- `ThreatDetectionSuite/TDSDriver/TDSDriver.vcxproj` se compila con WDK por separado.
- `build.sh` en Linux solo ejecuta checks de contratos y repositorio; no genera el driver ni un binario Windows.
- YARA es opcional en CMake y se activa con un SDK localizado por `TDS_YARA_ROOT`.

## 2. Arranque y ciclo de eventos

~~~mermaid
sequenceDiagram
    participant SCM as Windows SCM
    participant S as TDSService
    participant D as TDSDriver
    participant E as TDSEngine
    participant L as JSONL Logger
    SCM->>S: ServiceMain
    S->>E: Start
    S->>S: read TDS_RESPONSE_MODE
    S->>D: CreateFile TDS_Core_Link
    S->>D: SET_PROTECTION_POLICY
    loop until service stop
      S->>D: GET_NEXT_EVENT
      D-->>S: bounded header + payload
      S->>S: validate size and decode offsets
      S->>E: PushEvent valid event
      E->>L: detection/telemetry record
    end
    S->>D: CloseHandle
    S->>E: Shutdown
~~~

`observe` queda como política inicial. `contain` y `terminate` solo cambian los flags enviados al driver; no son evidencia de que la contención o terminación haya sido validada en una instalación Windows real.

Las señales de hilo remoto, APC y ETW-TI conservan separado el proceso emisor del proceso objetivo cuando el ABI lo entrega. Las respuestas y el correlador usan `TargetProcessId`; el collector ETW actual solo puede atribuir al emisor cuando el proveedor no entrega un objetivo decodificable. La secuencia de APC antes de la primera imagen o actividad de hilo se marca como inicialización temprana, no como prueba definitiva de Early Bird.

## 3. Seguridad de la frontera kernel/user

- Policy IOCTL exige `FILE_WRITE_ACCESS`, tamaño exacto, versión 1, flags conocidos y campos reservados en cero.
- Event IOCTL exige `FILE_READ_ACCESS`, buffer de salida suficiente y el límite `MAX_EVENT_BUFFER_SIZE`.
- El driver comprueba que el solicitante de la policy sea el proceso TDS autorizado; el servicio vuelve a abrir el device si se desconecta.
- La cola es acotada para que el flujo de eventos no convierta una ráfaga en crecimiento sin límite de memoria.

## 4. Qué prueba cada gate

| Gate | Prueba | No prueba |
| --- | --- | --- |
| `build.sh` | contratos ABI y estructura del repo en Linux | compilación o runtime Windows |
| user-mode CI | compilación MSVC de CMake | instalación/carga del driver |
| driver contract | access bits, IOCTL y lifecycle estáticos | callback real, WFP real, firma |
| laboratorio WDK | driver instalado y observado | seguridad universal en todos los Windows |
