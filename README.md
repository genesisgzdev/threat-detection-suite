# Threat Detection Suite

TDS conecta un driver de kernel, un servicio de análisis en user mode y herramientas SOC pequeñas para estudiar telemetría y contratos de seguridad de Windows.

En 30 segundos: el driver entrega eventos acotados al servicio, el servicio aplica heurísticas y políticas, y la salida termina en JSONL u OTLP. El repo sirve para ingeniería y validación controlada; no es un EDR comercial terminado ni debe instalarse en producción.

[![Windows build](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/ci.yml)
[![Security audit](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/security.yml/badge.svg)](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/security.yml)
[![License](https://img.shields.io/github/license/genesisgzdev/threat-detection-suite)](LICENSE)

## Estado que puedes afirmar

La rama `main` tiene checks reproducibles del repositorio, CI de user mode para Windows, análisis de código con CodeQL y checks de contratos. Para probar el driver hace falta una máquina Windows 10/11 x64 con Visual Studio, WDK, Driver Verifier y un plan aislado.

La canalización empieza en `observe`. `contain` y `terminate` son modos explícitos para validación controlada. CI y los checks de contrato demuestran coherencia de fuentes y compilación disponible; no demuestran que un driver firmado sea seguro en cualquier Windows.

## Flujo que importa

```text
kernel driver  ->  bounded event contract  ->  TDSService
       |                                      |
       +-- WFP, minifilter, process callbacks  +-- ETW-TI and heuristics
                                              |
                                  JSONL / OTLP / optional SOC bot
```

El detalle de IOCTL, ciclo de vida, colas, ETW-TI, WFP, minifilter y consumidores está en [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

La compilación de user mode produce `TDSService` y `TDSBridge`. El driver se compila por separado con el proyecto WDK `ThreatDetectionSuite/TDSDriver/TDSDriver.vcxproj`.

Las piezas que explican el sistema son:

- WFP and minifilter telemetry with explicit lifecycle cleanup
- A bounded kernel-to-user event queue and validated IOCTL buffers
- Process protection callbacks and policy authorization checks
- ETW-TI collection, entropy analysis and optional YARA support
- JSONL logging, local rotation and separate SOC/OTLP consumer tools
- PowerShell tooling for service installation and controlled diagnostics

YARA es opcional. TDSBridge y OTLP son consumidores separados. El driver requiere la herramienta WDK.

## Compilar en Windows

Requisitos:

- Windows 10/11 x64
- Visual Studio 2022 with Desktop development with C++
- A WDK matching the installed Windows SDK
- CMake 3.20 or newer

Compila los componentes de user mode:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DTDS_ENABLE_YARA=OFF
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

Compila el driver con las herramientas del WDK:

```powershell
msbuild ThreatDetectionSuite/TDSDriver/TDSDriver.vcxproj /m /p:Configuration=Release /p:Platform=x64 /warnAsError
```

En Linux, `bash build.sh` ejecuta checks del repositorio y de los contratos. No compila el driver de Windows.

## Configuración, dependencias y confianza

- `TDS_RESPONSE_MODE=observe|alert|contain|terminate`
- `TDS_LOG_PATH` selects the JSONL output path
- `TDS_FORENSICS=1` enables critical-alert process dumps
- `TDS_ENABLE_YARA` is enabled through CMake and requires a YARA SDK

Revisa [BUILDING.md](BUILDING.md), [SECURITY.md](SECURITY.md) y [DISCLAIMER.md](DISCLAIMER.md) antes de cargar un driver o activar respuestas.

Dependencias críticas: Windows 10/11 x64, Visual Studio, SDK/WDK compatible y permisos de laboratorio. En Linux, `build.sh` ejecuta checks de repositorio y ABI; la compilación del driver ocurre en Windows.

Antes de cargarlo, revisa [BUILDING.md](BUILDING.md), [SECURITY.md](SECURITY.md), [DISCLAIMER.md](DISCLAIMER.md) y los checks de [`tests/windows/`](tests/windows/). La arquitectura y los límites de confianza están en [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Qué está probado

La CI comprueba los contratos guardados y la ruta de compilación de Windows. La firma WDK, la carga del driver y las respuestas frente a entradas hostiles necesitan una VM o un equipo aislado.

## Licencia

Apache 2.0. See [LICENSE](LICENSE).
