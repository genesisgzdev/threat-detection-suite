# Mapa del repositorio

Usa este índice cuando quieras encontrar una parte del proyecto. Para empezar a usarlo, vuelve al [README](../README.md). Los archivos generados al compilar y las dependencias instaladas quedan fuera del mapa.

## Qué hace cada parte

| Área | Recorrido | Qué conviene comprobar |
| --- | --- | --- |
| Kernel | callbacks → ABI versionado → SLIST acotada → IOCTL autorizado | Contrato y proyecto WDK; Driver Verifier y descarga real pendientes |
| Ingesta | TDSService/Bridge → validación de payload → EventBus | Orden por timestamp e inserción; capacidad y pérdidas observables |
| ETW | sesión por proceso → eventos de proveedor → atribución | Un target desconocido no se convierte en PID de respuesta |
| Análisis | heurísticas, correlación, detectores, escáner de memoria | Windows user-mode compilado; no equivale a eficacia de detección medida |
| Respuesta | ResponsePolicy observe/alert/contain/terminate → IPS | Observe por defecto; operaciones privilegiadas requieren laboratorio |
| Salida | Logger JSONL → panel local o exportador OTLP | Búfer acotado con reintento de archivo; OTLP conserva su cursor y puede repetir entregas |
| Herramientas separadas | SOC bot, installer, driver build, diagnósticos, arneses de laboratorio | No se ejecutaron arneses de ataque ni acciones sobre equipos externos |

ThreatIntelManager no implementa todavía un proveedor de enriquecimiento. YARA es opcional y no está activado en el build estándar. El bot GitHub es un consumidor separado y no comparte las garantías de checkpoint del exportador OTLP. Un archivo rotado y eliminado antes de su lectura no puede recuperarse. Este mapa distingue componentes presentes de comportamientos verificados; no es una certificación EDR.

## Inventario de archivos

| Archivo | Responsabilidad |
| --- | --- |
| [.editorconfig](../.editorconfig) | Configuración/metadata: .editorconfig |
| [.github/workflows/ci.yml](../.github/workflows/ci.yml) | Automatización de ci |
| [.github/workflows/release.yml](../.github/workflows/release.yml) | Automatización de release |
| [.github/workflows/security.yml](../.github/workflows/security.yml) | Automatización de security |
| [.gitignore](../.gitignore) | Configuración/metadata: .gitignore |
| [BUILDING.md](../BUILDING.md) | Documentación: BUILDING |
| [CHANGELOG.md](../CHANGELOG.md) | Documentación: CHANGELOG |
| [CMakeLists.txt](../CMakeLists.txt) | Configuración/metadata: CMakeLists.txt |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Documentación: CONTRIBUTING |
| [DISCLAIMER.md](../DISCLAIMER.md) | Documentación: DISCLAIMER |
| [LICENSE](../LICENSE) | Licencia del proyecto |
| [README.md](../README.md) | Documentación: README |
| [SECURITY.md](../SECURITY.md) | Documentación: SECURITY |
| [ThreatDetectionSuite/TDSCommon/EventAttribution.h](../ThreatDetectionSuite/TDSCommon/EventAttribution.h) | Frontera de atribución entre emisor y target |
| [ThreatDetectionSuite/TDSCommon/TDSCommon.h](../ThreatDetectionSuite/TDSCommon/TDSCommon.h) | ABI compartido kernel/user-mode |
| [ThreatDetectionSuite/TDSCommon/TDSEvents.h](../ThreatDetectionSuite/TDSCommon/TDSEvents.h) | Componente nativo: TDSEvents |
| [ThreatDetectionSuite/TDSCommon/TDSThreats.h](../ThreatDetectionSuite/TDSCommon/TDSThreats.h) | Componente nativo: TDSThreats |
| [ThreatDetectionSuite/TDSDriver/TDSDriver.c](../ThreatDetectionSuite/TDSDriver/TDSDriver.c) | Driver, callbacks, control de acceso e IOCTL |
| [ThreatDetectionSuite/TDSDriver/TDSDriver.vcxproj](../ThreatDetectionSuite/TDSDriver/TDSDriver.vcxproj) | Configuración/metadata: TDSDriver.vcxproj |
| [ThreatDetectionSuite/TDSEngine/EventBus.h](../ThreatDetectionSuite/TDSEngine/EventBus.h) | Componente nativo: EventBus |
| [ThreatDetectionSuite/TDSEngine/ForensicManager.h](../ThreatDetectionSuite/TDSEngine/ForensicManager.h) | Componente nativo: ForensicManager |
| [ThreatDetectionSuite/TDSEngine/HeuristicsEngine.cpp](../ThreatDetectionSuite/TDSEngine/HeuristicsEngine.cpp) | Componente nativo: HeuristicsEngine |
| [ThreatDetectionSuite/TDSEngine/HeuristicsEngine.h](../ThreatDetectionSuite/TDSEngine/HeuristicsEngine.h) | Componente nativo: HeuristicsEngine |
| [ThreatDetectionSuite/TDSEngine/Logger.h](../ThreatDetectionSuite/TDSEngine/Logger.h) | Componente nativo: Logger |
| [ThreatDetectionSuite/TDSEngine/ResponsePolicy.h](../ThreatDetectionSuite/TDSEngine/ResponsePolicy.h) | Componente nativo: ResponsePolicy |
| [ThreatDetectionSuite/TDSEngine/TDSEngine.cpp](../ThreatDetectionSuite/TDSEngine/TDSEngine.cpp) | Componente nativo: TDSEngine |
| [ThreatDetectionSuite/TDSEngine/TDSEngine.h](../ThreatDetectionSuite/TDSEngine/TDSEngine.h) | Componente nativo: TDSEngine |
| [ThreatDetectionSuite/TDSEngine/TDSService.cpp](../ThreatDetectionSuite/TDSEngine/TDSService.cpp) | Componente nativo: TDSService |
| [ThreatDetectionSuite/TDSEngine/ThreatIntelManager.h](../ThreatDetectionSuite/TDSEngine/ThreatIntelManager.h) | Enriquecedor sin proveedor implementado |
| [ThreatDetectionSuite/TDSEngine/collectors/EtwCollector.cpp](../ThreatDetectionSuite/TDSEngine/collectors/EtwCollector.cpp) | Componente nativo: EtwCollector |
| [ThreatDetectionSuite/TDSEngine/collectors/EtwCollector.h](../ThreatDetectionSuite/TDSEngine/collectors/EtwCollector.h) | Componente nativo: EtwCollector |
| [ThreatDetectionSuite/TDSEngine/correlator/SequenceCorrelator.cpp](../ThreatDetectionSuite/TDSEngine/correlator/SequenceCorrelator.cpp) | Componente nativo: SequenceCorrelator |
| [ThreatDetectionSuite/TDSEngine/correlator/SequenceCorrelator.h](../ThreatDetectionSuite/TDSEngine/correlator/SequenceCorrelator.h) | Componente nativo: SequenceCorrelator |
| [ThreatDetectionSuite/TDSEngine/detectors/NetworkDetector.cpp](../ThreatDetectionSuite/TDSEngine/detectors/NetworkDetector.cpp) | Componente nativo: NetworkDetector |
| [ThreatDetectionSuite/TDSEngine/detectors/NetworkDetector.h](../ThreatDetectionSuite/TDSEngine/detectors/NetworkDetector.h) | Componente nativo: NetworkDetector |
| [ThreatDetectionSuite/TDSEngine/detectors/PersistenceDetector.cpp](../ThreatDetectionSuite/TDSEngine/detectors/PersistenceDetector.cpp) | Componente nativo: PersistenceDetector |
| [ThreatDetectionSuite/TDSEngine/detectors/PersistenceDetector.h](../ThreatDetectionSuite/TDSEngine/detectors/PersistenceDetector.h) | Componente nativo: PersistenceDetector |
| [ThreatDetectionSuite/TDSEngine/detectors/RegistryDetector.cpp](../ThreatDetectionSuite/TDSEngine/detectors/RegistryDetector.cpp) | Componente nativo: RegistryDetector |
| [ThreatDetectionSuite/TDSEngine/detectors/RegistryDetector.h](../ThreatDetectionSuite/TDSEngine/detectors/RegistryDetector.h) | Componente nativo: RegistryDetector |
| [ThreatDetectionSuite/TDSEngine/detectors/SignatureVerifier.h](../ThreatDetectionSuite/TDSEngine/detectors/SignatureVerifier.h) | Componente nativo: SignatureVerifier |
| [ThreatDetectionSuite/TDSEngine/ips/IPSManager.cpp](../ThreatDetectionSuite/TDSEngine/ips/IPSManager.cpp) | Componente nativo: IPSManager |
| [ThreatDetectionSuite/TDSEngine/ips/IPSManager.h](../ThreatDetectionSuite/TDSEngine/ips/IPSManager.h) | Componente nativo: IPSManager |
| [ThreatDetectionSuite/TDSScanner/Entropy.cpp](../ThreatDetectionSuite/TDSScanner/Entropy.cpp) | Componente nativo: Entropy |
| [ThreatDetectionSuite/TDSScanner/Entropy.h](../ThreatDetectionSuite/TDSScanner/Entropy.h) | Componente nativo: Entropy |
| [ThreatDetectionSuite/TDSScanner/MemoryScanner.cpp](../ThreatDetectionSuite/TDSScanner/MemoryScanner.cpp) | Componente nativo: MemoryScanner |
| [ThreatDetectionSuite/TDSScanner/MemoryScanner.h](../ThreatDetectionSuite/TDSScanner/MemoryScanner.h) | Componente nativo: MemoryScanner |
| [build.sh](../build.sh) | Herramienta de ejecución: build |
| [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) | Documentación: ARCHITECTURE |
| [docs/REPOSITORY_MAP.md](../docs/REPOSITORY_MAP.md) | Documentación: REPOSITORY_MAP |
| [installer/README.md](../installer/README.md) | Documentación: README |
| [installer/TDS.wxs](../installer/TDS.wxs) | Recursos de distribución: TDS.wxs |
| [installer/build-msi.ps1](../installer/build-msi.ps1) | Herramienta de ejecución: build-msi |
| [release_notes.md](../release_notes.md) | Documentación: release_notes |
| [tests/contract_checks.py](../tests/contract_checks.py) | Validación: contract_checks |
| [tests/test_otlp_delivery.py](../tests/test_otlp_delivery.py) | Validación: test_otlp_delivery |
| [tests/test_otlp_exporter.py](../tests/test_otlp_exporter.py) | Validación: test_otlp_exporter |
| [tests/windows/README.md](../tests/windows/README.md) | Validación: README |
| [tests/windows/driver_security_contract.ps1](../tests/windows/driver_security_contract.ps1) | Validación: driver_security_contract |
| [tests/windows/event_bus_runtime.cpp](../tests/windows/event_bus_runtime.cpp) | Validación: event_bus_runtime |
| [tools/attack_sim.cpp](../tools/attack_sim.cpp) | Componente nativo: attack_sim |
| [tools/bridge/TDSBridge.cpp](../tools/bridge/TDSBridge.cpp) | Componente nativo: TDSBridge |
| [tools/build-driver.ps1](../tools/build-driver.ps1) | Herramienta de ejecución: build-driver |
| [tools/doctor.ps1](../tools/doctor.ps1) | Herramienta de ejecución: doctor |
| [tools/fuzzer.cpp](../tools/fuzzer.cpp) | Componente nativo: fuzzer |
| [tools/fuzzer_advanced.cpp](../tools/fuzzer_advanced.cpp) | Componente nativo: fuzzer_advanced |
| [tools/fuzzer_standalone.cpp](../tools/fuzzer_standalone.cpp) | Componente nativo: fuzzer_standalone |
| [tools/ghost_poc.cpp](../tools/ghost_poc.cpp) | Componente nativo: ghost_poc |
| [tools/install-service.ps1](../tools/install-service.ps1) | Herramienta de ejecución: install-service |
| [tools/soc/TDSWatcher.ps1](../tools/soc/TDSWatcher.ps1) | Herramienta de ejecución: TDSWatcher |
| [tools/soc/otlp_exporter.py](../tools/soc/otlp_exporter.py) | Módulo: otlp_exporter |
| [tools/soc/requirements.txt](../tools/soc/requirements.txt) | Dependencias y comandos del componente |
| [tools/soc/soc_bot.py](../tools/soc/soc_bot.py) | Módulo: soc_bot |
| [tools/uninstall-service.ps1](../tools/uninstall-service.ps1) | Herramienta de ejecución: uninstall-service |
| [docs/USO.md](../docs/USO.md) | Guía de instalación, lectura y diagnóstico |
| [tools/monitor.py](../tools/monitor.py) | Sirve eventos recientes en un panel local de solo lectura |
| [tools/monitor.html](../tools/monitor.html) | Presenta búsqueda, prioridades y detalle de eventos reales |
| [tests/test_monitor.py](../tests/test_monitor.py) | Comprueba lectura incremental, rotación y acceso HTTP local |
| [tests/windows/logger_runtime.cpp](../tests/windows/logger_runtime.cpp) | Comprueba que un fallo de escritura conserva datos y que el JSON es válido |
