# Comprobar TDS en Windows

Estas comprobaciones sirven para quien compila y valida TDS. El [panel y la guía de uso](../../docs/USO.md) son la entrada recomendada para leer observaciones.

## Qué comprueban las pruebas automáticas

CMake compila el servicio y las utilidades. CTest verifica la cola de eventos, el guardado del informe después de un fallo de archivo y la ayuda del ejecutable. Los contratos comprueban formatos, permisos declarados y estructura del controlador.

```powershell
python tests/contract_checks.py
powershell -NoProfile -File tests/windows/driver_security_contract.ps1
ctest --test-dir build -C Release --output-on-failure
```

La compilación del controlador requiere Windows Driver Kit además de Visual Studio C++:

```powershell
powershell -NoProfile -File tools/build-driver.ps1 -Configuration Release -Platform x64
```

## Qué necesita una instalación real de pruebas

Usa un equipo de pruebas aislado con un controlador cuya firma sea aceptada por Windows. Comprueba los permisos antes de habilitar respuestas que intervengan sobre procesos o conexiones.

| Comprobación | Resultado esperado |
| --- | --- |
| Un usuario normal intenta escribir una política | Windows rechaza el acceso |
| Un administrador ajeno intenta escribir una política | Recibe acceso denegado; la escritura pertenece al servicio LocalSystem |
| El servicio configura el modo de observación | El controlador acepta la política válida |
| Se interrumpe la conexión con el controlador | El servicio vuelve a conectar y solo continúa después de aplicar la política |
| Se ejecuta Driver Verifier en el entorno de pruebas | Se revisan sus resultados antes de habilitar intervención |

El controlador comprueba los permisos de lectura y escritura con `IoValidateDeviceIoControlAccess`. Los números de petición y el formato compartido `TDS_PROTECTION_POLICY` mantienen la compatibilidad entre servicio y controlador.

Una comprobación en Linux no sustituye estas pruebas. Compilar correctamente tampoco demuestra el comportamiento del controlador instalado.
