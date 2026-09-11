# Poner TDS en marcha y entender sus avisos

## Abrir el panel

Con Python instalado, ejecuta `python tools/monitor.py` desde la carpeta del proyecto. Abre la dirección que imprime. El panel solo acepta conexiones desde tu equipo y no modifica aplicaciones.

La ruta predeterminada es `C:\ProgramData\TDS\tds_threat_events.jsonl`. Si guardas los eventos en otro lugar:

```powershell
python tools/monitor.py --log "D:\Informes\tds.jsonl"
```

También puedes definir `TDS_LOG_PATH`. `--port 8766` cambia el puerto del panel. `--limit 500` muestra más eventos recientes. El lector trabaja con el último MiB del archivo para no cargar en memoria un registro enorme; el panel indica cuando la vista es parcial.

Si el servicio acaba de escribir parte de una línea, el panel espera a la siguiente actualización para leerla completa. Si encuentra líneas dañadas, informa cuántas no pudo interpretar. Una rotación del archivo se recoge en la siguiente lectura.

## Comprobar la instalación

Ejecuta `tools/doctor.ps1`. Está preparado para Windows PowerShell 5.1 y PowerShell 7. `-Json` devuelve el diagnóstico para otra herramienta. `-RequireDriver` considera un problema que el controlador no esté activo; sin esa opción lo muestra como aviso.

El diagnóstico diferencia la configuración guardada del estado que puede tener un proceso ya iniciado. Un cambio en variables de entorno puede requerir reiniciar el servicio o Windows para llegar al proceso.

## Instalar el servicio compilado

Primero sigue la compilación del README. Copia los ejecutables necesarios a una carpeta estable bajo tu control. La instalación necesita permisos de administración de Windows.

```powershell
.\tools\install-service.ps1 -InstallRoot "C:\Program Files\TDS" -ResponseMode observe -WhatIf
```

`-WhatIf` permite revisar las acciones previstas sin ejecutarlas. Cuando la carpeta contenga los binarios compilados y hayas revisado las acciones, ejecuta el mismo comando sin `-WhatIf`. Después comprueba `Get-Service TDSService` y el diagnóstico.

La opción `-InstallDriver` requiere además el archivo `ThreatDetectionKernel.sys`, compilado con WDK y firmado de forma que Windows lo acepte. No desactives las comprobaciones de firma para convertir una instalación rechazada en una instalación aparentemente correcta.

Para detener el servicio usa `Stop-Service TDSService` desde una sesión con los permisos correspondientes. Cerrar el panel solo cierra el visor.

## Modos y datos

| Variable | Uso |
| --- | --- |
| `TDS_RESPONSE_MODE=observe` | Recoger y revisar sin autorizar contención o terminación |
| `TDS_RESPONSE_MODE=alert` | Registrar alertas sin autorizar esas intervenciones |
| `TDS_LOG_PATH` | Elegir el archivo de observaciones |
| `TDS_FORENSICS=1` | Activar la captura adicional de memoria ante eventos críticos; desactivada por defecto |

Los modos `contain` y `terminate` pueden intervenir sobre conexiones o procesos. No son necesarios para aprender a leer los eventos y requieren pruebas específicas en un entorno controlado.

El servicio vacía el búfer de informes durante su ciclo de trabajo y al cerrar. Si no puede escribir, conserva hasta 1000 eventos en memoria y avisa por el canal de diagnóstico de Windows. Al llenarse ese búfer pueden perderse nuevos eventos; corrige la ruta o los permisos. Un fallo parcial de escritura puede producir repeticiones al reintentar. No interpretes el archivo como una entrega garantizada sin pérdidas.

## Integraciones

YARA necesita su SDK y una compilación que lo habilite. El exportador OTLP y el bot SOC son herramientas aparte. No tienes que configurarlos para leer el panel. El bot puede publicar en GitHub cuando se configura para ello; no se activa al abrir este visor.

Las herramientas experimentales de la carpeta `tools` no forman parte del inicio recomendado. El [mapa de archivos](REPOSITORY_MAP.md) distingue esas herramientas del servicio y del visor.

[Volver al inicio](../README.md)
