# Preparar el instalador de TDS

Esta carpeta sirve a quien distribuye TDS. Si solo necesitas instalarlo o consultar sus eventos, empieza por la [guía de uso](../docs/USO.md).

## Qué prepara el paquete

`build-msi.ps1` reúne el ejecutable del servicio y el controlador en un archivo MSI usando WiX v4. El paquete instala y arranca el servicio. Copiar el archivo del controlador no significa que Windows lo haya cargado.

Necesitas los binarios ya compilados y WiX instalado:

```powershell
.\installer\build-msi.ps1 -ServiceExe "C:\Compilacion\TDSService.exe" -DriverSys "C:\Compilacion\ThreatDetectionKernel.sys"
```

El resultado predeterminado es `ThreatDetectionSuite.msi`. Puedes elegir otra ruta con `-Output`. El script se detiene si WiX no está disponible o falla la compilación del paquete.

## Antes de distribuirlo

Firma el MSI y el controlador con los certificados que correspondan a la distribución. Comprueba que Windows acepte las firmas. La instalación del controlador se realiza por separado mediante `tools/install-service.ps1 -InstallDriver` y necesita los permisos y requisitos descritos en la guía.

El número de versión de `TDS.wxs` debe coincidir con la versión que distribuyes. Un paquete generado no demuestra por sí solo que el controlador cargue ni que sus respuestas sean correctas. Completa las [comprobaciones de Windows](../tests/windows/README.md).
