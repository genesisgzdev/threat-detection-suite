# Windows driver acceptance checks

Ubuntu validation intentionally does not claim WDK compilation or driver
runtime behavior. A Windows runner with Visual Studio C++ and WDK must run:

```powershell
python tests/contract_checks.py
pwsh -NoProfile -File tests/windows/driver_security_contract.ps1
pwsh -NoProfile -File tools/build-driver.ps1 -Configuration Release -Platform x64
```

For an isolated administrator test machine, install the signed test driver and
service, then verify:

1. A standard user cannot open `\\.\TDS_Core_Link` for policy writes.
2. An unrelated elevated process receives `ERROR_ACCESS_DENIED` when sending
   `IOCTL_TDS_SET_PROTECTION_POLICY`.
3. `TDSService` can set observe mode and the configured response mode.
4. Restarting the driver/device causes the service to reconnect only after the
   policy IOCTL succeeds.
5. Driver Verifier is run against the test-signed driver before enabling any
   enforcing response mode.

The driver validates the requested read/write access explicitly with
`IoValidateDeviceIoControlAccess`; the `CTL_CODE` values and shared
`TDS_PROTECTION_POLICY` layout remain unchanged for ABI compatibility.
