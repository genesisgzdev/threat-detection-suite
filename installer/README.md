# TDS packaging

`build-msi.ps1` creates the MSI payload with WiX v4. The MSI must be signed with
the release certificate before distribution. Driver installation is performed by
`tools/install-service.ps1 -InstallDriver` after signature verification; test
certificates are allowed only in an isolated development VM with test signing
explicitly enabled.
