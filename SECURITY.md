# SECURITY POLICY: Threat Detection Suite v4.2.0

Threat Detection Suite is a high-security tool operating at the kernel level. We take the security of this software and its users with the utmost seriousness.

## Reporting a Vulnerability

If you discover a security vulnerability in Threat Detection Suite, please do **NOT** open a public issue. Instead, report it through our professional disclosure process:

1.  **Direct Communication:** Send a detailed email to `security@genzt.dev`.
2.  **Encrypted Communication:** We highly recommend using PGP to encrypt your report.
3.  **Detailed Report:** Include a clear description of the vulnerability, a proof-of-concept (PoC), and the potential impact assessment.

## Scope

This security policy covers:
- **ThreatDetectionKernel Driver:** IOCTL handlers, memory management, and callback implementations.
- **ThreatDetectionService:** Service-to-driver communication, ETW parsing, and command execution.
- **TDSEngine:** Behavioral correlation logic and detection algorithms.
- **IPC Protocols:** Any communication between the various components of the suite.

## Our Commitment

- **Acknowledgment:** We will acknowledge receipt of your report within 24 hours.
- **Investigation:** Our engineering team will investigate and validate the vulnerability immediately.
- **Resolution:** We aim to provide a verified fix or mitigation within 14 days for high-severity issues.
- **Recognition:** With your permission, we will credit you in our security advisories after the vulnerability is resolved.

## Responsible Disclosure Guidelines

- Do not attempt to exploit the vulnerability on systems you do not own.
- Do not disclose the vulnerability publicly until an official fix has been released.
- Give us a reasonable amount of time to address the issue before making it public.

Thank you for helping us maintain the integrity of the Threat Detection Suite.
