# Security Policy: Responsible Disclosure

The Threat Detection Suite (TDS) team is committed to ensuring the security and integrity of our users' systems. We recognize the critical role that security researchers play in the ecosystem and welcome their contributions through responsible disclosure.

## Reporting a Vulnerability

If you discover a security vulnerability within TDS, we ask that you provide us with the opportunity to remediate the issue before any public disclosure.

### 🛡️ Submission Process
1.  **DO NOT** open public issues or pull requests for security vulnerabilities.
2.  Send an encrypted email to `security@tds-project.org` (PGP Key ID: `0xDEADBEEF`) or use our private reporting portal if available.
3.  Include a detailed description of the vulnerability, including:
    -   Affected component (Driver, Service, API).
    -   Step-by-step instructions to reproduce the issue.
    -   A Proof-of-Concept (PoC) if possible (please ensure PoCs are safe and non-destructive).
    -   Potential impact assessment.

### 🤝 Our Commitment
- We will acknowledge receipt of your report within **24-48 hours**.
- We will provide a preliminary assessment and an estimated timeline for a fix.
- We will notify you once the vulnerability has been patched.
- We will offer attribution in our security advisories (with your consent).

## Prohibited Actions
While we encourage research, the following actions are strictly prohibited:
- Any testing that results in a Denial of Service (DoS) or system instability on non-lab environments.
- Exfiltration of data from systems you do not own.
- Social engineering or physical security attacks against maintainers or users.

## Disclosure Timeline
We follow a coordinated disclosure model. We generally aim to release a patch and a security advisory within **90 days** of the report. We ask that you refrain from sharing technical details publicly until the patch is available.

Thank you for helping us keep the Windows kernel a safer place.
