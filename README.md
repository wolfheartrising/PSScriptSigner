# PowerShell Script Signer – Foresta  
**Version:** 2.3.5  
**Author:** Foresta  
**Build Time:** Automatically stamped by the script

## Overview
This utility securely signs PowerShell `.ps1` scripts using a self-created code-signing certificate. It includes a guided GUI for setup, password protection, certificate creation, and bulk script signing with full audit logging.

Ideal for administrators, developers, and compliance-focused workflows, it behaves like an install-free desktop app — no modules or dependencies needed.

## Features
- 🔐 One-time setup with password protection and log folder selection  
- 📜 Create code-signing certificates (.pfx and .cer) from a custom subject  
- ⚙️ Install certificates to CurrentUser, LocalMachine, or both  
- 🧠 Detects administrator privileges before system-level certificate install  
- 🖋️ Authenticated multi-script signing with SHA256 timestamping  
- 📁 Smart filename handling from `CN=YourCertName`  
- 🧾 Action logs in CSV for auditing (`SigningActivityLog.csv`)  
- 🪟 All dialogs focus reliably to avoid lost windows or stuck prompts

## Requirements
- Windows PowerShell 5.x or later  
- GUI session (uses Windows Forms)  
- Internet access (for timestamping)  
- Administrator rights (for installing to LocalMachine store)

## Getting Started

1. **Run the script** (`PS_CodeSigner.ps1`). Elevated launch recommended.  
2. Follow the GUI setup:
   - Select a log directory
   - Create a script access password  
3. From the main menu:
   - Use Mode `4` to generate a certificate (`CN=YourCertName`)  
   - Use Mode `1` to begin signing scripts — password required  
4. Signed scripts will be timestamped and logged automatically  
5. Action results stored in your selected folder as `SigningActivityLog.csv`

## Modes

| Mode | Description                        |
|------|------------------------------------|
| 1    | Sign scripts                       |
| 2    | Reset access password              |
| 3    | Switch to a different certificate  |
| 4    | Create new code-signing certificate |
| 5    | Exit                               |

## Notes & Tips
- The `.pfx` file contains your **private key** — guard it carefully.  
- Only `CN=...` portions affect the generated filenames.  
- If installing to `LocalMachine`, run PowerShell **as Administrator**.  
- The timestamping service used is [http://timestamp.digicert.com](http://timestamp.digicert.com)  
- Summary screen allows quick access to logs after signing

## Version History

| Version | Changes |
|---------|---------|
| 2.3.5   | Fixed folder dialog default path issue. Stable release. |
| 2.3.4   | Patched error output in signing loop to resolve parser bug |
| 2.3.3   | Added 5-second splash screen and prompt focus reliability |
| 2.3.2   | Smart certificate filename logic using CN extraction |
| 2.3.1   | Elevation detection before system certificate install |
| 2.3.0   | Core signer logic, password vault, and UI foundation |

## License
This script is provided for internal or administrative use.  
You may modify and redistribute it freely with appropriate attribution.  

---

_Designed with care to make signing simple, secure, and seamless._
