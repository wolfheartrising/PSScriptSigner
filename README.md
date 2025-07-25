# PowerShell Script Signer – Foresta  
**Version:** 4.0.0  
**Author:** Foresta  
**Build Time:** Automatically stamped by the script

---

## 🔐 Overview

This utility securely signs PowerShell `.ps1`, `.psd1`, `.psm1`, and `.exe` files using a self-created code-signing certificate.  
Includes encrypted configuration, remote credential reset via GitHub Gist, and unified logging.  
Behaves like an install-free desktop app—no modules or dependencies needed.

---

## ✨ Features

- 🔒 AES-encrypted config with master key or certificate binding  
- 📜 Recursive signing for scripts and executables  
- 🧩 Create code-signing certificates (.pfx and .cer) from a custom subject  
- ⚙️ Install certificates to CurrentUser, LocalMachine, or both  
- 🧠 Credential reset via cert thumbprint or remote master key hash  
- 🌐 Remote hash validation via GitHub Gist (`reset-key.json`)  
- 🧾 Unified CSV logging (`SigningActivityLog.csv`) with timestamp and status  
- 🧼 Optional masking of failed credential attempts  
- 🧭 Interactive startup menu for signing, resetting, and config flow  
- 🧱 All dialogs retain focus to avoid lost windows or stuck prompts

---

## 🧰 Requirements

- Windows PowerShell 5.1 or PowerShell Core  
- GUI session (uses Windows Forms)  
- Internet access (for remote hash validation)  
- Administrator rights (for installing to LocalMachine store)

---

## 🚀 Getting Started

Run the script (`PSScriptSigner.ps1`). Elevated launch recommended.

Follow the GUI setup:  
- Select a log directory  
- Enter certificate thumbprint or master key  
- Provide GitHub Gist URL for remote hash validation

From the main menu:  
- Use Mode 4 to generate a certificate (CN=YourCertName)  
- Use Mode 1 to begin signing scripts or executables  
- Use Mode 3 to reset credentials

Signed files will be timestamped and logged automatically.  
Action results stored in your selected folder as `SigningActivityLog.csv`.

---

## 🎛️ Modes

| Mode | Description                          |
|------|--------------------------------------|
| 1    | Sign scripts (.ps1, .psd1, .psm1)     |
| 2    | Sign executables (.exe)              |
| 3    | Reset credentials (Cert or MasterKey)|
| 4    | Create new code-signing certificate  |
| 5    | Exit                                 |

---

## 📝 Notes & Tips

- The `.pfx` file contains your private key—guard it carefully  
- Remote hash must be stored in a Gist file named `reset-key.json`  
- If installing to LocalMachine, run PowerShell as Administrator  
- All actions are logged to `SigningActivityLog.csv` in your selected folder  
- Failed credential attempts can be masked with `<REDACTED>` if configured  
- Summary screen allows quick access to logs after signing

---

## 📜 Version History

- **4.0.0** – Encrypted config, EXE signing, remote Gist validation, unified logging  
- **3.0.1** – GUI splash, certificate export/install, password encryption  
- **2.x.x** – Basic script signing with manual certificate injection  
- **1.x.x** – Initial prototype for internal PowerShell signing

---

## 📄 License

This script is provided for internal or administrative use.  
You may modify and redistribute it freely with appropriate attribution.  
Designed with care to make signing simple, secure, and seamless.

---
