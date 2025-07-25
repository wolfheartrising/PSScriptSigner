# PSScriptSigner

**Version:** 4.0.0  
**Author:** Foresta Lupo  
**Email:** forestathewolfie@gmail.com

## 🔐 Overview
PSScriptSigner is a secure and flexible PowerShell utility for digitally signing scripts and executables. Ideal for administrative environments, deployment automation, and compliance workflows.

## ✨ Features
- Encrypted configuration with AES, master key, or certificate binding
- Dual credential reset modes: Cert thumbprint or remote master key hash
- Remote hash validation via GitHub Gist (`reset-key.json`)
- Recursive signing support for `.ps1`, `.psd1`, `.psm1`, and `.exe` files
- Unified action logging to CSV for auditing
- Optional masking for failed attempts to preserve security hygiene

## 📦 Installation

```powershell
# Clone the repo
git clone https://github.com/wolfheartrising/PSScriptSigner.git

# Run the script
.\PSScriptSigner.ps1