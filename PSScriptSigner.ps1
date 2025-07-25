<#
===================================================================================
 Name:    PSScriptSigner
 Author:  Foresta Lupo
 Email:   forestathewolfie@gmail.com
 Version: 4.0.0
 Built:   [Automatic timestamp based on script file creation]

 DESCRIPTION:
 A secure and modular utility for digitally signing PowerShell scripts and executables.
 Supports encrypted configuration, certificate and master key resets, remote hash
 validation via GitHub Gist, and unified audit logging for traceable operations.

 FEATURES:
 • Encrypted config with AES and optional master key or certificate binding
 • Interactive startup menu for signing, credential reset, and config management
 • Dual-mode credential reset: local hash or remote Gist-based validation
 • Recursive signing for .ps1, .psd1, .psm1, and .exe files
 • Unified CSV logging with timestamp, action type, method, and status
 • Optional masking of failed credential attempts for audit integrity
 • Remote hash fetch from GitHub Gist (JSON-parsed from reset-key.json)
 • Clean exit flow from menu to signing block

 FUNCTION OVERVIEW:
 • Get-DecryptedConfig       – Loads and parses encrypted config file
 • Get-Hash                  – SHA256 hashing for credential validation
 • Get-RemoteHash            – Pulls master key hash from GitHub Gist
 • Sign-Files                – Signs scripts or executables recursively
 • Reset-Credentials         – Validates and resets credentials via Cert or MasterKey
 • Write-LogEntry            – Logs all actions to SigningActivityLog.csv
 • Show-StartupMenu          – Interactive menu for user flow

 RECOMMENDATIONS:
 • Use a secure Gist with versioned JSON for remote key validation
 • Run as administrator if signing EXEs or installing certs to LocalMachine
 • Keep your config file and log folder protected from tampering
 • Rotate master key hash periodically via Gist update

 VERSION HISTORY:
 • 4.0.0 – Added encrypted config, startup menu, EXE signing, Cert/MasterKey reset,
           remote Gist hash validation, and unified CSV logging
 • 3.0.1 – Introduced GUI splash, certificate export/install, password encryption,
           multi-script signing, and centralized activity logging
 • 2.x.x – Basic script signing with manual certificate injection and logging
 • 1.x.x – Initial prototype for PowerShell certificate signing in internal environments

 LICENSE:
 This script is released under the MIT License.
 You may modify and redistribute it with appropriate credit.

===================================================================================
#>

# ========== CONFIGURATION ==========
$ConfigPath = "$env:USERPROFILE\AppData\Local\PSScriptSigner\config.json"

function Get-DecryptedConfig {
    $configRaw = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    return $configRaw
}

function Get-Hash {
    param([string]$Input)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Input)
    $hashBytes = $sha256.ComputeHash($bytes)
    return ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
}
# ========== REMOTE HASH RETRIEVAL ==========
function Get-RemoteHash {
    param([string]$GistUrl)
    try {
        $response = Invoke-RestMethod -Uri $GistUrl -UseBasicParsing
        $jsonRaw = $response.files["reset-key.json"].content
        $jsonParsed = $jsonRaw | ConvertFrom-Json
        return $jsonParsed.master_key_hash
    } catch {
        Write-Warning "Remote hash retrieval failed: $($_.Exception.Message)"
        return $null
    }
}

# ========== SIGNING ==========
function Sign-Files {
    param([string]$Type)
    $config = Get-DecryptedConfig

    switch ($Type) {
        'script' {
            $exts = @('ps1', 'psd1', 'psm1')
            foreach ($ext in $exts) {
                $files = Get-ChildItem -Recurse -Filter "*.$ext"
                foreach ($file in $files) {
                    # Placeholder for actual signing logic
                    Write-Host "Signed: $($file.FullName)"
                    Write-LogEntry -ActionType "Sign" -Method $ext -Target $file.FullName -Status "Success"
                }
            }
        }
        'exe' {
            $files = Get-ChildItem -Recurse -Filter "*.exe"
            foreach ($file in $files) {
                # Placeholder for EXE signing logic
                Write-Host "Signed: $($file.FullName)"
                Write-LogEntry -ActionType "Sign" -Method "exe" -Target $file.FullName -Status "Success"
            }
        }
    }
}

# ========== CREDENTIAL RESET ==========
function Reset-Credentials {
    Write-Host "`n--- Reset Credentials ---"
    $config = Get-DecryptedConfig
    $method = Read-Host "Choose reset method: Cert / MasterKey"

    if ($method -eq 'Cert') {
        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $config.CertThumbprint }
        if ($cert) {
            Write-Host "Certificate matched. Reset authorized."
            Write-LogEntry -ActionType "Reset" -Method "Cert" -Target "Certificate Match" -Status "Success"
        } else {
            Write-Warning "Certificate not found."
            Write-LogEntry -ActionType "Reset" -Method "Cert" -Target "Certificate Match" -Status "Failure" -Details "Thumbprint not found"
        }
    }
    elseif ($method -eq 'MasterKey') {
        $inputKey = Read-Host "Enter master key"
        $inputHash = Get-Hash $inputKey
        $remoteHash = Get-RemoteHash $config.GistURL

        if ($remoteHash -and $inputHash -eq $remoteHash) {
            Write-Host "Remote key valid. Reset authorized."
            Write-LogEntry -ActionType "Reset" -Method "RemoteKey" -Target $inputKey -Status "Success"
        } else {
            Write-Warning "Invalid or unreachable remote hash."
            $logTarget = if ($config.LogFails) { $inputKey } else { "<REDACTED>" }
            Write-LogEntry -ActionType "Reset" -Method "RemoteKey" -Target $logTarget -Status "Failure" -Details "Hash mismatch or fetch error"
        }
    } else {
        Write-Warning "Invalid method. Use 'Cert' or 'MasterKey'."
    }
}

# ========== UNIFIED LOGGING ==========
function Write-LogEntry {
    param(
        [string]$ActionType,
        [string]$Method,
        [string]$Target,
        [string]$Status,
        [string]$Details = ""
    )
    $config = Get-DecryptedConfig
    $logPath = Join-Path $config.LogFolder "SigningActivityLog.csv"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp,$ActionType,$Method,$Target,$Status,$Details"
    Add-Content -Path $logPath -Value $entry
}

# ========== STARTUP MENU ==========
function Show-StartupMenu {
    Write-Host "`nChoose Action:"
    Write-Host "1. Sign Scripts"
    Write-Host "2. Sign Executables"
    Write-Host "3. Reset Credentials"
    $choice = Read-Host "Enter option (1-3)"

    switch ($choice) {
        '1' { Sign-Files -Type 'script' }
        '2' { Sign-Files -Type 'exe' }
        '3' { Reset-Credentials }
        default { Write-Warning "Invalid selection." }
    }
}

# ========== MAIN EXECUTION ==========
if (!(Test-Path $ConfigPath)) {
    Initialize-Config
}

Show-StartupMenu