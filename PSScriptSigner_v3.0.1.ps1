<#
===================================================================================
 PowerShell Script Signer – Foresta
 Version: 3.0.1
 Built:   [Automatic timestamp based on script file creation]

 DESCRIPTION:
 A secure and user-friendly utility for digitally signing PowerShell scripts using
 code-signing certificates. It streamlines setup, authentication, certificate creation,
 and signing—ensures traceability and clarity for administrative environments.

 FEATURES:
 • One-time setup with password protection and log folder selection
 • Certificate creation (self-signed, exportable as .pfx and .cer)
 • Install cert to CurrentUser, LocalMachine, or both—with admin detection
 • Authentication splash confirms access; self-closes after 5 seconds
 • Multi-script signing with timestamping and action logging
 • Smart filename handling based on subject name
 • CSV log for review and auditing
 • All prompts retain focus for seamless UI
 • Clean exit flow from menu to signing block

 FUNCTION OVERVIEW:
 • Prompt-ForPassword       – GUI prompt for entering or confirming passwords
 • ConvertTo-SHA256         – Hashes input using SHA256 for secure password storage
 • Encrypt-Settings         – Saves configuration settings using SecureString encryption
 • Decrypt-Settings         – Loads and decrypts stored settings for runtime use
 • Save-Settings            – Writes updated config values back to disk securely
 • Log-Attempt              – Records signing activity and user actions for audit
 • Test-IsAdmin             – Detects admin rights for system-level certificate install
 • Certificate Creation     – Builds and exports signing certificates (.pfx/.cer)
 • Certificate Installation – Imports cert into CurrentUser and/or LocalMachine stores
 • Signing Flow             – Authenticates, signs scripts, shows summary dialog

 RECOMMENDATIONS:
 • Run the script as administrator to install certificates to LocalMachine
 • Safeguard your .pfx private key file—it holds signing authority
 • Audit script content before signing
 • Validate certificate visibility in Personal store for all signing modes

 LICENSE:
 This script was developed for internal organizational use.
 You may modify and redistribute it with appropriate credit.

===================================================================================
#>

# Relaunch with elevation if needed
if (-not (
    [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
)) {
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process powershell.exe -Verb RunAs `
        -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$scriptPath`""
    exit
}

# Define environment metadata
$scriptFile     = $MyInvocation.MyCommand.Path
$PSScriptRoot   = Split-Path -Parent $scriptFile
$toolVersion    = "3.0.1"
$buildTimestamp = (Get-Item $scriptFile).CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
$settingsPath   = Join-Path $PSScriptRoot "EncryptedSettings.xml"

# Load GUI components
Add-Type -AssemblyName System.Windows.Forms
function Prompt-ForPassword {
    # GUI form to securely prompt user for password input
    param([string]$Title = "Enter Script Password", [string]$LabelText = "Enter Password:")
    $form = New-Object Windows.Forms.Form
    $form.Text = $Title
    $form.Size = '300,150'
    $form.StartPosition = "CenterScreen"

    $label = New-Object Windows.Forms.Label
    $label.Text = $LabelText
    $label.AutoSize = $true
    $label.Location = '10,20'

    $textbox = New-Object Windows.Forms.TextBox
    $textbox.Location = '10,50'
    $textbox.Size = '260,20'
    $textbox.UseSystemPasswordChar = $true

    $okButton = New-Object Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = '200,80'
    $okButton.Add_Click({ $form.DialogResult = 'OK'; $form.Close() })

    $form.Controls.AddRange(@($label, $textbox, $okButton))
    $form.AcceptButton = $okButton
    $form.Add_Shown({ $form.Activate(); $form.BringToFront(); $form.Focus() })
    $form.ShowDialog() | Out-Null

    return $textbox.Text.Trim()
}

function ConvertTo-SHA256 {
    # Computes SHA256 hash for given string
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "EMPTY_INPUT" }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    return ($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Encrypt-Settings {
    # Encrypts settings JSON and stores securely in CLI XML
    param([string]$json)
    $secure = ConvertTo-SecureString $json -AsPlainText -Force
    $secure | Export-CliXml -Path $settingsPath
}

function Decrypt-Settings {
    # Decrypts and loads settings from CLI XML
    if (-not (Test-Path $settingsPath)) { return $null }
    $secure = Import-CliXml -Path $settingsPath
    return [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    ) | ConvertFrom-Json
}

function Save-Settings {
    # Saves config values as encrypted JSON
    param($settings)
    Encrypt-Settings ($settings | ConvertTo-Json -Depth 4)
}

function Log-Attempt {
    # Records signing attempt to log file (CSV)
    param([string]$EnteredPassword, [string]$Outcome, [string]$SignedScript = "")
    $logPath   = Join-Path $settings.LogDirectory "SigningActivityLog.csv"
    $logFolder = Split-Path $logPath
    if (-not (Test-Path $logFolder)) {
        New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
    }

    $masked = '*' * $EnteredPassword.Length
    $entry = [PSCustomObject]@{
        Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Outcome         = $Outcome
        EnteredPassword = $masked
        SignedFile      = $SignedScript
        Host            = $env:COMPUTERNAME
        User            = $env:USERNAME
        ToolVersion     = $toolVersion
        BuildTimestamp  = $buildTimestamp
    }

    $entry | Export-Csv -Path $logPath -Append -NoTypeInformation
}

function Test-IsAdmin {
    # Detects admin elevation status
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Load saved settings or perform one-time setup
$settings = Decrypt-Settings
if (-not $settings) {
    $settings = @{ LogDirectory = ""; CertThumbprint = ""; PasswordHash = "" }

    # Prompt user to select log storage folder
    $logDialog = New-Object Windows.Forms.FolderBrowserDialog
    $logDialog.Description = "Select folder to store log files"
    $logDialog.SelectedPath = $PSScriptRoot
    if ($logDialog.ShowDialog() -eq "OK") {
        $settings.LogDirectory = $logDialog.SelectedPath
    }

    # Prompt user to set initial password (hashed and stored)
    $settings.PasswordHash = ConvertTo-SHA256 (
        Prompt-ForPassword -Title "Set Script Password" -LabelText "Create a password for future use:"
    )

    Save-Settings $settings
    [Windows.Forms.MessageBox]::Show("Setup complete. Returning to main menu.", "Signer Ready", "OK", "Information")
}

# Start interactive menu loop
$exitMenu = $false
do {
    Write-Host "`nChoose operation mode:"
    Write-Host "1. Sign scripts"
    Write-Host "2. Reset password"
    Write-Host "3. Reset certificate"
    Write-Host "4. Create certificate"
    Write-Host "5. Exit"
    $selection = Read-Host "Enter selection (1–5)"

    switch ($selection) {
        '1' {
            $mode = "sign"
            $exitMenu = $true
        }

        '2' {
            # Reset script password
            $settings.PasswordHash = ConvertTo-SHA256 (Prompt-ForPassword)
            Save-Settings $settings
            [Windows.Forms.MessageBox]::Show("Password updated successfully.", "Reset Complete", "OK", "Information")
            $exitMenu = $true
        }

        '3' {
            # Reset signing certificate
            $certs = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey }
            if ($certs.Count -eq 0) {
                Write-Host "No usable certificates found in CurrentUser store."
                $exitMenu = $true
            } else {
                for ($i = 0; $i -lt $certs.Count; $i++) {
                    Write-Host "$i. [$($certs[$i].FriendlyName)] $($certs[$i].Subject)"
                }

                $choice = Read-Host "Enter certificate number"
                if ($choice -match '^\d+$' -and [int]$choice -lt $certs.Count) {
                    $settings.CertThumbprint = $certs[$choice].Thumbprint
                    Save-Settings $settings
                    [Windows.Forms.MessageBox]::Show("Certificate updated successfully.", "Reset Complete", "OK", "Information")
                } else {
                    Write-Host "Invalid selection."
                }
                $exitMenu = $true
            }
        }

        '4' {
            # Create and install new code-signing certificate
            $certName = Read-Host "Enter certificate subject (format: CN=YourCertName)"
            $subjectCN = ($certName -split "=")[-1] -replace '[^a-zA-Z0-9_-]', ''
            $pfxPassword = Read-Host "Set password to protect the .pfx file" -AsSecureString

            $folderDialog = New-Object Windows.Forms.FolderBrowserDialog
            $folderDialog.Description = "Choose folder to save certificate files"
            $folderDialog.SelectedPath = $PSScriptRoot
            if ($folderDialog.ShowDialog() -ne "OK") {
                Write-Host "Certificate creation cancelled. No folder selected."
                continue
            }
            $certFolder = $folderDialog.SelectedPath

            $cert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject $certName `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -KeyExportPolicy Exportable `
                -KeySpec Signature `
                -KeyLength 2048 `
                -HashAlgorithm "SHA256" `
                -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
                -KeyProtection ProtectHigh

            # Export private key as .pfx
            $pfxPath = Join-Path $certFolder "$subjectCN.pfx"
            Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword
            Write-Host "Certificate exported as '$subjectCN.pfx'. Keep this file secure."

            # Choose installation target
            do {
                Write-Host "`nSelect installation target:"
                Write-Host "1. CurrentUser"
                Write-Host "2. LocalMachine (requires admin rights)"
                Write-Host "3. Both"
                $installChoice = Read-Host "Enter choice (1–3)"
                $validChoice = $false
                $isAdmin = Test-IsAdmin

                switch ($installChoice) {
                    '1' {
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\CurrentUser\My" -Password $pfxPassword
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\CurrentUser\Root" -Password $pfxPassword
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\CurrentUser\TrustedPublisher" -Password $pfxPassword
                        $validChoice = $true
                    }
                    '2' {
                        if (-not $isAdmin) {
                            Write-Warning "Admin privileges required for LocalMachine. Re-run script as administrator."
                            continue
                        }
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\LocalMachine\My" -Password $pfxPassword
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\LocalMachine\Root" -Password $pfxPassword
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" -Password $pfxPassword
                        $validChoice = $true
                    }
                    '3' {
                        if (-not $isAdmin) {
                            Write-Warning "Admin privileges required for LocalMachine. Re-run script as administrator."
                            continue
                        }
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\CurrentUser\My" -Password $pfxPassword
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\CurrentUser\Root" -Password $pfxPassword
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\CurrentUser\TrustedPublisher" -Password $pfxPassword
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\LocalMachine\My" -Password $pfxPassword
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\LocalMachine\Root" -Password $pfxPassword
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" -Password $pfxPassword
                        $validChoice = $true
                    }
                    default {
                        Write-Host "Invalid selection. Choose 1, 2, or 3."
                    }
                }
            } while (-not $validChoice)

            # Export public key as .cer
            $cerPath = Join-Path $certFolder "$subjectCN.cer"
            Export-Certificate -Cert $cert -FilePath $cerPath
            Write-Host "Public certificate exported as '$subjectCN.cer'."

            $settings.CertThumbprint = $cert.Thumbprint
            Save-Settings $settings
            [Windows.Forms.MessageBox]::Show("Certificate creation and install complete.", "Success", "OK", "Information")
            $exitMenu = $true
        }

        '5' {
            Write-Host "Exiting Script Signer."
            exit
        }

        default {
            Write-Host "Invalid selection. Enter a number 1–5."
        }
    }
} while (-not $exitMenu)

if ($mode -eq "sign") {
    $success = $false
    for ($i = 1; $i -le 3; $i++) {
        $input = Prompt-ForPassword
        $inputHash = ConvertTo-SHA256 $input

        Write-Host "Entered hash: $inputHash"
        Write-Host "Stored hash:  $($settings.PasswordHash)"

        if ($inputHash -eq $settings.PasswordHash) {
            $success = $true
            Log-Attempt -EnteredPassword $input -Outcome "Password accepted"

            # Show success splash screen
            $form = New-Object Windows.Forms.Form
            $form.Text = "Access Granted"
            $form.Size = '400,160'
            $form.StartPosition = "CenterScreen"
            $form.TopMost = $true

            $label = New-Object Windows.Forms.Label
            $label.Font = "Segoe UI,11"
            $label.Text = "Authentication successful.`nVersion: $toolVersion`nBuilt: $buildTimestamp"
            $label.AutoSize = $true
            $label.Location = '50,50'

            $form.Controls.Add($label)
            $timer = New-Object Windows.Forms.Timer
            $timer.Interval = 4000
            $timer.Add_Tick({ $timer.Stop(); $form.Close() })
            $form.Add_Shown({ $form.Activate(); $form.BringToFront(); $form.Focus(); $timer.Start() })
            $form.ShowDialog()

            break
        } else {
            Log-Attempt -EnteredPassword $input -Outcome "Incorrect password"
            Write-Host "Incorrect password. ($i of 3)"
        }
    }

    if (-not $success) {
        Write-Host "Authentication failed after 3 attempts. Exiting."
        exit
    }

    # Prompt to select scripts to sign
    $fileDialog = New-Object Windows.Forms.OpenFileDialog
    $fileDialog.Title = "Select PowerShell scripts to sign"
    $fileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1"
    $fileDialog.Multiselect = $true
    $fileDialog.InitialDirectory = $PSScriptRoot

    $selected = @()
    if ($fileDialog.ShowDialog() -eq "OK") {
        $selected = $fileDialog.FileNames
    } else {
        Write-Host "No files selected. Exiting."
        exit
    }

    # Load certificate
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        $_.Thumbprint -eq $settings.CertThumbprint -and $_.HasPrivateKey
    }

    if (-not $cert) {
        Write-Host "Unable to locate certificate. Exiting."
        exit
    }

    # Sign each selected file
    $signedCount = 0
    $warnCount   = 0
    $failCount   = 0

    foreach ($file in $selected) {
        try {
            $result = Set-AuthenticodeSignature -FilePath $file -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
            switch ($result.Status) {
                'Valid' {
                    Write-Host "[✔] Signed '$file'"
                    Log-Attempt -EnteredPassword "✓" -Outcome "Signed" -SignedScript $file
                    $signedCount++
                }
                'UnknownError' {
                    Write-Host "[!] Warning signing '$file': Unknown status"
                    Log-Attempt -EnteredPassword "!" -Outcome "Warning" -SignedScript $file
                    $warnCount++
                }
                default {
                    Write-Warning "Failed to sign '$file'. Status: $($result.Status)"
                    Log-Attempt -EnteredPassword "×" -Outcome "Failed ($($result.Status))" -SignedScript $file
                    $failCount++
                }
            }
        } catch {
            Write-Warning "Error signing '$file': $_"
            Log-Attempt -EnteredPassword "×" -Outcome "Exception ($($_.Exception.Message))" -SignedScript $file
            $failCount++
        }
    }

    # Final summary dialog
    $form = New-Object Windows.Forms.Form
    $form.Text = "Signing Summary"
    $form.Size = '400,200'
    $form.StartPosition = "CenterScreen"

    $summary = New-Object Windows.Forms.Label
    $summary.Font = "Segoe UI,10"
    $summary.Text = "Signed: $signedCount`nWarnings: $warnCount`nFailed: $failCount"
    $summary.AutoSize = $true
    $summary.Location = '30,30'

    $viewButton = New-Object Windows.Forms.Button
    $viewButton.Text = "View Log"
    $viewButton.Location = '250,140'
    $viewButton.Add_Click({ 
        Start-Process notepad.exe (Join-Path $settings.LogDirectory "SigningActivityLog.csv")
        $form.Close()
    })

    $closeButton = New-Object Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.Location = '150,140'
    $closeButton.Add_Click({ $form.Close() })

    $form.Controls.AddRange(@($summary, $viewButton, $closeButton))
    $form.Add_Shown({ $form.Activate(); $form.BringToFront(); $form.Focus() })
    $form.ShowDialog()
}
