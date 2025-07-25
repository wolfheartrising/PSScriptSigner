@{
    RootModule           = 'PSScriptSigner.ps1'
    ModuleVersion        = '4.0.0'
    Author               = 'Foresta Lupo'
    Description          = 'Secure signing utility for PowerShell scripts and EXEs. Includes encrypted config, credential reset, remote hash validation, and unified logging.'
    PowerShellVersion    = '5.1'
    RequiredModules      = @()
    FunctionsToExport    = @(
        'Sign-Files',
        'Reset-Credentials',
        'Write-LogEntry',
        'Show-StartupMenu',
        'Get-DecryptedConfig',
        'Get-RemoteHash',
        'Get-Hash'
    )
    PrivateData          = @{
        ProjectUri      = 'https://github.com/wolfheartrising/PSScriptSigner'
        LicenseUri      = 'https://opensource.org/licenses/MIT'
    }
}