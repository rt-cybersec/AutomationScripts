<#
.SYNOPSIS
    Lists autorun entries that could indicate persistence mechanisms.

.DESCRIPTION
    This script enumerates common persistence mechanisms such as:
    - Startup folder programs
    - Run and RunOnce registry keys
    - Services and scheduled tasks (basic info)
    - WMI Event Consumers (optional, commented)

.NOTES
    File: startupPrograms.ps1
    Author: Rishabh Trivedi
    Usage: Run with PowerShell (preferably as Administrator for full coverage)
#>

Write-Host "`n=== Startup Programs & Persistence Mechanisms ===`n" -ForegroundColor Cyan

# 1. Startup folder (per-user and all-users)
Write-Host "`n[+] Startup Folder Entries:`n" -ForegroundColor Yellow
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem $folder | Select-Object FullName, LastWriteTime
    }
}

# 2. Registry Run / RunOnce keys
Write-Host "`n[+] Registry Run/RunOnce Entries:`n" -ForegroundColor Yellow
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        Write-Host "`n--- $path ---" -ForegroundColor Green
        $props = Get-ItemProperty $path
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                [PSCustomObject]@{
                    Name  = $prop.Name
                    Value = $prop.Value
                }
            }
        }
    }
}

# 3. Scheduled Tasks
Write-Host "`n[+] Scheduled Tasks (non-Microsoft):`n" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*"} | 
    Select-Object TaskName, TaskPath, State, Actions

# 4. Services (auto-start)
Write-Host "`n[+] Auto-start Services:`n" -ForegroundColor Yellow
Get-Service | Where-Object { $_.StartType -eq "Automatic" } |
    Select-Object DisplayName, Name, Status

# 5. (Optional) WMI Event Consumers – can be abused for persistence
<# Uncomment if needed
Write-Host "`n[+] WMI Event Consumers:`n" -ForegroundColor Yellow
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
#>

Write-Host "`n=== Enumeration Complete ===`n" -ForegroundColor Cyan
