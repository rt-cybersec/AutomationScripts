# Path where the report will be saved
$filePath = "C:\Reports\Current_AD_Users.csv"
$daysInactive = 90
$inactiveDate = (Get-Date).AddDays(-$daysInactive)

# 1. Ensure the directory exists
$dir = Split-Path $filePath
if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force }

# 2. Fetch current AD User Data
try {
    # We use -Filter * to get everyone, then calculate status
    $currentUsers = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, EmailAddress | Select-Object `
        Name, 
        SamAccountName, 
        EmailAddress,
        Enabled, 
        @{Name="LastLogon"; Expression={$_.LastLogonDate}},
        @{Name="Status"; Expression={
            if ($_.Enabled -eq $false) { "Disabled" }
            elseif ($_.LastLogonDate -lt $inactiveDate -and $_.LastLogonDate -ne $null) { "Inactive" }
            else { "Active" }
        }}

    # 3. Export/Overwrite the CSV
    # Removing -Append causes PowerShell to overwrite the file with fresh data
    $currentUsers | Export-Csv -Path $filePath -NoTypeInformation -Force
    
    Write-Host "Current user list updated successfully at $filePath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to update AD user list: $($_.Exception.Message)"
}