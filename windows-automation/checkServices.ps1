<#
.SYNOPSIS
    Checks running Windows services against VirusTotal for malware/vulnerability detection.

.DESCRIPTION
    This script fetches all running services, computes the hash of their executable path (if available),
    and queries the VirusTotal API for a security report.

.REQUIREMENTS
    - PowerShell 5.1 or later
    - VirusTotal API Key (Free/Pro)
    - Internet connectivity

.NOTES
    Author: Rishabh Trivedi (refactored with GPT-5)
#>

# ==============================
# CONFIGURATION
# ==============================
$apiKey = "274bd8f0c89c88bba0336e4c953598953f63b9cb880e7cb28377d3e52b899c83"
$VTUrl = "https://www.virustotal.com/api/v3/files/"
$Headers = @{ "x-apikey" = $ApiKey }
$ExportPath = "ServiceScanResults.csv"

# ==============================
# FUNCTIONS
# ==============================

function Get-FileHashSHA256 {
    param([string]$FilePath)

    try {
        if (Test-Path "$FilePath") {
            return (Get-FileHash -Algorithm SHA256 -Path "$FilePath").Hash
        } else {
            Write-Warning "File not found: $FilePath"
            return $null
        }
    } catch {
        Write-Warning "Error computing hash for ${FilePath}: $_"
        return $null
    }
}

function Invoke-VirusTotalApi {
    param([string]$FileHash)

    try {
        $response = Invoke-RestMethod -Method Get -Uri "$VTUrl$FileHash" -Headers $Headers -ErrorAction Stop
        return $response
    } catch {
        Write-Warning "VirusTotal query failed for hash ${FileHash}: $_"
        return $null
    }
}

function Test-Service {
    param([System.ServiceProcess.ServiceController]$Service)

    $exePath = (Get-WmiObject Win32_Service -Filter "Name='$($Service.Name)'" | Select-Object -ExpandProperty PathName) -replace '"',''
    
    if ([string]::IsNullOrWhiteSpace($exePath)) {
        Write-Output "Service '$($Service.Name)' has no executable path."
        return
    }

    # Extract only the EXE path (handles parameters in PathName)
    $exePath = $exePath.Split(" ")[0]

    $hash = Get-FileHashSHA256 -FilePath $exePath
    if (-not $hash) { return $null}

    $vtResult = Invoke-VirusTotalApi -FileHash $hash
    if ($vtResult) {
        $detections = $vtResult.data.attributes.last_analysis_stats.malicious
        $suspicious = $vtResult.data.attributes.last_analysis_stats.suspicious
        $link = "https://www.virustotal.com/gui/file/$hash"

        return [PSCustomObject]@{
            ServiceName    = $Service.DisplayName
            ExecutablePath = $exePath
            Hash           = $hash
            Malicious      = $detections
            Suspicious     = $suspicious
            VTLink         = $link
        }
    } else {
        return $null
    }
}

# ==============================
# MAIN EXECUTION
# ==============================
Write-Output "Starting Windows Services VirusTotal Scan..."
$services = Get-Service | Where-Object { $_.Status -eq "Running" }

$results = @()

foreach ($svc in $services) {
    $result = Test-Service -Service $svc
    if ($result) {
        $results += $result
        Write-Output "[$($result.ServiceName)] - Malicious: $($result.Malicious) | Suspicious: $($result.Suspicious)"
    }
}

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force
    Write-Output "✅ Scan completed! Results exported to $ExportPath"
} else {
    Write-Output "✅ Scan completed! No results to export."
}