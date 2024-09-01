# Your VirusTotal API key
$apiKey = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXxxx"

# Function to check a file against VirusTotal
function Check-FileAgainstVirusTotal {
    param (
        [string]$filePath
    )

    # Compute the file hash
    $hash = Get-FileHash -Path $filePath -Algorithm SHA256
    $fileHash = $hash.Hash

    # VirusTotal API endpoint for searching files by hash
    $url = "https://www.virustotal.com/api/v3/files/$fileHash"

    # Send request to VirusTotal
    try {
        $response = Invoke-RestMethod -Uri $url -Headers @{ "x-apikey" = $apiKey }

        if ($response.data) {
            $malicious = $response.data.attributes.last_analysis_stats.malicious
            if ($malicious -gt 0) {
                $vtUrl = "https://www.virustotal.com/gui/file/$fileHash"
                return @{ Status = "malicious"; Url = $vtUrl }
            } else {
                return @{ Status = "clean"; Url = "" }
            }
        } else {
            return @{ Status = "not found"; Url = "" }
        }
    } catch {
        Write-Output "Error checking file ${filePath}: $_"
        return @{ Status = "error"; Url = "" }
    }
}

# Get running services with detailed information
$services = Get-WmiObject Win32_Service | Where-Object { $_.State -eq 'Running' }

# Initialize an array to hold the results
$results = @()

# Check each service's executable path against VirusTotal
foreach ($service in $services) {
    $executablePath = $service.PathName -replace '"', ''
    if (Test-Path -Path $executablePath) {
        $result = Check-FileAgainstVirusTotal -filePath $executablePath
        if ($result.Status -ne "clean") {
            $results += [PSCustomObject]@{
                ServiceName    = $service.Name
                ExecutablePath = $executablePath
                Status         = $result.Status
                VirusTotalUrl  = $result.Url
            }
        }
    } else {
        Write-Output "Executable path for service ${service.Name} not found: $executablePath"
    }
}

# Export the results to a CSV file
$results | Export-Csv -Path "C:\Users\Dell\Desktop\Scripts\UncleanServices.csv" -NoTypeInformation

Write-Output "The results have been exported to C:\Users\Dell\Desktop\Scripts\UncleanServices.csv"