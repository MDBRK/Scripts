<#
Scan files or directories for potential network connections (possible C2 indicators).
.PARAMETER Path
File or folder to scan.
# Scan a single file
.\C2Scan.ps1 -Path "C:\Users\user\script.ps1"

# Scan a folder recursively
.\C2Scan.ps1 -Path "C:\Users\user\Downloads"

#>

param (
    [Parameter(Mandatory=$true)]
    [string]$Path
)

# Regex patterns for potential network indicators
$networkPatterns = @(
    "\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",       # IPv4 addresses
    "(?i)https?://[^\s'\""]+",                 # URLs (HTTP/HTTPS)
    "(?i)ftp://[^\s'\""]+",                     # FTP URLs
    "(?i)(Invoke-WebRequest|Invoke-Expression|wget|curl)\b"  # PowerShell/network commands
)

# Function to scan a single file
function Scan-File {
    param([string]$File)

    try {
        $content = Get-Content -Path $File -Raw -ErrorAction Stop
        foreach ($pattern in $networkPatterns) {
            $matches = [regex]::Matches($content, $pattern)
            if ($matches.Count -gt 0) {
                Write-Output ("Potential network indicator found in {0}:" -f $File)
                $matches | ForEach-Object { Write-Output ("   {0}" -f $_) }
            }
        }
    } catch {
        Write-Output ("Failed to read {0}: {1}" -f $File, $_)
    }
}

# Check if path is file or directory
if (Test-Path $Path) {
    if ((Get-Item $Path).PSIsContainer) {
        # Directory: scan all files recursively
        Get-ChildItem -Path $Path -Recurse -File | ForEach-Object {
            Scan-File $_.FullName
        }
    } else {
        # Single file
        Scan-File $Path
    }
} else {
    Write-Output ("Path not found: {0}" -f $Path)
}

