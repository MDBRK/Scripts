#How to use : 
# ./Script.ps1 -Name software-name    


param(
  [Parameter(Mandatory=$true)][string]$Name
)

Write-Host "`n=== Persistence & Hidden Process Hunt for: $Name ===`n" -ForegroundColor Cyan
$R = [System.Collections.Generic.List[psobject]]::new()
function Add($t,$n,$v){ $R.Add([pscustomobject]@{Type=$t;Name=$n;Info=$v}) }

# -------------------------------------------------------------
# 1) Common file locations (deep & extended)
# -------------------------------------------------------------
$paths = @(
   "$env:ProgramFiles\$Name\$Name.exe",
  "$env:ProgramFiles(x86)\$Name\$Name.exe",
  "$env:ProgramData\$Name\$Name.exe",
  "$env:ProgramData\$Name\",
  "$env:APPDATA\$Name\$Name.exe",
  "$env:LOCALAPPDATA\$Name\$Name.exe",
  "$env:SystemRoot\System32\$Name.exe",
  "$env:SystemRoot\SysWOW64\$Name.exe",
  "$env:TEMP\$Name.exe",
  "$env:USERPROFILE\Downloads\$Name.exe",
  "$env:USERPROFILE\AppData\Local\Temp\$Name.exe"

)
foreach($p in $paths){
  if (Test-Path $p) { Add "FileFound" $p "Exists" }
}

# Search disk for suspicious matches (light search, not full drive)
$searchRoots = @("$env:ProgramData","$env:APPDATA","$env:LOCALAPPDATA","$env:USERPROFILE\Downloads","$env:SystemDrive\Users")
foreach($root in $searchRoots){
  if (Test-Path $root) {
    Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue -Include "*.exe","*.dll" |
      Where-Object { $_.FullName -match $Name } |
      ForEach-Object { Add "FileMatch" $_.FullName ("Size: " + $_.Length + " bytes") }
  }
}

# -------------------------------------------------------------
# 2) Services (by name/display/path)
# -------------------------------------------------------------
Get-CimInstance Win32_Service | ForEach-Object {
  if ( ($_.Name -match $Name) -or ($_.DisplayName -match $Name) -or ($_.PathName -match $Name) ) {
    Add "Service" $_.Name ($_.State + " | " + $_.PathName)
  }
}

# -------------------------------------------------------------
# 3) Processes (live processes and command lines)
# -------------------------------------------------------------
Get-CimInstance Win32_Process | Where-Object {
  ($_.Name -match $Name) -or ($_.CommandLine -and $_.CommandLine -match $Name)
} | ForEach-Object { Add "Process" $_.ProcessId ($_.CommandLine) }

# -------------------------------------------------------------
# 4) Network connections
# -------------------------------------------------------------
$net = netstat -ano 2>$null | findstr /i $Name
if ($net) { Add "Netstat" "Matching lines" ($net -join "`n") }

# -------------------------------------------------------------
# 5) Scheduled tasks
# -------------------------------------------------------------
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  $xml = (Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue) -as [string]
  if ($xml -and $xml -match $Name) { Add "ScheduledTask" $_.TaskName $_.TaskPath }
}

# -------------------------------------------------------------
# 6) Registry Run keys
# -------------------------------------------------------------
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach($k in $runKeys){
  if (Test-Path $k) {
    Get-ItemProperty -Path $k | ForEach-Object {
      $_.PSObject.Properties | ForEach-Object {
        if ($_.Value -and ($_.Value -match $Name)) { Add "RegistryRun" "$k\$($_.Name)" $_.Value }
      }
    }
  }
}

# -------------------------------------------------------------
# 7) Startup folder entries
# -------------------------------------------------------------
$starts = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
foreach($s in $starts){
  if (Test-Path $s) {
    Get-ChildItem -Path $s -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      if ($_.Name -match $Name) { Add "StartupFile" $_.FullName $_.Length }
      elseif (($_.Extension -in '.lnk','.bat','.ps1') -and (Get-Content $_.FullName -ErrorAction SilentlyContinue) -match $Name) {
        Add "StartupFileContent" $_.FullName "Contains $Name"
      }
    }
  }
}

# -------------------------------------------------------------
# 8) Signature verification
# -------------------------------------------------------------
$foundFiles = $R | Where-Object { $_.Type -match 'File' } | Select-Object -ExpandProperty Name -Unique
foreach($f in $foundFiles){ if (Test-Path $f) {
  $sig = Get-AuthenticodeSignature $f
  Add "Signature" $f ("Status=" + $sig.Status + " | Publisher=" + ($sig.SignerCertificate.Subject -as [string]))
}}

# -------------------------------------------------------------
# Output
# -------------------------------------------------------------
if ($R.Count -eq 0) {
  Write-Host "No matches found for '$Name'." -ForegroundColor Green
} else {
  $R | Sort-Object Type | Format-Table -AutoSize
}
Write-Host "`n=== Scan complete ===`n" -ForegroundColor Cyan
