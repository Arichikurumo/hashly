# Installs (or with -Uninstall removes) the extension for the current user. No admin needed.
param([switch]$Uninstall)
$dir = Join-Path $env:LOCALAPPDATA 'MalScan'
$dll = Join-Path $dir 'malscan.dll'
if ($Uninstall) {
    if (Test-Path $dll) { regsvr32 /s /u $dll }
    Write-Host 'Unregistered. Restart Explorer, then delete' $dir
    return
}
New-Item -ItemType Directory -Force $dir | Out-Null
# Explorer keeps the old DLL loaded; copy under a new name if the file is locked.
try { Copy-Item "$PSScriptRoot\build\malscan.dll" $dll -Force }
catch { Write-Warning 'malscan.dll is locked by Explorer. Run: Stop-Process -Name explorer (it restarts itself), then rerun.'; return }
regsvr32 /s $dll
Write-Host 'Installed. Right-click a file > Show more options > Scan with VirusTotal, or Properties > VirusTotal.'
Write-Host 'Put your API key into' (Join-Path $env:APPDATA 'MalScan\apikey.txt')
