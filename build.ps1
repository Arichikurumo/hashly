# Builds build\malscan.dll (x64, static CRT). Needs VS Build Tools with the C++ workload.
# -Installer additionally builds dist\MalScan-Setup-<version>.exe (needs Inno Setup 6).
param([switch]$Installer)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual Studio C++ build tools not found.' }
New-Item -ItemType Directory -Force build | Out-Null
$bat = @"
@echo off
set "PATH=%PATH%;${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
call "$vs\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
rc /nologo /fo build\malscan.res src\malscan.rc || exit /b 1
cl /nologo /std:c++17 /EHsc /O2 /MT /LD /W3 src\malscan.cpp build\malscan.res /Fo:build\ /Fe:build\malscan.dll /link /DEF:src\malscan.def ole32.lib shell32.lib shlwapi.lib winhttp.lib bcrypt.lib user32.lib gdi32.lib advapi32.lib comctl32.lib uxtheme.lib uuid.lib || exit /b 1
"@
Set-Content build\build.bat $bat -Encoding ascii
cmd /c build\build.bat
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
Write-Host 'OK: build\malscan.dll'

if ($Installer) {
    $iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) { throw 'Inno Setup 6 not found (winget install JRSoftware.InnoSetup).' }
    & $iscc /Qp installer\malscan.iss
    if ($LASTEXITCODE -ne 0) { throw 'Installer build failed.' }
    Write-Host 'OK: dist\MalScan-Setup-*.exe'
}
