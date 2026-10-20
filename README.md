# Hashly

Windows Explorer shell extension that checks a file against [VirusTotal](https://www.virustotal.com).

- Adds a **VirusTotal** tab to the file *Properties* dialog and a **Scan with VirusTotal** right-click entry
  (Windows 11: under *Show more options*).
- Computes the file's SHA-256 and looks it up via the VirusTotal v3 API. **Only the hash is sent; the file is never uploaded.**
- Shows a score ring (e.g. 5/72), a headline, a proportion bar and a per-vendor result table.

## Requirements

- Windows 10/11 x64
- Visual Studio Build Tools with the C++ workload (to build)
- A free VirusTotal API key (4 requests/min, 500/day)

## Installer

```powershell
./build.ps1 -Installer     # -> dist\Hashly-Setup-1.0.0.exe (needs Inno Setup 6: winget install JRSoftware.InnoSetup)
```

The setup is per-user (no admin), optionally asks for your API key, and can be removed via *Apps & features*.

## Build, install, remove (without the installer)

```powershell
./build.ps1                # -> build\hashly.dll
./install.ps1              # copies to %LOCALAPPDATA%\Hashly and registers per user (HKCU, no admin)
./install.ps1 -Uninstall
```

If Explorer has an older copy loaded, `install.ps1` warns; run `Stop-Process -Name explorer` (it restarts itself) and rerun.

## API key

Put the key on one line in `%APPDATA%\Hashly\apikey.txt`, or set the `VT_API_KEY` environment variable.
The tab's *API key file...* button creates and opens the file.

## Notes

MD5 is shown for information only (some tools still list files by MD5). It is not used for the lookup because it is collision-prone: a crafted file could borrow another file's clean verdict. A "no detections" result only means VirusTotal's engines flag nothing for this exact SHA-256.
