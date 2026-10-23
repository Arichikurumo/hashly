; Inno Setup script. Build with: ./build.ps1 -Installer
#define AppName "Hashly"
#define AppVersion "1.0.2"

[Setup]
AppId={{7B3C5E52-4A1D-4C8E-9F26-5D1B8E0A6C31}
AppName={#AppName} (VirusTotal for Explorer)
AppVersion={#AppVersion}
AppPublisher=Hashly
DefaultDirName={localappdata}\{#AppName}
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=Hashly-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName} (VirusTotal for Explorer)

[Files]
; restartreplace: if Explorer still holds an older copy, it is swapped at the next sign-in/reboot.
Source: "..\build\hashly.dll"; DestDir: "{app}"; Flags: ignoreversion restartreplace uninsrestartdelete

[Run]
Filename: "{sys}\regsvr32.exe"; Parameters: "/s ""{app}\hashly.dll"""; Flags: runhidden; StatusMsg: "Registering Explorer extension..."

[UninstallRun]
Filename: "{sys}\regsvr32.exe"; Parameters: "/s /u ""{app}\hashly.dll"""; Flags: runhidden; RunOnceId: "UnregHashly"

[Code]
var
  KeyPage: TInputQueryWizardPage;

function KeyFile: String;
begin
  Result := ExpandConstant('{userappdata}\Hashly\apikey.txt');
end;

procedure InitializeWizard;
begin
  KeyPage := CreateInputQueryPage(wpWelcome, 'VirusTotal API key',
    'Optional: you can also set this later.',
    'Paste your free VirusTotal API key (virustotal.com > profile > API key). ' +
    'It is stored only in ' + KeyFile + '.');
  KeyPage.Add('API key:', False);
  if FileExists(KeyFile) then
    KeyPage.Values[0] := '';  // never display an existing key
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Key: String;
begin
  if (CurStep = ssPostInstall) then
  begin
    Key := Trim(KeyPage.Values[0]);
    if Key <> '' then
    begin
      ForceDirectories(ExtractFileDir(KeyFile));
      SaveStringToFile(KeyFile, Key, False);
    end;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  // keep the existing key on upgrades
  Result := (PageID = KeyPage.ID) and FileExists(KeyFile);
end;
