; PineCrack Community wizard installer (Inno Setup 6)
; Compile:  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" PineCrackCE.iss
; Requires PineCrack.exe next to this script (build it first: build_exe.bat)

#define AppName "PineCrack Community"
#define AppVer "2.2"
#define AppExe "PineCrack.exe"

[Setup]
AppId={{9A21D7C4-PINE-CRAK-COMM-000000000001}
AppName={#AppName}
AppVersion={#AppVer}
DefaultDirName={autopf}\PineCrack
DefaultGroupName=PineCrack
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=PineCrack-Community-Setup
SetupIconFile=pinecrack.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "wsltools"; Description: "Set up WSL + hcxtools  (enables local .pcap/.cap to .hc22000 conversion; downloads ~500 MB, may need a restart)"; GroupDescription: "Local capture conversion:"
Name: "gettools"; Description: "Download + install hashcat + aircrack-ng  (the cracking engine; ~70 MB from official sites, falls back to your server)"; GroupDescription: "Cracking engine:"
Name: "getperl"; Description: "Install Strawberry Perl  (optional - enables John's .pl hash extractors like 7z2john.pl for password-protected archives; ~152 MB)"; GroupDescription: "Cracking engine:"; Flags: unchecked

[Files]
Source: "PineCrack.exe";     DestDir: "{app}"; Flags: ignoreversion
Source: "setup-wsl.ps1";     DestDir: "{app}"; Flags: ignoreversion
Source: "install-tools.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "install-perl.ps1";  DestDir: "{app}"; Flags: ignoreversion
Source: "7zr.exe";           DestDir: "{app}"; Flags: ignoreversion
Source: "UnRAR.exe";         DestDir: "{app}"; Flags: ignoreversion
Source: "README.md";         DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "LICENSE";           DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\PineCrack";              Filename: "{app}\{#AppExe}"
Name: "{group}\PineCrack - Set up WSL"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup-wsl.ps1"""; IconFilename: "{app}\{#AppExe}"; Comment: "Install / repair WSL + hcxtools for local .pcap conversion"
Name: "{group}\PineCrack - Install hashcat"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install-tools.ps1"""; IconFilename: "{app}\{#AppExe}"; Comment: "Download + install hashcat / aircrack-ng (official, or your server)"
Name: "{group}\PineCrack - Install Perl"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install-perl.ps1"""; IconFilename: "{app}\{#AppExe}"; Comment: "Install Strawberry Perl for John's .pl hash extractors"
Name: "{group}\Uninstall PineCrack";    Filename: "{uninstallexe}"
Name: "{autodesktop}\PineCrack";        Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install-tools.ps1"""; StatusMsg: "Downloading + installing hashcat / aircrack-ng (this can take a few minutes)..."; Flags: waituntilterminated; Tasks: gettools
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install-perl.ps1"""; StatusMsg: "Downloading + installing Strawberry Perl (~152 MB)..."; Flags: waituntilterminated; Tasks: getperl
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup-wsl.ps1"""; StatusMsg: "Setting up WSL + hcxtools (this can take several minutes)..."; Flags: waituntilterminated; Tasks: wsltools
Filename: "{app}\{#AppExe}"; Description: "Launch PineCrack now"; Flags: nowait postinstall skipifsilent

[Code]
var
  WordlistPage, LootPage: TInputQueryWizardPage;

procedure BrowseWordlist(Sender: TObject);
var s: String;
begin
  s := WordlistPage.Values[0];
  if BrowseForFolder('Select your wordlist folder', s, False) then
    WordlistPage.Values[0] := s;
end;

procedure BrowseLoot(Sender: TObject);
var s: String;
begin
  s := LootPage.Values[0];
  if BrowseForFolder('Select your capture / loot folder', s, False) then
    LootPage.Values[0] := s;
end;

procedure AddBrowseButton(Page: TInputQueryWizardPage; Handler: TNotifyEvent);
var b: TNewButton;
begin
  b := TNewButton.Create(WizardForm);
  b.Parent := Page.Surface;
  b.Width := ScaleX(80);
  b.Height := ScaleY(23);
  b.Left := Page.SurfaceWidth - b.Width;
  b.Top := Page.Edits[0].Top + Page.Edits[0].Height + ScaleY(8);
  b.Caption := 'Browse...';
  b.OnClick := Handler;
end;

procedure InitializeWizard;
begin
  { Input-QUERY pages (not InputDir) so an empty value is allowed = "use bundled". }
  WordlistPage := CreateInputQueryPage(wpSelectTasks,
    'Wordlist folder', 'Where do you keep your wordlists?',
    'Optional - pick a folder with your own wordlists, or leave blank to use the bundled starter lists.');
  WordlistPage.Add('Wordlist folder (optional):', False);
  AddBrowseButton(WordlistPage, @BrowseWordlist);

  LootPage := CreateInputQueryPage(WordlistPage.ID,
    'Handshake / capture folder', 'Where do you keep your captures?',
    'Optional - pick a folder with your .pcap / .hc22000 captures, or leave blank to skip.');
  LootPage.Add('Capture folder (optional):', False);
  AddBrowseButton(LootPage, @BrowseLoot);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  cfgDir, wl, lt, json: String;
begin
  if CurStep = ssPostInstall then
  begin
    wl := WordlistPage.Values[0];
    lt := LootPage.Values[0];
    StringChangeEx(wl, '\', '\\', True);
    StringChangeEx(lt, '\', '\\', True);
    cfgDir := ExpandConstant('{localappdata}\PineCrack');
    CreateDir(cfgDir);
    json := '{' + #13#10 +
            '  "wordlist_dir": "' + wl + '",' + #13#10 +
            '  "loot_dir": "' + lt + '"' + #13#10 +
            '}';
    SaveStringToFile(cfgDir + '\pinecrack_config.json', json, False);
  end;
end;
