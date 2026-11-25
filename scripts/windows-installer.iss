[Setup]
AppId=JustConnect
AppName=JustConnect
AppVersion={#AppVersion}
AppPublisher=JustConnect
AppPublisherURL=https://github.com/wtalioy/JustConnect
DefaultDirName={localappdata}\Programs\JustConnect
DisableDirPage=no
PrivilegesRequired=lowest
ArchitecturesAllowed={#TargetArchitecture}
DisableProgramGroupPage=yes
RestartApplications=no
SetupIconFile=..\resource\JustConnect.ico
UninstallDisplayIcon={app}\JustConnect.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "{#Payload}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Tasks]
Name: "startmenuicon"; Description: "Create a Start menu shortcut"

[Icons]
Name: "{autoprograms}\JustConnect"; Filename: "{app}\JustConnect.exe"; Tasks: startmenuicon

[Run]
Filename: "{app}\JustConnect.exe"; Parameters: "--remove-staged-installer ""{srcexe}"""; Flags: nowait runasoriginaluser; Check: IsJustConnectUpdate

[Code]
function OpenProcess(DesiredAccess, InheritHandle, ProcessId: LongWord): THandle;
  external 'OpenProcess@kernel32.dll stdcall';
function WaitForSingleObject(Handle: THandle; Milliseconds: LongWord): LongWord;
  external 'WaitForSingleObject@kernel32.dll stdcall';
function CloseHandle(Handle: THandle): LongWord;
  external 'CloseHandle@kernel32.dll stdcall';

function IsJustConnectUpdate: Boolean;
begin
  Result := StrToIntDef(ExpandConstant('{param:JCUPDATEPID|0}'), 0) > 0;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ProcessId: LongWord;
  ProcessHandle: THandle;
begin
  Result := '';
  if not IsJustConnectUpdate then Exit;
  ProcessId := StrToIntDef(ExpandConstant('{param:JCUPDATEPID|0}'), 0);
  ProcessHandle := OpenProcess($00100000, 0, ProcessId);
  if ProcessHandle = 0 then begin
    if DLLGetLastError <> 87 then Result := 'Unable to confirm that JustConnect has exited.';
    Exit;
  end;
  if WaitForSingleObject(ProcessHandle, 30000) <> 0 then
    Result := 'JustConnect is still closing. Select Install Update again after it exits.';
  CloseHandle(ProcessHandle);
end;
