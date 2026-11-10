[Setup]
AppId=JustConnect
AppName=JustConnect
AppVersion={#AppVersion}
AppPublisher=JustConnect
AppPublisherURL=https://github.com/wtalioy/JustConnect
DefaultDirName={localappdata}\Programs\JustConnect
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

[Icons]
Name: "{autoprograms}\JustConnect"; Filename: "{app}\JustConnect.exe"
