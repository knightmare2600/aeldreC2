; AeldreC2 -- Win32s / Win95 / NT installer
; Built with InnoSetup 1.2.16 (jrsoftware.org/isdl-old.php)
;
; PREREQUISITE: On Windows 3.11 / WFW 3.11, Win32s 1.30 must already be
; installed before running this installer.  Install it with the redistributable
; fetched via fetch-win32s.sh, then run setup32.exe.
; On Windows 95 and NT 3.x / 4.x no prerequisites are required.
;
; Build (from windows/ directory inside the Docker build container):
;   innoextract -d /tmp/aeldrec2-inno ../dist/isetup16-1.2.16.exe
;   wine /tmp/aeldrec2-inno/app/ISCC.EXE setup32.iss

[Setup]
AppName=AeldreC2
AppVerName=AeldreC2
AppPublisher=knightmare2600
DefaultDirName={pf}\AeldreC2
DefaultGroupName=AeldreC2
LicenseFile=..\gpl30.txt
OutputDir=.
OutputBaseFilename=setup32

[Tasks]
Name: nttools; Description: NT-only tools (Windows NT 3.1 or later); Flags: unchecked

[Files]
; ------ Core operator tools: Win32s + Win95 + NT ------
Source: joshua.exe;   DestDir: {app}; Flags: ignoreversion
Source: tank.exe;     DestDir: {app}; Flags: ignoreversion
Source: clu.exe;      DestDir: {app}; Flags: ignoreversion
Source: flynn.exe;    DestDir: {app}; Flags: ignoreversion
Source: ncwfw.exe;    DestDir: {app}; Flags: ignoreversion
Source: grid.exe;     DestDir: {app}; Flags: ignoreversion
Source: clip.exe;     DestDir: {app}; Flags: ignoreversion
Source: wget.exe;     DestDir: {app}; Flags: ignoreversion
Source: ipcalc32.exe; DestDir: {app}; Flags: ignoreversion
Source: markuped.exe; DestDir: {app}; Flags: ignoreversion
Source: yori32.exe;   DestDir: {app}; Flags: ignoreversion
Source: jloshtog.exe; DestDir: {app}; Flags: ignoreversion
Source: net-stat.exe; DestDir: {app}; Flags: ignoreversion
Source: aelctl.dll;   DestDir: {app}; Flags: ignoreversion

; ------ NT-only tools (optional, unchecked by default) ------
Source: lightman.exe; DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: ncnt.exe;     DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: gridcli.exe;  DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: gridnt.exe;   DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: grid32.exe;   DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: netstatN.exe; DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: route.exe;    DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: svcany.exe;   DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: regcli.exe;   DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: whoami.exe;   DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: arp.exe;      DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: stager.exe;   DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: timestmp.exe; DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: yoriview.exe; DestDir: {app}; Tasks: nttools; Flags: ignoreversion
Source: dumont.exe;   DestDir: {app}; Tasks: nttools; Flags: ignoreversion

[Icons]
Name: {group}\Joshua C2 Controller;  Filename: {app}\joshua.exe
Name: {group}\CLU Implant Generator; Filename: {app}\clu.exe
Name: {group}\Flynn Operator Client; Filename: {app}\flynn.exe
Name: {group}\ncwfw Netcat TLS;      Filename: {app}\ncwfw.exe
Name: {group}\Uninstall AeldreC2;    Filename: {uninstallexe}

[UninstallDelete]
Type: dirifempty; Name: {app}
