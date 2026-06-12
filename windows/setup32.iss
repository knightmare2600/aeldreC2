; AeldreC2 -- installer for Windows 3.1x / Win32s / Win95 / NT
; Built with InnoSetup 1.2.16 16-bit edition (isetup16-1.2.16.exe)
;
; The installer itself is a Win16 NE executable produced by COMPIL16.EXE.
; It runs on bare Windows 3.1x / WFW 3.11 (no Win32s required to run
; the installer), as well as on Win32s, Win95, and NT 3.x / 4.x.
; The files it installs are Win32 PE executables targeting Win32s / NT.
;
; Build (automated via wmake dist / tools/run_inno16.sh):
;   innoextract -d /tmp/aeldrec2-inno ../dist/isetup16-1.2.16.exe
;   xvfb-run wine /tmp/aeldrec2-inno/app/COMPIL16.EXE setup32.iss

[Setup]
AppName=AeldreC2
AppVerName=AeldreC2
AppPublisher=knightmare2600
DefaultDirName={pf}\AeldreC2
DefaultGroupName=AeldreC2
LicenseFile=..\gpl30.txt
OutputDir=.
OutputBaseFilename=setup32

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
; ------ NT-only tools (carry DOS stub on wrong platform) ------
Source: lightman.exe; DestDir: {app}; Flags: ignoreversion
Source: ncnt.exe;     DestDir: {app}; Flags: ignoreversion
Source: gridcli.exe;  DestDir: {app}; Flags: ignoreversion
Source: gridnt.exe;   DestDir: {app}; Flags: ignoreversion
Source: grid32.exe;   DestDir: {app}; Flags: ignoreversion
Source: netstatN.exe; DestDir: {app}; Flags: ignoreversion
Source: route.exe;    DestDir: {app}; Flags: ignoreversion
Source: svcany.exe;   DestDir: {app}; Flags: ignoreversion
Source: regcli.exe;   DestDir: {app}; Flags: ignoreversion
Source: whoami.exe;   DestDir: {app}; Flags: ignoreversion
Source: arp.exe;      DestDir: {app}; Flags: ignoreversion
Source: stager.exe;   DestDir: {app}; Flags: ignoreversion
Source: timestmp.exe; DestDir: {app}; Flags: ignoreversion
Source: yoriview.exe; DestDir: {app}; Flags: ignoreversion
Source: dumont.exe;   DestDir: {app}; Flags: ignoreversion

[Icons]
Name: {group}\Joshua C2 Controller;  Filename: {app}\joshua.exe
Name: {group}\CLU Implant Generator; Filename: {app}\clu.exe
Name: {group}\Flynn Operator Client; Filename: {app}\flynn.exe
Name: {group}\ncwfw Netcat TLS;      Filename: {app}\ncwfw.exe
Name: {group}\Uninstall AeldreC2;    Filename: {uninstallexe}

[UninstallDelete]
Type: dirifempty; Name: {app}
