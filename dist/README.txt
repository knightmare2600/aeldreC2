Runtime DLLs for Win32s / WFW 3.11 deployment
==============================================

  WSOCK32.DLL   -- Win32s Winsock (from Win32s 1.30 package)
  COMDLG32.DLL  -- Win32s common dialogs (from Win32s 1.30 package)
  CTL3DV2.DLL   -- Win16 3D controls (extracted from InnoSetup 1.2.16 sample,
                   Microsoft redistributable; gives dialogs beveled appearance
                   on Windows 3.1x / WFW 3.11)

Source: Microsoft Win32s 1.30 distribution (freely available on archive.org
and Winworld). Extract from the Win32s installer or from a WFW 3.11 disc
that includes the Win32s supplement.

IMPORTANT -- Win32s targets only
---------------------------------
These DLLs are Win32s-specific editions. They import W32SKRNL.DLL (the
Win32s kernel shim), which exists only on a WFW 3.11 machine with Win32s
installed. Do NOT copy these files to a Windows NT or Windows 95 machine:
  - On NT: native COMDLG32.DLL and WSOCK32.DLL are already in System32.
    Deploying these Win32s versions to an NT folder causes a startup failure
    because the loader finds W32SKRNL.DLL missing.
  - On Win95: same -- native DLLs in System32 are correct.

Deployment
----------
'make dist-win32' copies these DLLs automatically into output/win32s/ so
the output folder is self-contained for Win32s deployment.

On a Win32s machine with the standard Win32s 1.30 + Winsock32 packages
already installed, these DLLs are already in the Win32s system directory
and the output/win32s/ copies are redundant but harmless.

CTL3DV2.DLL note
----------------
CTL3DV2.DLL is generated automatically at build time: 'wmake dist' runs
innoextract on isetup16-1.2.16.exe, which includes CTL3DV2.DLL in its
sample directory as a Microsoft redistributable. The build copies it here.
Safe to redistribute; safe on Win32s, Win95, and NT.

Not included
------------
COMCTL32.DLL is NOT included. It is not part of Win32s and is not
compatible with WFW 3.11. It ships built into Windows 95 / NT 4.0 and
does not need to be bundled for those targets. Tools that require
COMCTL32 (winsftp.exe, putty.exe, puttytel.exe) are NT/Win95-only.
