Place runtime DLLs here for bundling into setup.exe:

  WSOCK32.DLL   -- Win32s Winsock (from Win32s 1.30 package)
  COMDLG32.DLL  -- Win32s common dialogs (from Win32s 1.30 package)

Source: Microsoft Win32s 1.30 distribution (freely available on archive.org
and Winworld). Extract from the Win32s installer or from a WFW 3.11 disc
that includes the Win32s supplement.

NOTE: COMCTL32.DLL is NOT included. It is not part of Win32s and is not
compatible with Windows 3.11. It ships built into Windows 95 / NT 4.0 and
does not need to be bundled for those targets.
