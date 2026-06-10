; ntstub.asm  --  AeldreC2 DOS stub for NT-only console tools
;
; This stub is embedded as the MZ DOS header of SUBSYSTEM_CONSOLE PE
; binaries.  It runs when the PE is launched under MS-DOS, Windows 3.x,
; or Win32s, which cannot execute NT console executables.  Instead of
; the default cryptic "This program cannot be run in DOS mode" message
; it prints a clear explanation and exits with code 1.
;
; Build (OpenWatcom, 16-bit):
;   wasm -ms ntstub.asm
;   wlink system dos file ntstub.obj name ntstub.exe
;
; Wire into a PE via wcl386/wlink:
;   option stub=ntstub.exe
;

.8086
.model small
.stack 32

.data
msg     db  13, 10
        db  "AeldreC2: This tool requires Windows NT 3.1 or later.", 13, 10
        db  "It cannot run under MS-DOS, Windows 3.x, or Win32s.", 13, 10
        db  13, 10, "$"

.code
start:
        mov     ax, @data
        mov     ds, ax
        mov     dx, offset msg
        mov     ah, 9
        int     21h
        mov     ax, 4c01h
        int     21h

end start
