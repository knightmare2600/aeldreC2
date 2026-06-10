/*
 * clip16.c  --  AeldreC2 clipboard tool for Windows 3.1 / WFW 3.11
 *
 * Reads from or writes to the Windows clipboard.
 * Launched via WinExec from COMMAND.COM; all output via MessageBox
 * (Win16 has no console subsystem).
 *
 * Usage:
 *   clip16                    display clipboard text in a dialog
 *   clip16 read               display clipboard text in a dialog
 *   clip16 read <file>        save clipboard text to <file>
 *   clip16 write <text>       write <text> to clipboard
 *
 * Build:
 *   wcc -ml -bt=windows -zu -s -I/opt/watcom/h/win clip16.c
 *   wlink system windows name clip16.exe file clip16.obj
 */

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#ifndef DEFAULT_GUI_FONT
#define DEFAULT_GUI_FONT SYSTEM_FONT
#endif
/* Win32 aliases not present in Win16 headers */
#ifndef MB_ICONERROR
#define MB_ICONERROR   MB_ICONSTOP
#endif
#ifndef MB_ICONWARNING
#define MB_ICONWARNING MB_ICONEXCLAMATION
#endif

static HINSTANCE g_hinst = NULL;

/* -------------------------------------------------------------------
 * Write text to the clipboard as CF_TEXT.
 * ------------------------------------------------------------------- */
static int clip_write(const char FAR *text)
{
    HGLOBAL hMem;
    char FAR *ptr;
    int len = lstrlen(text) + 1;

    hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, (DWORD)len);
    if (!hMem) return 0;
    ptr = (char FAR *)GlobalLock(hMem);
    if (!ptr) { GlobalFree(hMem); return 0; }
    lstrcpy(ptr, text);
    GlobalUnlock(hMem);

    if (!OpenClipboard(NULL)) { GlobalFree(hMem); return 0; }
    EmptyClipboard();
    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();
    return 1;
}

/* -------------------------------------------------------------------
 * Read CF_TEXT from clipboard into a GlobalAlloc'd buffer.
 * Caller must GlobalFree the returned handle (not the pointer).
 * Returns NULL if clipboard is empty or has no text.
 * ------------------------------------------------------------------- */
static HGLOBAL clip_read_hglobal(char FAR **out_ptr)
{
    HGLOBAL hSrc, hCopy;
    char FAR *src;
    char FAR *dst;
    DWORD len;

    if (!OpenClipboard(NULL)) return NULL;
    hSrc = GetClipboardData(CF_TEXT);
    if (!hSrc) { CloseClipboard(); return NULL; }
    src = (char FAR *)GlobalLock(hSrc);
    if (!src) { CloseClipboard(); return NULL; }
    len = (DWORD)lstrlen(src) + 1;
    hCopy = GlobalAlloc(GMEM_MOVEABLE, len);
    if (hCopy) {
        dst = (char FAR *)GlobalLock(hCopy);
        if (dst) { lstrcpy(dst, src); GlobalUnlock(hCopy); }
        else { GlobalFree(hCopy); hCopy = NULL; }
    }
    GlobalUnlock(hSrc);
    CloseClipboard();
    if (hCopy) *out_ptr = (char FAR *)GlobalLock(hCopy);
    return hCopy;
}

/* -------------------------------------------------------------------
 * WinMain
 * ------------------------------------------------------------------- */
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nShow)
{
    (void)hPrev; (void)nShow;
    g_hinst = hInst;

    /* skip leading whitespace */
    while (*lpCmd == ' ') lpCmd++;

    if (*lpCmd == '\0' ||
        (_fstrnicmp(lpCmd, "read", 4) == 0 &&
         (lpCmd[4] == '\0' || lpCmd[4] == ' '))) {

        /* ---- read mode ---- */
        const char FAR *filearg = NULL;
        if (_fstrnicmp(lpCmd, "read", 4) == 0 && lpCmd[4] == ' ') {
            filearg = lpCmd + 5;
            while (*filearg == ' ') filearg++;
            if (!*filearg) filearg = NULL;
        }

        {
            char FAR *text = NULL;
            HGLOBAL  hMem  = clip_read_hglobal(&text);
            if (!hMem || !text) {
                MessageBox(NULL,
                    "Clipboard is empty or contains no text.",
                    "clip16", MB_OK | MB_ICONINFORMATION);
            } else if (filearg && *filearg) {
                HFILE hf = _lcreat(filearg, 0);
                if (hf == HFILE_ERROR) {
                    char msg[MAX_PATH + 32];
                    wsprintf(msg, "Cannot create:\r\n%s", (LPSTR)filearg);
                    MessageBox(NULL, msg, "clip16", MB_OK | MB_ICONSTOP);
                } else {
                    if (_lwrite(hf, text, lstrlen(text)) == HFILE_ERROR) {
                        _lclose(hf);
                        MessageBox(NULL, "Write failed (disk full?).",
                                   "clip16", MB_OK | MB_ICONSTOP);
                    } else {
                        char msg[MAX_PATH + 48];
                        _lclose(hf);
                        wsprintf(msg, "Clipboard saved to:\r\n%s", (LPSTR)filearg);
                        MessageBox(NULL, msg, "clip16 -- saved",
                                   MB_OK | MB_ICONINFORMATION);
                    }
                }
            } else {
                /* show in dialog — cap at 1020 chars for readability */
                char buf[1025];
                int  tlen = lstrlen(text);
                if (tlen > 1020) {
                    _fmemcpy(buf, text, 1020);
                    lstrcpy(buf + 1020, "...");
                } else {
                    lstrcpy(buf, text);
                }
                MessageBox(NULL, buf, "clip16 -- clipboard",
                           MB_OK | MB_ICONINFORMATION);
            }
            if (hMem) { GlobalUnlock(hMem); GlobalFree(hMem); }
        }

    } else if (_fstrnicmp(lpCmd, "write", 5) == 0 && lpCmd[5] == ' ') {

        /* ---- write mode ---- */
        const char FAR *text = lpCmd + 6;
        while (*text == ' ') text++;
        if (!*text) {
            MessageBox(NULL, "Usage: clip16 write <text>",
                       "clip16", MB_OK | MB_ICONEXCLAMATION);
        } else if (clip_write(text)) {
            char msg[64];
            wsprintf(msg, "%d character(s) written to clipboard.", lstrlen(text));
            MessageBox(NULL, msg, "clip16 -- written",
                       MB_OK | MB_ICONINFORMATION);
        } else {
            MessageBox(NULL, "Failed to write to clipboard.",
                       "clip16", MB_OK | MB_ICONSTOP);
        }

    } else {
        MessageBox(NULL,
            "clip16  \xc6ldreC2 clipboard tool for WFW 3.11\r\n\r\n"
            "Usage:\r\n"
            "  clip16                  display clipboard text\r\n"
            "  clip16 read             display clipboard text\r\n"
            "  clip16 read <file>      save clipboard text to file\r\n"
            "  clip16 write <text>     write text to clipboard",
            "clip16 -- help", MB_OK | MB_ICONINFORMATION);
    }

    return 0;
}
