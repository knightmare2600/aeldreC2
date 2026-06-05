/*
 * setup16.c -- AeldreC2 Win16 self-extracting installer
 *
 * Wizard pages: Welcome -> License (GPL3) -> Components ->
 *               DLL Options (conditional) -> Confirm -> Progress/Done
 *
 * Build (from windows/ directory):
 *   wcc -ml -bt=windows -zu -s -I/opt/watcom/h/win -fo=setup16.obj setup16.c
 *   wlink system windows name setup16.exe file setup16.obj library commdlg.lib
 *   wrc setup16.res setup16.exe
 *   python3 ../tools/mksetup.py   <- bundles EXEs into self-extracting setup.exe
 */

#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>
#include <direct.h>

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define IDR_GPL3         100
#define IDD_WELCOME      101
#define IDD_LICENSE      102
#define IDD_COMPONENTS   103
#define IDD_DLLOPTS      104
#define IDD_CONFIRM      105
#define IDD_PROGRESS     106

#define IDC_LIC_TEXT     201
#define IDC_LIC_ACCEPT   202
#define IDC_C2_CHECK     210
#define IDC_C2_PATH      211
#define IDC_C2_BROWSE    212
#define IDC_PUTTY_CHECK  213
#define IDC_PUTTY_PATH   214
#define IDC_PUTTY_BROWSE 215
#define IDC_DLL_CHECK    216
#define IDC_DLL_WARN     217
#define IDC_DLL_APPDIR   220
#define IDC_DLL_SYSDIR   221
#define IDC_CONFIRM_TXT  230
#define IDC_PROG_FILE    240
#define IDC_PROG_PCT     241
#define IDC_PROG_LOG     242

#define IDC_BACK         1001

#define WIZ_CANCEL  0
#define WIZ_NEXT    1
#define WIZ_BACK    2

/* Bundle destination codes (must match mksetup.py) */
#define DEST_C2    0
#define DEST_PUTTY 1
#define DEST_DLL   2
#define DEST_ROOT  3   /* same dir as C2 (GRP, TXT) */

#define BUNDLE_MAGIC  0x31444C41UL   /* 'ALD1' little-endian */
#define MAX_ENTRIES   96

/* ------------------------------------------------------------------ */
/* Bundle structures — packed to match Python struct.pack              */
/* ------------------------------------------------------------------ */

#pragma pack(1)
typedef struct {
    char  name[64];
    BYTE  dest;
    DWORD off;
    DWORD size;
} BundleEntry;   /* 73 bytes */

typedef struct {
    DWORD index_off;
    DWORD n_files;
    DWORD magic;
} BundleFooter;  /* 12 bytes */
#pragma pack()

/* ------------------------------------------------------------------ */
/* Globals                                                              */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hinst;
static HWND      g_hwnd_main;

static BOOL g_inst_c2    = TRUE;
static char g_c2_path[MAX_PATH]    = "C:\\Hack";
static BOOL g_inst_putty = FALSE;
static char g_putty_path[MAX_PATH] = "C:\\Programs\\Putty";
static BOOL g_inst_dlls  = TRUE;
static int  g_dll_dest   = 0;   /* 0=app dirs, 1=C:\Windows\System */

static BundleEntry g_entries[MAX_ENTRIES];
static int         g_nentries = 0;
static BOOL        g_bundled  = FALSE;

static HWND   g_hwnd_progress = NULL;
static int    g_prog_done     = 0;
static int    g_gauge_pct     = 0;
static WNDPROC g_gauge_oldproc = NULL;

static const char *k_dll_names[] = { "WSOCK32.DLL", "COMDLG32.DLL", NULL };

/* ------------------------------------------------------------------ */
/* Forward declarations                                                 */
/* ------------------------------------------------------------------ */

BOOL __export CALLBACK WelcomeDlgProc  (HWND, UINT, WPARAM, LPARAM);
BOOL __export CALLBACK LicenseDlgProc  (HWND, UINT, WPARAM, LPARAM);
BOOL __export CALLBACK CompsDlgProc    (HWND, UINT, WPARAM, LPARAM);
BOOL __export CALLBACK DllOptsDlgProc  (HWND, UINT, WPARAM, LPARAM);
BOOL __export CALLBACK ConfirmDlgProc  (HWND, UINT, WPARAM, LPARAM);
BOOL __export CALLBACK ProgressDlgProc (HWND, UINT, WPARAM, LPARAM);

/* ------------------------------------------------------------------ */
/* Bundle helpers                                                       */
/* ------------------------------------------------------------------ */

static BOOL load_bundle(void)
{
    char path[MAX_PATH];
    FILE *f;
    long fsize;
    BundleFooter foot;
    int i;

    GetModuleFileName(g_hinst, path, sizeof(path));
    f = fopen(path, "rb");
    if (!f) return FALSE;

    fseek(f, 0L, SEEK_END);
    fsize = ftell(f);
    if (fsize < (long)sizeof(BundleFooter)) { fclose(f); return FALSE; }

    fseek(f, fsize - (long)sizeof(BundleFooter), SEEK_SET);
    if (fread(&foot, 1, sizeof(foot), f) != sizeof(foot)) { fclose(f); return FALSE; }

    if (foot.magic != BUNDLE_MAGIC || foot.n_files == 0
        || foot.n_files > MAX_ENTRIES) { fclose(f); return FALSE; }

    fseek(f, (long)foot.index_off, SEEK_SET);
    for (i = 0; i < (int)foot.n_files; i++) {
        if (fread(&g_entries[i], 1, sizeof(BundleEntry), f)
                != sizeof(BundleEntry)) break;
        g_entries[i].name[63] = '\0';   /* safety */
    }
    g_nentries = i;
    fclose(f);
    g_bundled = (g_nentries > 0);
    return g_bundled;
}

static BOOL extract_file_to(int idx, const char FAR *destpath)
{
    char selfpath[MAX_PATH];
    FILE *fsrc, *fdst;
    DWORD remaining;
    char buf[2048];
    int n;

    GetModuleFileName(g_hinst, selfpath, sizeof(selfpath));
    fsrc = fopen(selfpath, "rb");
    if (!fsrc) return FALSE;
    fdst = fopen(destpath, "wb");
    if (!fdst) { fclose(fsrc); return FALSE; }

    fseek(fsrc, (long)g_entries[idx].off, SEEK_SET);
    remaining = g_entries[idx].size;
    while (remaining > 0) {
        int toread = (remaining > sizeof(buf)) ? (int)sizeof(buf) : (int)remaining;
        n = (int)fread(buf, 1, toread, fsrc);
        if (n <= 0) break;
        fwrite(buf, 1, n, fdst);
        remaining -= (DWORD)n;
    }
    fclose(fsrc);
    fclose(fdst);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Utility helpers                                                      */
/* ------------------------------------------------------------------ */

static void ensure_dir(const char FAR *path)
{
    char tmp[MAX_PATH];
    char *p;
    lstrcpy(tmp, path);
    for (p = tmp + 3; *p; p++) {
        if (*p == '\\') {
            *p = '\0';
            _mkdir(tmp);
            *p = '\\';
        }
    }
    _mkdir(tmp);
}

static BOOL file_exists_in_sysdir(const char *name)
{
    char path[MAX_PATH];
    HFILE hf;
    GetSystemDirectory(path, sizeof(path));
    lstrcat(path, "\\");
    lstrcat(path, name);
    hf = _lopen(path, READ);
    if (hf != HFILE_ERROR) { _lclose(hf); return TRUE; }
    return FALSE;
}

static BOOL any_dll_in_sysdir(void)
{
    int i;
    for (i = 0; k_dll_names[i]; i++)
        if (file_exists_in_sysdir(k_dll_names[i])) return TRUE;
    return FALSE;
}

static void get_dest_dir(int dest, char FAR *out)
{
    switch (dest) {
    case DEST_C2:
    case DEST_ROOT:
        lstrcpy(out, g_c2_path);
        break;
    case DEST_PUTTY:
        lstrcpy(out, g_putty_path);
        break;
    case DEST_DLL:
        if (g_dll_dest == 1)
            GetSystemDirectory(out, MAX_PATH);
        else
            lstrcpy(out, g_c2_path);   /* DLLs alongside C2 apps */
        break;
    }
}

/* ------------------------------------------------------------------ */
/* PROGMAN DDE group creation                                           */
/* ------------------------------------------------------------------ */

static void pm_exec(HWND hwnd_pm, const char FAR *cmd)
{
    HGLOBAL hg;
    LPSTR p;
    hg = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, lstrlen(cmd) + 1);
    if (!hg) return;
    p = (LPSTR)GlobalLock(hg);
    lstrcpy(p, cmd);
    GlobalUnlock(hg);
    /* Win16 WM_DDE_EXECUTE: wParam=sender hwnd, lParam=hGlobal */
    SendMessage(hwnd_pm, WM_DDE_EXECUTE,
                (WPARAM)g_hwnd_main, (LPARAM)hg);
    GlobalFree(hg);
}

static void create_program_group(void)
{
    char cmd[256];
    HWND hwnd_pm;
    ATOM aApp, aTopic;

    hwnd_pm = FindWindow("Progman", NULL);
    if (!hwnd_pm) return;

    aApp   = GlobalAddAtom("PROGMAN");
    aTopic = GlobalAddAtom("PROGMAN");
    SendMessage(hwnd_pm, WM_DDE_INITIATE,
                (WPARAM)g_hwnd_main, MAKELONG(aApp, aTopic));
    GlobalDeleteAtom(aApp);
    GlobalDeleteAtom(aTopic);

    pm_exec(hwnd_pm, "[CreateGroup(AeldreC2)]");

    if (g_inst_c2) {
        wsprintf(cmd, "[AddItem(%s\\joshua.exe,Joshua C2)]",   (LPSTR)g_c2_path);
        pm_exec(hwnd_pm, cmd);
        wsprintf(cmd, "[AddItem(%s\\clu.exe,CLU Implant Builder)]", (LPSTR)g_c2_path);
        pm_exec(hwnd_pm, cmd);
        wsprintf(cmd, "[AddItem(%s\\markuped.exe,markuped Editor)]", (LPSTR)g_c2_path);
        pm_exec(hwnd_pm, cmd);
        wsprintf(cmd, "[AddItem(%s\\grid.exe,Grid Port Scanner)]",   (LPSTR)g_c2_path);
        pm_exec(hwnd_pm, cmd);
        wsprintf(cmd, "[AddItem(%s\\ncwfw.exe,NCWfW Netcat)]",       (LPSTR)g_c2_path);
        pm_exec(hwnd_pm, cmd);
        wsprintf(cmd, "[AddItem(%s\\flynn.exe,Flynn Operator)]",     (LPSTR)g_c2_path);
        pm_exec(hwnd_pm, cmd);
        wsprintf(cmd, "[AddItem(%s\\ipcalc32.exe,IP Calculator)]",   (LPSTR)g_c2_path);
        pm_exec(hwnd_pm, cmd);
    }
    if (g_inst_putty) {
        wsprintf(cmd, "[AddItem(%s\\putty.exe,PuTTY)]",         (LPSTR)g_putty_path);
        pm_exec(hwnd_pm, cmd);
        wsprintf(cmd, "[AddItem(%s\\winsftp.exe,WinSFTP)]",     (LPSTR)g_putty_path);
        pm_exec(hwnd_pm, cmd);
        wsprintf(cmd, "[AddItem(%s\\puttygen.exe,PuTTYgen)]",   (LPSTR)g_putty_path);
        pm_exec(hwnd_pm, cmd);
        wsprintf(cmd, "[AddItem(%s\\pageant.exe,Pageant)]",     (LPSTR)g_putty_path);
        pm_exec(hwnd_pm, cmd);
    }

    pm_exec(hwnd_pm, "[ShowGroup(AeldreC2,1)]");
    PostMessage(hwnd_pm, WM_DDE_TERMINATE, (WPARAM)g_hwnd_main, 0L);
}

/* ------------------------------------------------------------------ */
/* Dialog: Welcome (page 0)                                             */
/* ------------------------------------------------------------------ */

BOOL __export CALLBACK WelcomeDlgProc(HWND hwnd, UINT msg,
                                       WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {
    case WM_INITDIALOG:
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK)     { EndDialog(hwnd, WIZ_NEXT);   return TRUE; }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(hwnd, WIZ_CANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Dialog: License (page 1)                                             */
/* ------------------------------------------------------------------ */

BOOL __export CALLBACK LicenseDlgProc(HWND hwnd, UINT msg,
                                       WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {
    case WM_INITDIALOG: {
        HRSRC   hrsrc;
        HGLOBAL hres, hbuf;
        DWORD   size;
        LPSTR   ptext, pbuf;

        EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);

        hrsrc = FindResource(g_hinst, MAKEINTRESOURCE(IDR_GPL3), RT_RCDATA);
        if (hrsrc) {
            hres  = LoadResource(g_hinst, hrsrc);
            size  = SizeofResource(g_hinst, hrsrc);
            ptext = (LPSTR)LockResource(hres);
            hbuf  = GlobalAlloc(GMEM_MOVEABLE, size + 1);
            if (hbuf) {
                pbuf = (LPSTR)GlobalLock(hbuf);
                _fmemcpy(pbuf, ptext, size);
                pbuf[size] = '\0';
                SendDlgItemMessage(hwnd, IDC_LIC_TEXT, EM_LIMITTEXT, 0, 0L);
                SetDlgItemText(hwnd, IDC_LIC_TEXT, pbuf);
                GlobalUnlock(hbuf);
                GlobalFree(hbuf);
            }
            FreeResource(hres);
        } else {
            SetDlgItemText(hwnd, IDC_LIC_TEXT,
                "GNU GENERAL PUBLIC LICENSE\r\nVersion 3, 29 June 2007\r\n\r\n"
                "This program is free software: you can redistribute it\r\n"
                "and/or modify it under the terms of the GNU General\r\n"
                "Public License as published by the Free Software\r\n"
                "Foundation, version 3.\r\n\r\n"
                "See GPL30.TXT in the installation directory for the full text.");
        }
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_LIC_ACCEPT) {
            EnableWindow(GetDlgItem(hwnd, IDOK),
                IsDlgButtonChecked(hwnd, IDC_LIC_ACCEPT) ? TRUE : FALSE);
            return TRUE;
        }
        if (LOWORD(wp) == IDOK) {
            if (IsDlgButtonChecked(hwnd, IDC_LIC_ACCEPT))
                EndDialog(hwnd, WIZ_NEXT);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(hwnd, WIZ_CANCEL); return TRUE; }
        if (LOWORD(wp) == IDC_BACK) { EndDialog(hwnd, WIZ_BACK);   return TRUE; }
        break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Dialog: Components (page 2)                                          */
/* ------------------------------------------------------------------ */

static void comps_sync(HWND hwnd)
{
    BOOL c2    = IsDlgButtonChecked(hwnd, IDC_C2_CHECK)   ? TRUE : FALSE;
    BOOL putty = IsDlgButtonChecked(hwnd, IDC_PUTTY_CHECK) ? TRUE : FALSE;
    EnableWindow(GetDlgItem(hwnd, IDC_C2_PATH),      c2);
    EnableWindow(GetDlgItem(hwnd, IDC_C2_BROWSE),    c2);
    EnableWindow(GetDlgItem(hwnd, IDC_PUTTY_PATH),   putty);
    EnableWindow(GetDlgItem(hwnd, IDC_PUTTY_BROWSE), putty);
}

static void browse_for_dir(HWND hwnd, int path_ctl)
{
    OPENFILENAME ofn;
    char pathbuf[MAX_PATH];

    GetDlgItemText(hwnd, path_ctl, pathbuf, sizeof(pathbuf) - 1);
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = hwnd;
    ofn.lpstrFilter = "All Files\0*.*\0\0";
    ofn.lpstrFile   = pathbuf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = "Navigate to the directory, then click OK";
    ofn.Flags       = OFN_HIDEREADONLY | OFN_NOCHANGEDIR;

    if (GetOpenFileName(&ofn)) {
        char *bs = _fstrrchr(pathbuf, '\\');
        if (bs) *bs = '\0';
        SetDlgItemText(hwnd, path_ctl, pathbuf);
    }
}

BOOL __export CALLBACK CompsDlgProc(HWND hwnd, UINT msg,
                                     WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {
    case WM_INITDIALOG:
        CheckDlgButton(hwnd, IDC_C2_CHECK,    g_inst_c2    ? 1 : 0);
        CheckDlgButton(hwnd, IDC_PUTTY_CHECK, g_inst_putty ? 1 : 0);
        CheckDlgButton(hwnd, IDC_DLL_CHECK,   g_inst_dlls  ? 1 : 0);
        SetDlgItemText(hwnd, IDC_C2_PATH,     g_c2_path);
        SetDlgItemText(hwnd, IDC_PUTTY_PATH,  g_putty_path);
        comps_sync(hwnd);
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_C2_CHECK:
        case IDC_PUTTY_CHECK:
            comps_sync(hwnd);
            return TRUE;

        case IDC_C2_BROWSE:
            browse_for_dir(hwnd, IDC_C2_PATH);
            return TRUE;
        case IDC_PUTTY_BROWSE:
            browse_for_dir(hwnd, IDC_PUTTY_PATH);
            return TRUE;

        case IDOK:
            g_inst_c2    = IsDlgButtonChecked(hwnd, IDC_C2_CHECK)    ? TRUE : FALSE;
            g_inst_putty = IsDlgButtonChecked(hwnd, IDC_PUTTY_CHECK) ? TRUE : FALSE;
            g_inst_dlls  = IsDlgButtonChecked(hwnd, IDC_DLL_CHECK)   ? TRUE : FALSE;
            GetDlgItemText(hwnd, IDC_C2_PATH,    g_c2_path,    sizeof(g_c2_path)    - 1);
            GetDlgItemText(hwnd, IDC_PUTTY_PATH, g_putty_path, sizeof(g_putty_path) - 1);
            if (!g_inst_c2 && !g_inst_putty) {
                MessageBox(hwnd,
                    "Please select at least one component to install.",
                    "Setup", MB_OK | MB_ICONEXCLAMATION);
                return TRUE;
            }
            EndDialog(hwnd, WIZ_NEXT);
            return TRUE;
        case IDCANCEL: EndDialog(hwnd, WIZ_CANCEL); return TRUE;
        case IDC_BACK: EndDialog(hwnd, WIZ_BACK);   return TRUE;
        }
        break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Dialog: DLL Options (page 3, conditional)                            */
/* ------------------------------------------------------------------ */

BOOL __export CALLBACK DllOptsDlgProc(HWND hwnd, UINT msg,
                                       WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {
    case WM_INITDIALOG: {
        char sysdir[MAX_PATH];
        char existing[128] = "";
        char warn[640];
        int i;

        GetSystemDirectory(sysdir, sizeof(sysdir));

        for (i = 0; k_dll_names[i]; i++) {
            if (file_exists_in_sysdir(k_dll_names[i])) {
                if (existing[0]) lstrcat(existing, ", ");
                lstrcat(existing, k_dll_names[i]);
            }
        }

        wsprintf(warn,
            "The following runtime DLLs already exist in %s:\r\n\r\n"
            "    %s\r\n\r\n"
            "Overwriting them may affect other Win32s applications.\r\n"
            "It is recommended to install DLLs into the application\r\n"
            "folder instead unless you know these versions are newer.",
            (LPSTR)sysdir, (LPSTR)existing);
        SetDlgItemText(hwnd, IDC_DLL_WARN, warn);

        /* Default: install to app dir (safer) */
        CheckRadioButton(hwnd, IDC_DLL_APPDIR, IDC_DLL_SYSDIR,
                         (g_dll_dest == 1) ? IDC_DLL_SYSDIR : IDC_DLL_APPDIR);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            g_dll_dest = IsDlgButtonChecked(hwnd, IDC_DLL_SYSDIR) ? 1 : 0;
            EndDialog(hwnd, WIZ_NEXT);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(hwnd, WIZ_CANCEL); return TRUE; }
        if (LOWORD(wp) == IDC_BACK) { EndDialog(hwnd, WIZ_BACK);   return TRUE; }
        break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Dialog: Confirm (page 4)                                             */
/* ------------------------------------------------------------------ */

BOOL __export CALLBACK ConfirmDlgProc(HWND hwnd, UINT msg,
                                       WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {
    case WM_INITDIALOG: {
        char sysdir[MAX_PATH];
        char dlldir[MAX_PATH];
        char buf[768];
        GetSystemDirectory(sysdir, sizeof(sysdir));
        if (g_dll_dest == 1) lstrcpy(dlldir, sysdir);
        else                 lstrcpy(dlldir, g_c2_path);

        wsprintf(buf,
            "Setup will install the following:\r\n\r\n"
            "%s  AeldreC2 C2 Framework\r\n"
            "    Destination:  %s\r\n\r\n"
            "%s  Putty-Win32s Tools\r\n"
            "    Destination:  %s\r\n\r\n"
            "%s  Runtime DLLs (WSOCK32, COMDLG32)\r\n"
            "    Destination:  %s\r\n\r\n"
            "Click Install to begin.",
            (LPSTR)(g_inst_c2    ? "[x]" : "[ ]"), (LPSTR)g_c2_path,
            (LPSTR)(g_inst_putty ? "[x]" : "[ ]"), (LPSTR)g_putty_path,
            (LPSTR)(g_inst_dlls  ? "[x]" : "[ ]"), (LPSTR)dlldir);
        SetDlgItemText(hwnd, IDC_CONFIRM_TXT, buf);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK)     { EndDialog(hwnd, WIZ_NEXT);   return TRUE; }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(hwnd, WIZ_CANCEL); return TRUE; }
        if (LOWORD(wp) == IDC_BACK) { EndDialog(hwnd, WIZ_BACK);   return TRUE; }
        break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Win16 GDI gauge bar (subclassed STATIC control)                     */
/* ------------------------------------------------------------------ */

#define IDC_PROG_BAR 243

static LRESULT __export CALLBACK GaugeSubclass(HWND hwnd, UINT msg,
                                                WPARAM wp, LPARAM lp)
{
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        RECT rc, filled;
        HDC dc;
        int fillw;

        dc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &rc);
        fillw = (int)(((long)(rc.right - rc.left) * g_gauge_pct) / 100L);

        /* Filled portion */
        filled = rc;
        filled.right = rc.left + fillw;
        FillRect(dc, &filled, GetStockObject(BLACK_BRUSH));

        /* Empty portion */
        filled.left  = rc.left + fillw;
        filled.right = rc.right;
        FillRect(dc, &filled, GetStockObject(WHITE_BRUSH));

        EndPaint(hwnd, &ps);
        return 0;
    }
    return CallWindowProc(g_gauge_oldproc, hwnd, msg, wp, lp);
}

static void update_gauge(int pct)
{
    HWND hbar;
    if (!g_hwnd_progress) return;
    g_gauge_pct = pct;
    hbar = GetDlgItem(g_hwnd_progress, IDC_PROG_BAR);
    InvalidateRect(hbar, NULL, FALSE);
    UpdateWindow(hbar);
}

/* ------------------------------------------------------------------ */
/* Install logic (called from progress dialog)                          */
/* ------------------------------------------------------------------ */

static void prog_log(const char FAR *text)
{
    HWND hlog;
    int len;
    if (!g_hwnd_progress) return;
    hlog = GetDlgItem(g_hwnd_progress, IDC_PROG_LOG);
    len  = (int)SendMessage(hlog, WM_GETTEXTLENGTH, 0, 0L);
    SendMessage(hlog, EM_SETSEL, len, (LPARAM)len);
    SendMessage(hlog, EM_REPLACESEL, 0, (LPARAM)text);
    SendMessage(hlog, EM_REPLACESEL, 0, (LPARAM)(LPCSTR)"\r\n");
}

static void prog_pct(int done, int total)
{
    char buf[32];
    int pct = (total > 0) ? (int)((long)done * 100L / (long)total) : 0;
    wsprintf(buf, "%d / %d  (%d%%)", done, total, pct);
    SetDlgItemText(g_hwnd_progress, IDC_PROG_PCT, buf);
    update_gauge(pct);
}

static void do_install(void)
{
    int i, done = 0, total = 0;
    char destdir[MAX_PATH], destpath[MAX_PATH];
    MSG msg;

    /* Count files we'll actually install */
    for (i = 0; i < g_nentries; i++) {
        BYTE d = g_entries[i].dest;
        if (d == DEST_C2    && !g_inst_c2)    continue;
        if (d == DEST_ROOT  && !g_inst_c2)    continue;
        if (d == DEST_PUTTY && !g_inst_putty) continue;
        if (d == DEST_DLL   && !g_inst_dlls)  continue;
        total++;
    }

    for (i = 0; i < g_nentries; i++) {
        BYTE d = g_entries[i].dest;
        char logline[96];

        if (d == DEST_C2    && !g_inst_c2)    continue;
        if (d == DEST_ROOT  && !g_inst_c2)    continue;
        if (d == DEST_PUTTY && !g_inst_putty) continue;
        if (d == DEST_DLL   && !g_inst_dlls)  continue;

        get_dest_dir((int)d, destdir);
        ensure_dir(destdir);

        wsprintf(destpath, "%s\\%s", (LPSTR)destdir,
                 (LPSTR)g_entries[i].name);
        wsprintf(logline,  "Installing %s", (LPSTR)g_entries[i].name);
        prog_log(logline);
        SetDlgItemText(g_hwnd_progress, IDC_PROG_FILE,
                       g_entries[i].name);

        /* Pump messages to keep UI alive */
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessage(&msg);

        extract_file_to(i, destpath);
        done++;
        prog_pct(done, total);

        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessage(&msg);
    }

    prog_log("Creating Program Manager group...");
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessage(&msg);
    create_program_group();

    prog_log("");
    prog_log("Installation complete!");
    SetDlgItemText(g_hwnd_progress, IDC_PROG_FILE, "Done.");
    g_prog_done = 1;
    EnableWindow(GetDlgItem(g_hwnd_progress, IDOK), TRUE);
    SetFocus(GetDlgItem(g_hwnd_progress, IDOK));
}

/* ------------------------------------------------------------------ */
/* Dialog: Progress / Done (page 5)                                     */
/* ------------------------------------------------------------------ */

BOOL __export CALLBACK ProgressDlgProc(HWND hwnd, UINT msg,
                                        WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {
    case WM_INITDIALOG: {
        HWND hbar;
        g_hwnd_progress = hwnd;
        g_prog_done     = 0;
        g_gauge_pct     = 0;
        EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);
        /* Subclass the gauge static so it draws a filled rectangle */
        hbar = GetDlgItem(hwnd, IDC_PROG_BAR);
        g_gauge_oldproc = (WNDPROC)SetWindowLong(hbar, GWL_WNDPROC,
                                                  (LONG)GaugeSubclass);
        /* Kick off install via timer so dialog is fully visible first */
        SetTimer(hwnd, 1, 200, NULL);
        return TRUE;
    }

    case WM_TIMER:
        KillTimer(hwnd, 1);
        do_install();
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wp) == IDOK && g_prog_done) {
            g_hwnd_progress = NULL;
            EndDialog(hwnd, WIZ_NEXT);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Minimal stub window (needed as DDE sender)                           */
/* ------------------------------------------------------------------ */

static LRESULT __export CALLBACK StubWndProc(HWND hwnd, UINT msg,
                                              WPARAM wp, LPARAM lp)
{
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* WinMain                                                              */
/* ------------------------------------------------------------------ */

int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nShow)
{
    WNDCLASS wc;
    int page, result;

    (void)hPrev; (void)lpCmd; (void)nShow;
    g_hinst = hInst;

    /* Register stub window class for DDE sender */
    if (!hPrev) {
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = StubWndProc;
        wc.hInstance     = hInst;
        wc.lpszClassName = "Setup16Stub";
        RegisterClass(&wc);
    }
    g_hwnd_main = CreateWindow("Setup16Stub", "",
        WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, hInst, NULL);

    /* Check bundle is present */
    if (!load_bundle()) {
        MessageBox(NULL,
            "This installer has not been bundled with application files.\n\n"
            "Run tools/mksetup.py to create a distributable setup.exe.",
            "AeldreC2 Setup", MB_OK | MB_ICONEXCLAMATION);
        /* Allow running anyway for testing the UI */
    }

    /* Wizard loop */
    page = 0;
    for (;;) {
        switch (page) {
        case 0:
            result = DialogBox(hInst, MAKEINTRESOURCE(IDD_WELCOME),
                               g_hwnd_main, WelcomeDlgProc);
            break;
        case 1:
            result = DialogBox(hInst, MAKEINTRESOURCE(IDD_LICENSE),
                               g_hwnd_main, LicenseDlgProc);
            break;
        case 2:
            result = DialogBox(hInst, MAKEINTRESOURCE(IDD_COMPONENTS),
                               g_hwnd_main, CompsDlgProc);
            break;
        case 3:
            if (g_inst_dlls && any_dll_in_sysdir())
                result = DialogBox(hInst, MAKEINTRESOURCE(IDD_DLLOPTS),
                                   g_hwnd_main, DllOptsDlgProc);
            else
                result = WIZ_NEXT;   /* skip DLL options page */
            break;
        case 4:
            result = DialogBox(hInst, MAKEINTRESOURCE(IDD_CONFIRM),
                               g_hwnd_main, ConfirmDlgProc);
            break;
        case 5:
            result = DialogBox(hInst, MAKEINTRESOURCE(IDD_PROGRESS),
                               g_hwnd_main, ProgressDlgProc);
            break;
        default:
            result = WIZ_NEXT;
            break;
        }

        if (result == WIZ_CANCEL) {
            if (MessageBox(g_hwnd_main,
                    "Cancel installation?", "Setup",
                    MB_YESNO | MB_ICONQUESTION) == IDYES)
                break;
            /* stay on current page */
            continue;
        }

        if (result == WIZ_NEXT) {
            if (page >= 5) break;   /* done */
            page++;
        } else {   /* WIZ_BACK */
            if (page > 0) page--;
        }
    }

    if (g_hwnd_main) DestroyWindow(g_hwnd_main);
    return 0;
}
