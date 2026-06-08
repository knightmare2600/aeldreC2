/*
 * jloshtog.c  --  AeldreC2  --  Joshua Log Viewer
 *
 * Reads joshua.log outwith the main Joshua controller — for post-op
 * analysis, audit trails, and general nosiness outwith live sessions.
 *
 * "Outwith" — Scots: outside of, beyond.  This tool operates entirely
 * outwith Joshua itself: no sockets, no Schannel, no operator auth.
 * Outwith all that patter — just the log, plain and legible.
 *
 * "Losh" — mild Scots exclamation, a softened "Lord".
 *  j(oshua) + losh + og (log) = jloshtog.
 *
 * Features:
 *  - Locates joshua.log in the same directory as this .exe, outwith
 *    any need to navigate there manually
 *  - File > Open   browse outwith the default location
 *  - F5 / Reload   refresh outwith restarting
 *  - View > Wrap   toggle word-wrap
 *  - View > Filter: All / Tanks only / Operators only
 *    Lets you see outwith the noise to the events you care about
 *  - Status bar: filename, line count, byte count
 *
 * Targets: Win32s / Windows NT 3.1+ / Windows 95+
 *
 * Build:
 *   wcl386 -za99 -bt=nt -l=nt_win -ox jloshtog.c comdlg32.lib
 *   wrc jloshtog.res jloshtog.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* IDs                                                                 */
/* ------------------------------------------------------------------ */

#define IDM_FILE_OPEN      101
#define IDM_FILE_RELOAD    102
#define IDM_FILE_EXIT      103
#define IDM_VIEW_WRAP      110
#define IDM_VIEW_ALL       111
#define IDM_VIEW_TANKS     112
#define IDM_VIEW_OPS       113
#define IDM_HELP_ABOUT     120

#define IDC_EDIT           201
#define IDC_STATUS         202

/* ------------------------------------------------------------------ */
/* Filter modes — what to show outwith the full log                   */
/* ------------------------------------------------------------------ */
#define FILTER_ALL   0   /* everything                               */
#define FILTER_TANKS 1   /* lines containing "[TANK]"                */
#define FILTER_OPS   2   /* lines containing "[OP]"                  */

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hinst    = NULL;
static HWND      g_hwnd     = NULL;
static HWND      g_edit     = NULL;
static HWND      g_status   = NULL;

static char g_path[MAX_PATH] = "";   /* current log file path        */
static int  g_wrap   = 0;            /* word-wrap toggle             */
static int  g_filter = FILTER_ALL;   /* active filter mode           */

static const int STATUS_H = 22;

/* ------------------------------------------------------------------ */
/* Find joshua.log outwith user intervention                          */
/* Looks in the same directory as jloshtog.exe.                       */
/* ------------------------------------------------------------------ */
static void find_default_log(char *out, int outsz)
{
    char dir[MAX_PATH];
    char *sl;
    DWORD n = GetModuleFileName(NULL, dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) { out[0] = '\0'; return; }
    sl = strrchr(dir, '\\');
    if (sl) *(sl + 1) = '\0';
    else    dir[0]    = '\0';
    _snprintf(out, outsz - 1, "%sjoshua.log", dir);
    out[outsz - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/* Update status bar outwith touching the edit content                */
/* ------------------------------------------------------------------ */
static void update_status(int lines, long bytes)
{
    char buf[MAX_PATH + 64];
    const char *name = g_path[0] ? g_path : "(no file)";
    /* Show just the filename portion outwith the full path           */
    const char *leaf = strrchr(name, '\\');
    if (leaf) leaf++; else leaf = name;
    _snprintf(buf, sizeof(buf) - 1,
              "  %s     %d lines     %ld bytes", leaf, lines, bytes);
    SetWindowText(g_status, buf);
}

/* ------------------------------------------------------------------ */
/* Load and display the log file, applying the active filter          */
/* Outwith this function nothing touches the edit control content.    */
/* ------------------------------------------------------------------ */
static void load_log(void)
{
    FILE   *f;
    long    fsz;
    char   *raw   = NULL;
    char   *out   = NULL;
    long    outsz = 0;
    int     lines = 0;
    long    obytes = 0;

    if (!g_path[0]) {
        SetWindowText(g_edit, "No log file selected.\r\n\r\n"
                              "Use File > Open to browse outwith the default location,\r\n"
                              "or place jloshtog.exe alongside joshua.log.");
        update_status(0, 0);
        return;
    }

    f = fopen(g_path, "rb");
    if (!f) {
        char msg[MAX_PATH + 64];
        _snprintf(msg, sizeof(msg) - 1,
                  "Cannot open '%s'.\r\n\r\n"
                  "The log may be outwith this directory, or Joshua may not\r\n"
                  "have written one yet.", g_path);
        SetWindowText(g_edit, msg);
        update_status(0, 0);
        return;
    }

    fseek(f, 0, SEEK_END);
    fsz = ftell(f);
    rewind(f);

    if (fsz <= 0) {
        fclose(f);
        SetWindowText(g_edit,
            "Log file is empty.\r\n"
            "Outwith a running Joshua session, nothing is written here yet.");
        update_status(0, 0);
        return;
    }

    raw = (char *)malloc((size_t)fsz + 2);
    if (!raw) { fclose(f); MessageBox(g_hwnd, "Out of memory.", "Jloshtog", MB_OK | MB_ICONSTOP); return; }
    fsz  = (long)fread(raw, 1, (size_t)fsz, f);
    fclose(f);
    raw[fsz] = '\0';

    if (g_filter == FILTER_ALL) {
        /* No filtering — use the raw buffer directly.
         * Normalise \r\n outwith worrying about mixed line endings.  */
        out   = raw;
        outsz = fsz;
        raw   = NULL;   /* prevent double-free below */
    } else {
        /* Filter outwith the lines we don't care about.
         * Walk line-by-line; include only matching ones.             */
        const char *needle = (g_filter == FILTER_TANKS) ? "[TANK]" : "[OP]";
        out = (char *)malloc((size_t)fsz + 2);
        if (!out) { free(raw); MessageBox(g_hwnd, "Out of memory.", "Jloshtog", MB_OK | MB_ICONSTOP); return; }
        {
            char *p   = raw;
            char *end = raw + fsz;
            char *dst = out;
            while (p < end) {
                char *nl  = memchr(p, '\n', (size_t)(end - p));
                char *eol = nl ? nl + 1 : end;
                int   len = (int)(eol - p);
                /* Temporarily NUL-terminate for strstr; restore after */
                char  saved = *eol;
                *eol = '\0';
                if (strstr(p, needle)) {
                    memcpy(dst, p, (size_t)len);
                    dst += len;
                    outsz += len;
                }
                *eol = saved;
                p    = eol;
            }
            *dst = '\0';
        }
        free(raw);
        raw = NULL;
    }

    /* Count lines for the status bar                                  */
    { char *p = out; while (*p) { if (*p == '\n') lines++; p++; } }
    obytes = outsz > 0 ? outsz : (long)strlen(out);

    /* Edit controls want \r\n — convert \n → \r\n outwith a second
     * pass if the file uses Unix line endings.                        */
    {
        char *crlf = (char *)malloc((size_t)(obytes * 2) + 4);
        if (crlf) {
            char *s = out, *d = crlf;
            while (*s) {
                if (*s == '\r' && *(s+1) == '\n') { *d++ = '\r'; *d++ = '\n'; s += 2; }
                else if (*s == '\n')              { *d++ = '\r'; *d++ = '\n'; s++;     }
                else                              { *d++ = *s++;                        }
            }
            *d = '\0';
            free(out);
            out = crlf;
        }
    }

    SetWindowText(g_edit, out);
    /* Scroll to the bottom — operators live outwith the past         */
    SendMessage(g_edit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessage(g_edit, EM_SCROLLCARET, 0, 0);

    update_status(lines, obytes);
    free(out);
}

/* ------------------------------------------------------------------ */
/* Rebuild the edit control outwith the current wrap setting          */
/* The control must be destroyed and recreated to change ES_AUTOHSCROLL. */
/* ------------------------------------------------------------------ */
static void rebuild_edit(void)
{
    DWORD style = WS_CHILD | WS_VISIBLE | WS_VSCROLL |
                  ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL;
    RECT rc;

    if (g_edit) DestroyWindow(g_edit);

    /* Word-wrap: outwith a horizontal scrollbar (the edit wraps itself).
     * No-wrap:   outwith ES_AUTOHSCROLL so we get a horizontal bar.   */
    if (!g_wrap) style |= WS_HSCROLL | ES_AUTOHSCROLL;

    GetClientRect(g_hwnd, &rc);
    g_edit = CreateWindow("EDIT", "",
                style,
                0, 0,
                rc.right, rc.bottom - STATUS_H,
                g_hwnd, (HMENU)IDC_EDIT, g_hinst, NULL);
    SendMessage(g_edit, WM_SETFONT,
                (WPARAM)GetStockObject(ANSI_FIXED_FONT), FALSE);
}

/* ------------------------------------------------------------------ */
/* Open-file dialog — browse outwith the current directory            */
/* ------------------------------------------------------------------ */
static int browse_open(void)
{
    OPENFILENAME ofn;
    char buf[MAX_PATH];
    lstrcpyn(buf, g_path, MAX_PATH);
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hwnd;
    ofn.lpstrFilter = "Log files (*.log)\0*.log\0All files (*.*)\0*.*\0\0";
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = "Open Joshua Log  \x97  Outwith the Default Location";
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileName(&ofn)) return 0;
    lstrcpyn(g_path, buf, MAX_PATH);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Tick the filter menu items to show which is active                 */
/* ------------------------------------------------------------------ */
static void update_filter_menu(HMENU hmenu)
{
    CheckMenuItem(hmenu, IDM_VIEW_ALL,   MF_BYCOMMAND |
                  (g_filter == FILTER_ALL   ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(hmenu, IDM_VIEW_TANKS, MF_BYCOMMAND |
                  (g_filter == FILTER_TANKS ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(hmenu, IDM_VIEW_OPS,   MF_BYCOMMAND |
                  (g_filter == FILTER_OPS   ? MF_CHECKED : MF_UNCHECKED));
}

/* ------------------------------------------------------------------ */
/* Window procedure                                                    */
/* ------------------------------------------------------------------ */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_CREATE: {
        RECT rc;
        GetClientRect(hwnd, &rc);

        /* Status bar — outwith the edit area, pinned to the bottom   */
        g_status = CreateWindow("STATIC", "  (no file)",
                       WS_CHILD | WS_VISIBLE | SS_LEFT,
                       0, rc.bottom - STATUS_H,
                       rc.right, STATUS_H,
                       hwnd, (HMENU)IDC_STATUS, g_hinst, NULL);
        SendMessage(g_status, WM_SETFONT,
                    (WPARAM)GetStockObject(DEFAULT_GUI_FONT), FALSE);

        /* Edit control — fills area outwith the status bar           */
        rebuild_edit();

        /* Try to find joshua.log outwith user intervention           */
        find_default_log(g_path, MAX_PATH);
        if (g_path[0] && GetFileAttributes(g_path) == 0xFFFFFFFF)
            g_path[0] = '\0';   /* not there — outwith luck           */
        load_log();
        return 0;
    }

    case WM_SIZE: {
        int w = (int)LOWORD(lp);
        int h = (int)HIWORD(lp);
        if (g_edit)   MoveWindow(g_edit,   0, 0, w, h - STATUS_H, TRUE);
        if (g_status) MoveWindow(g_status, 0, h - STATUS_H, w, STATUS_H, TRUE);
        return 0;
    }

    case WM_KEYDOWN:
        if (wp == VK_F5) { load_log(); return 0; }
        break;

    case WM_COMMAND:
        switch (LOWORD(wp)) {

        case IDM_FILE_OPEN:
            if (browse_open()) load_log();
            return 0;

        case IDM_FILE_RELOAD:
            load_log();
            return 0;

        case IDM_FILE_EXIT:
            DestroyWindow(hwnd);
            return 0;

        case IDM_VIEW_WRAP:
            g_wrap = !g_wrap;
            CheckMenuItem(GetMenu(hwnd), IDM_VIEW_WRAP, MF_BYCOMMAND |
                          (g_wrap ? MF_CHECKED : MF_UNCHECKED));
            rebuild_edit();     /* recreate outwith previous settings  */
            load_log();
            return 0;

        case IDM_VIEW_ALL:
            g_filter = FILTER_ALL;
            update_filter_menu(GetMenu(hwnd));
            load_log();
            return 0;

        case IDM_VIEW_TANKS:
            /* Show only tank events — outwith operator chatter        */
            g_filter = FILTER_TANKS;
            update_filter_menu(GetMenu(hwnd));
            load_log();
            return 0;

        case IDM_VIEW_OPS:
            /* Show only operator events — outwith tank noise          */
            g_filter = FILTER_OPS;
            update_filter_menu(GetMenu(hwnd));
            load_log();
            return 0;

        case IDM_HELP_ABOUT:
            MessageBox(hwnd,
                "Jloshtog  \x97  Joshua Log Viewer\r\n\r\n"
                "Reads joshua.log outwith the main Joshua controller.\r\n"
                "Outwith sockets, outwith auth, outwith MDI.\r\n"
                "Just the log.\r\n\r\n"
                "F5 to reload.  View > Filter to narrow events.\r\n\r\n"
                "\xc6ldreC2  \x97  Retro C2 for the masses.",
                "About Jloshtog", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* Build menu outwith hard-coding resource IDs in a .rc               */
/* ------------------------------------------------------------------ */
static HMENU build_menu(void)
{
    HMENU bar  = CreateMenu();
    HMENU file = CreatePopupMenu();
    HMENU view = CreatePopupMenu();
    HMENU help = CreatePopupMenu();

    AppendMenu(file, MF_STRING,    IDM_FILE_OPEN,   "&Open...\tCtrl+O");
    AppendMenu(file, MF_STRING,    IDM_FILE_RELOAD, "&Reload\tF5");
    AppendMenu(file, MF_SEPARATOR, 0, NULL);
    AppendMenu(file, MF_STRING,    IDM_FILE_EXIT,   "E&xit");

    AppendMenu(view, MF_STRING,    IDM_VIEW_WRAP,   "&Word Wrap");
    AppendMenu(view, MF_SEPARATOR, 0, NULL);
    /* Filter items — outwith all three checked, only one is active   */
    AppendMenu(view, MF_STRING | MF_CHECKED, IDM_VIEW_ALL,   "All &Events");
    AppendMenu(view, MF_STRING,              IDM_VIEW_TANKS, "&Tanks Only");
    AppendMenu(view, MF_STRING,              IDM_VIEW_OPS,   "&Operators Only");

    AppendMenu(help, MF_STRING, IDM_HELP_ABOUT, "&About");

    AppendMenu(bar, MF_POPUP, (UINT)file, "&File");
    AppendMenu(bar, MF_POPUP, (UINT)view, "&View");
    AppendMenu(bar, MF_POPUP, (UINT)help, "&Help");
    return bar;
}

/* ------------------------------------------------------------------ */
/* WinMain                                                             */
/* ------------------------------------------------------------------ */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASS wc;
    MSG      msg;

    g_hinst = hInst;

    /* Accept a log path from the command line — outwith the default  */
    if (lpCmdLine && lpCmdLine[0] && lpCmdLine[0] != '"')
        lstrcpyn(g_path, lpCmdLine, MAX_PATH);
    else if (lpCmdLine && lpCmdLine[0] == '"') {
        /* Strip quotes outwith duplicating the whole cmdline parser   */
        lstrcpyn(g_path, lpCmdLine + 1, MAX_PATH);
        { char *q = strchr(g_path, '"'); if (q) *q = '\0'; }
    }

    if (!hPrev) {
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = WndProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = "JloshtogFrame";
        wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
        RegisterClass(&wc);
    }

    g_hwnd = CreateWindow("JloshtogFrame",
                          "Jloshtog  \x97  Joshua Log Viewer",
                          WS_OVERLAPPEDWINDOW,
                          CW_USEDEFAULT, CW_USEDEFAULT,
                          800, 600,
                          NULL, build_menu(), hInst, NULL);
    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
