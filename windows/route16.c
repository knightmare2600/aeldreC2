/*
 * route16.c  --  AeldreC2 route for Win16 / WFW 3.11
 *
 * Runs 'route print' (or 'route add'/'delete' from the command line)
 * via COMMAND.COM, captures output, and displays it in a dialog.
 *
 * Same exec-to-tempfile approach as netstat16.
 *
 * Build:
 *   wcc -ml -bt=windows -zu -s route16.c
 *   wlink system windows name route16.exe file route16.obj
 */

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dos.h>
#include <io.h>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define IDC_OUTPUT  100
#define IDC_REFRESH 101
#define IDC_STATUS  102

static HINSTANCE g_hinst    = NULL;
static HWND      g_edit     = NULL;
static char      g_cmd[256] = "route print"; /* overridden by cmdline args */

/* -----------------------------------------------------------------------
 * Execute and capture
 * ----------------------------------------------------------------------- */
static void do_run(HWND hwnd)
{
    char    tmpdir[MAX_PATH], tmpfile[MAX_PATH], cmdline[MAX_PATH + 64];
    HFILE   hf;
    long    fsz;
    char   *buf;
    UINT    htask;
    unsigned long deadline;
    MSG     msg;

    SetDlgItemText(hwnd, IDC_STATUS, "Running...");
    SetWindowText(g_edit, "");

    GetWindowsDirectory(tmpdir, sizeof(tmpdir));
    lstrcat(tmpdir, "\\");
    wsprintf(tmpfile, "%sRT%04X.OUT", tmpdir,
             (unsigned int)(GetTickCount() & 0xFFFF));

    wsprintf(cmdline, "COMMAND.COM /c %s > %s 2>&1", g_cmd, tmpfile);
    htask = WinExec(cmdline, SW_HIDE);
    if (htask < 32) {
        SetWindowText(g_edit,
            "route.exe not found.\r\n\r\n"
            "Install a TCP/IP stack that includes route\r\n"
            "(e.g. Microsoft TCP/IP-32 for WFW 3.11).");
        SetDlgItemText(hwnd, IDC_STATUS, "Not available.");
        return;
    }

    deadline = GetTickCount() + 15000UL;
    while (GetTickCount() < deadline) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
        hf = _lopen(tmpfile, OF_READ);
        if (hf != HFILE_ERROR) {
            fsz = _llseek(hf, 0, 2);
            _lclose(hf);
            if (fsz > 0) break;
        }
    }

    hf = _lopen(tmpfile, OF_READ);
    if (hf == HFILE_ERROR) {
        SetWindowText(g_edit, "(No output)");
        SetDlgItemText(hwnd, IDC_STATUS, "No output.");
        return;
    }
    fsz = _llseek(hf, 0, 2);
    _llseek(hf, 0, 0);

    buf = malloc((int)fsz + 4);
    if (buf) {
        char  *out, *p, *q;
        int    rd;
        rd = _lread(hf, buf, (int)fsz);
        buf[rd > 0 ? rd : 0] = '\0';
        out = malloc(rd * 2 + 4);
        if (out) {
            p = buf; q = out;
            while (*p) {
                if (*p == '\n' && (p == buf || *(p-1) != '\r')) *q++ = '\r';
                *q++ = *p++;
            }
            *q = '\0';
            SetWindowText(g_edit, out);
            free(out);
        }
        free(buf);
    }
    _lclose(hf);
    unlink(tmpfile);
    SetDlgItemText(hwnd, IDC_STATUS, "Done.");
}

/* -----------------------------------------------------------------------
 * Main window procedure
 * ----------------------------------------------------------------------- */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT hfFixed = (HFONT)GetStockObject(SYSTEM_FIXED_FONT);
        HFONT hfGui   = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND  hw;
        RECT  cr;
        GetClientRect(hwnd, &cr);

        g_edit = CreateWindow("EDIT", "",
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|
            ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
            0, 0, cr.right, cr.bottom - 28,
            hwnd, (HMENU)IDC_OUTPUT, g_hinst, NULL);
        SendMessage(g_edit, WM_SETFONT, (WPARAM)hfFixed, FALSE);

        hw = CreateWindow("BUTTON", "Refresh",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            4, cr.bottom - 24, 80, 20,
            hwnd, (HMENU)IDC_REFRESH, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hfGui, FALSE);

        hw = CreateWindow("STATIC", "Ready.",
            WS_CHILD|WS_VISIBLE|SS_LEFT,
            92, cr.bottom - 22, cr.right - 96, 18,
            hwnd, (HMENU)IDC_STATUS, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hfGui, FALSE);

        do_run(hwnd);
        return 0;
    }
    case WM_SIZE: {
        int cw = (int)LOWORD(lp), ch = (int)HIWORD(lp);
        if (g_edit) MoveWindow(g_edit, 0, 0, cw, ch - 28, TRUE);
        if (GetDlgItem(hwnd, IDC_STATUS))
            MoveWindow(GetDlgItem(hwnd,IDC_STATUS), 92, ch-22, cw-96, 18, TRUE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_REFRESH) do_run(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* -----------------------------------------------------------------------
 * WinMain — parse optional args to set g_cmd (e.g. "route add ...")
 * ----------------------------------------------------------------------- */
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nShow)
{
    WNDCLASS wc;
    HWND     hwnd;
    MSG      msg;

    g_hinst = hInst;

    /* If command-line args given, prepend "route " and use as command */
    if (lpCmd && lpCmd[0]) {
        wsprintf(g_cmd, "route %s", lpCmd);
    }

    if (!hPrev) {
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = WndProc;
        wc.hInstance     = hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.lpszClassName = "RT16Main";
        RegisterClass(&wc);
    }

    hwnd = CreateWindow("RT16Main",
        "route16  \xc6ldreC2  --  Routing Table",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 400,
        NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
