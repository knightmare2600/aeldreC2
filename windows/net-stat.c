/*
 * net-stat.c  --  AeldreC2 netstat for Win9x / Win32s
 *
 * Win32 GUI dialog showing active TCP/UDP connections.
 * Refresh button re-queries on demand.
 *
 * Data sources (tried in order):
 *   1. iphlpapi.dll GetTcpTable / GetUdpTable  (Win95 OSR2+ / NT 4+)
 *   2. COMMAND.COM exec fallback               (Win32s / bare Win95 RTM)
 *
 * Build:
 *   wcl386 -bt=nt -l=nt_win net-stat.c wsock32.lib
 *   (GUI subsystem — runs on Win32s, Win95, NT without a console window)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aeldre_theme.h"

/* -----------------------------------------------------------------------
 * iphlpapi types (inline — no SDK header required)
 * ----------------------------------------------------------------------- */
typedef struct { DWORD dwState,dwLocalAddr,dwLocalPort,dwRemoteAddr,dwRemotePort; } NS_TCPROW;
typedef struct { DWORD dwNumEntries; NS_TCPROW  table[1]; } NS_TCPTABLE;
typedef DWORD (WINAPI *pfGetTcpTable)(PVOID, PDWORD, BOOL);

typedef struct { DWORD dwLocalAddr, dwLocalPort; } NS_UDPROW;
typedef struct { DWORD dwNumEntries; NS_UDPROW  table[1]; } NS_UDPTABLE;
typedef DWORD (WINAPI *pfGetUdpTable)(PVOID, PDWORD, BOOL);

#define IDC_OUTPUT  100
#define IDC_REFRESH 101
#define IDC_STATUS  102

#define OUT_BUF_SZ  65536

static HINSTANCE g_hinst    = NULL;
static HWND      g_edit     = NULL;
static int       g_theme    = 0;
static HBRUSH    g_bg_brush = NULL;

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */
static const char *tcp_state(DWORD s)
{
    switch(s) {
    case  1: return "CLOSED";      case  2: return "LISTEN";
    case  3: return "SYN_SENT";    case  4: return "SYN_RCVD";
    case  5: return "ESTABLISHED"; case  6: return "FIN_WAIT1";
    case  7: return "FIN_WAIT2";   case  8: return "CLOSE_WAIT";
    case  9: return "CLOSING";     case 10: return "LAST_ACK";
    case 11: return "TIME_WAIT";   case 12: return "DELETE_TCB";
    default: return "UNKNOWN";
    }
}

static void fmt_ep(char *out, DWORD ip, DWORD port)
{
    struct in_addr a; a.s_addr = ip;
    sprintf(out, "%s:%u", inet_ntoa(a), ntohs((WORD)port));
}

/* -----------------------------------------------------------------------
 * Append to a fixed output buffer; silently truncates on overflow
 * ----------------------------------------------------------------------- */
static void buf_cat(char *buf, const char *s)
{
    size_t blen = strlen(buf);
    size_t slen = strlen(s);
    if (blen + slen + 1 < OUT_BUF_SZ)
        memcpy(buf + blen, s, slen + 1);
}

/* -----------------------------------------------------------------------
 * Exec fallback: COMMAND.COM /c netstat -an > tmpfile
 * Used when iphlpapi is absent (Win32s, Win95 RTM)
 * ----------------------------------------------------------------------- */
static void exec_fallback(char *out)
{
    char tmpdir[MAX_PATH], tmpfile[MAX_PATH], cmdline[MAX_PATH + 64];
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;
    HANDLE hf;
    DWORD  rd;
    char   chunk[512];

    GetTempPath(MAX_PATH, tmpdir);
    if (!tmpdir[0]) lstrcpy(tmpdir, "C:\\TEMP\\");
    wsprintf(tmpfile, "%sNST%04lX.TMP", tmpdir, GetTickCount() & 0xFFFF);
    wsprintf(cmdline, "COMMAND.COM /c netstat -an > \"%s\" 2>&1", tmpfile);

    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcess(NULL, cmdline, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        buf_cat(out, "netstat.exe not found or COMMAND.COM unavailable.\r\n");
        return;
    }
    WaitForSingleObject(pi.hProcess, 15000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

    hf = CreateFile(tmpfile, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        buf_cat(out, "(No output from netstat)\r\n");
        return;
    }
    while (ReadFile(hf, chunk, sizeof(chunk) - 1, &rd, NULL) && rd > 0) {
        char *p;
        chunk[rd] = '\0';
        /* normalise bare \n -> \r\n for the edit control */
        for (p = chunk; *p; p++) {
            if (*p == '\n' && (p == chunk || *(p-1) != '\r')) buf_cat(out, "\r");
            { char tmp[2]; tmp[0] = *p; tmp[1] = '\0'; buf_cat(out, tmp); }
        }
    }
    CloseHandle(hf);
    DeleteFile(tmpfile);
}

/* -----------------------------------------------------------------------
 * Build the connection listing into a pre-allocated OUT_BUF_SZ buffer
 * ----------------------------------------------------------------------- */
static void build_output(char *out)
{
    HMODULE       hIP  = LoadLibrary("iphlpapi.dll");
    pfGetTcpTable fTCP = hIP ? (pfGetTcpTable)GetProcAddress(hIP,"GetTcpTable") : NULL;
    pfGetUdpTable fUDP = hIP ? (pfGetUdpTable)GetProcAddress(hIP,"GetUdpTable") : NULL;
    void  *buf;
    DWORD  sz, i;

    out[0] = '\0';

    if (!fTCP || !fUDP) {
        if (hIP) FreeLibrary(hIP);
        exec_fallback(out);
        return;
    }

    buf_cat(out, "Proto  Local Address          Foreign Address        State\r\n");
    buf_cat(out, "------ ---------------------- ---------------------- -----------\r\n");

    sz = 8192; buf = malloc(sz);
    if (buf && fTCP(buf, &sz, TRUE) == 0) {
        NS_TCPTABLE *t = (NS_TCPTABLE *)buf;
        for (i = 0; i < t->dwNumEntries; i++) {
            char la[28], ra[28], line[100];
            fmt_ep(la, t->table[i].dwLocalAddr,  t->table[i].dwLocalPort);
            fmt_ep(ra, t->table[i].dwRemoteAddr, t->table[i].dwRemotePort);
            wsprintf(line, "TCP    %-22s %-22s %s\r\n",
                     la, ra, tcp_state(t->table[i].dwState));
            buf_cat(out, line);
        }
    }
    free(buf);

    sz = 8192; buf = malloc(sz);
    if (buf && fUDP(buf, &sz, TRUE) == 0) {
        NS_UDPTABLE *t = (NS_UDPTABLE *)buf;
        for (i = 0; i < t->dwNumEntries; i++) {
            char la[28], line[64];
            struct in_addr a; a.s_addr = t->table[i].dwLocalAddr;
            wsprintf(la, "%s:%u", inet_ntoa(a),
                     ntohs((WORD)t->table[i].dwLocalPort));
            wsprintf(line, "UDP    %-22s *:*\r\n", la);
            buf_cat(out, line);
        }
    }
    free(buf);

    FreeLibrary(hIP);
}

/* -----------------------------------------------------------------------
 * Refresh: query and update the edit control
 * ----------------------------------------------------------------------- */
static void do_refresh(HWND hwnd)
{
    char *out = (char *)malloc(OUT_BUF_SZ);
    SetDlgItemText(hwnd, IDC_STATUS, "Refreshing...");
    SetWindowText(g_edit, "");
    if (out) {
        build_output(out);
        SetWindowText(g_edit, out);
        free(out);
    }
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
        HWND  hw; RECT cr;
        g_theme    = aeldre_theme_load();
        g_bg_brush = CreateSolidBrush(g_aeldre_themes[g_theme].bg);
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

        do_refresh(hwnd);
        return 0;
    }
    case WM_SIZE: {
        int cw = (int)LOWORD(lp), ch = (int)HIWORD(lp);
        if (g_edit) MoveWindow(g_edit, 0, 0, cw, ch - 28, TRUE);
        if (GetDlgItem(hwnd, IDC_STATUS))
            MoveWindow(GetDlgItem(hwnd, IDC_STATUS), 92, ch-22, cw-96, 18, TRUE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_REFRESH) do_refresh(hwnd);
        return 0;
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wp; RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_bg_brush);
        return 1;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        const AeldreTheme *t = &g_aeldre_themes[g_theme];
        SetTextColor(hdc, t->body); SetBkColor(hdc, t->bg);
        return (LRESULT)g_bg_brush;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        const AeldreTheme *t = &g_aeldre_themes[g_theme];
        SetTextColor(hdc, t->body); SetBkColor(hdc, t->bg);
        return (LRESULT)g_bg_brush;
    }
    case WM_CTLCOLORBTN:
        SetBkColor((HDC)wp, g_aeldre_themes[g_theme].bg);
        return (LRESULT)g_bg_brush;
    case WM_DESTROY:
        if (g_bg_brush) { DeleteObject(g_bg_brush); g_bg_brush = NULL; }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* -----------------------------------------------------------------------
 * WinMain
 * ----------------------------------------------------------------------- */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nShow)
{
    WNDCLASS wc;
    HWND     hwnd;
    MSG      msg;
    WSADATA  wsd;
    (void)hPrev; (void)lpCmd;

    g_hinst = hInst;
    WSAStartup(0x0101, &wsd);

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = "NS32Main";
    RegisterClass(&wc);

    hwnd = CreateWindow("NS32Main",
        "net-stat  \xe6ldreC2  --  Active Connections",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 420,
        NULL, NULL, hInst, NULL);
    if (!hwnd) { WSACleanup(); return 1; }
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    WSACleanup();
    return (int)msg.wParam;
}
