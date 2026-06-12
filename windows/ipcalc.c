/*
 * ipcalc.c  --  IP subnet calculator  (Win16 / Win32s / Win32)
 *
 * Single source.  Compile as:
 *   Win32s/NT  :  wcl386 -bt=nt -l=nt_win   (ipcalc.exe)
 *   Win16      :  wcc    -ms  -bt=windows    (ipcalc16.exe)
 *
 * GUI: input box + Calculate + read-only results area + Copy + Save
 *
 * CLI (both builds):
 *   ipcalc 192.168.1.1/24
 *   ipcalc 192.168.1.1 255.255.255.0
 *   ipcalc 192.168.1.1/24 -o out.txt
 *
 * Win32 only: if stdout is redirected, output goes there automatically.
 *
 * Based on the ipcalc algorithm by Joakim Plate (kjokjo/ipcalc, GPL).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef IPC_WIN16
#include "aeldre_theme.h"
#endif

/* ------------------------------------------------------------------ */
/* Win16 / Win32 portability                                          */
/* ------------------------------------------------------------------ */

#if defined(__WINDOWS__) && !defined(WIN32)
#  define IPC_WIN16
#endif

#ifdef IPC_WIN16
   /* Win16: window proc and enum procs must be exported             */
#  define WINCB  __export
   /* Win16: WM_COMMAND  wParam=ctlID  lParam=MAKELONG(hwnd,code)   */
#  define CMD_ID(wp,lp)   ((int)(wp))
#  define CMD_CODE(wp,lp) ((int)HIWORD(lp))
   /* Win32 aliases absent from Win16 headers */
#  ifndef MAX_PATH
#    define MAX_PATH        260
#  endif
#  ifndef MB_ICONERROR
#    define MB_ICONERROR    MB_ICONSTOP     /* 0x10 */
#  endif
#  ifndef MB_ICONINFORMATION
#    define MB_ICONINFORMATION MB_ICONASTERISK  /* 0x40 */
#  endif
#else
   /* Win32: WM_COMMAND  wParam=MAKELONG(id,code)  lParam=hwnd      */
#  define WINCB
#  define CMD_ID(wp,lp)   ((int)LOWORD(wp))
#  define CMD_CODE(wp,lp) ((int)HIWORD(wp))
#endif

/* ------------------------------------------------------------------ */
/* Control IDs                                                         */
/* ------------------------------------------------------------------ */

#define IDC_INPUT       101
#define IDC_CALC        102
#define IDC_RESULTS     103
#define IDC_COPY        104
#define IDC_SAVE        105
#define IDC_ABOUT       106
#define IDC_CLOSE       107

/* Save-dialog controls */
#define IDC_FILENAME    201
#define IDSAVE_OK       202
#define IDSAVE_CANCEL   203

#define WC_IPCALC       "IPCALC"
#define WC_SAVEDLG      "IPCSAVE"

/* ------------------------------------------------------------------ */
/* IP calculation engine                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned long addr;       /* host byte order */
    unsigned long mask;       /* host byte order */
    int           prefix;
    unsigned long network;
    unsigned long broadcast;
    unsigned long host_min;
    unsigned long host_max;
    unsigned long n_hosts;
    unsigned long wildcard;
    int           net_class; /* 'A'..'E' */
    int           is_private;
    int           is_loopback;
    int           is_multicast;
    int           is_linklocal;
    int           is_hostroute; /* /32 */
    int           is_p2p;       /* /31 RFC 3021 */
} IpInfo;

static int prefix_to_mask(int prefix, unsigned long *mask)
{
    if (prefix < 0 || prefix > 32) return 0;
    *mask = prefix ? (0xFFFFFFFFUL << (32 - prefix)) : 0UL;
    return 1;
}

static int mask_to_prefix(unsigned long mask, int *prefix)
{
    int p = 0;
    unsigned long m = mask;
    /* must be contiguous 1s then 0s */
    while (p < 32 && (m & 0x80000000UL)) { m <<= 1; p++; }
    if (m != 0) return 0;   /* non-contiguous */
    *prefix = p;
    return 1;
}

static unsigned long octet_to_ul(int a, int b, int c, int d)
{
    return ((unsigned long)a << 24) |
           ((unsigned long)b << 16) |
           ((unsigned long)c <<  8) |
            (unsigned long)d;
}

static int parse_ip(const char *s, unsigned long *out)
{
    int a, b, c, d;
    if (sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return 0;
    if (a < 0 || a > 255 || b < 0 || b > 255 ||
        c < 0 || c > 255 || d < 0 || d > 255) return 0;
    *out = octet_to_ul(a, b, c, d);
    return 1;
}

static void ul_to_dot(unsigned long v, char *buf)
{
    sprintf(buf, "%lu.%lu.%lu.%lu",
            (v >> 24) & 0xFF, (v >> 16) & 0xFF,
            (v >>  8) & 0xFF,  v        & 0xFF);
}

static void ul_to_binary(unsigned long v, char *buf)
{
    int i;
    char *p = buf;
    for (i = 31; i >= 0; i--) {
        *p++ = (v & (1UL << i)) ? '1' : '0';
        if (i > 0 && (i % 8) == 0) *p++ = '.';
    }
    *p = '\0';
}

static int ipcalc(const char *input, IpInfo *r, char *errbuf)
{
    char buf[128];
    char *slash, *space;
    unsigned long addr, mask;
    int prefix;

    strncpy(buf, input, 127); buf[127] = '\0';

    /* trim leading/trailing whitespace */
    {
        char *p = buf, *q;
        while (*p == ' ' || *p == '\t') p++;
        if (p != buf) memmove(buf, p, strlen(p) + 1);
        q = buf + strlen(buf) - 1;
        while (q >= buf && (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r'))
            *q-- = '\0';
    }

    slash = strchr(buf, '/');
    space = strchr(buf, ' ');

    if (slash) {
        *slash = '\0';
        if (!parse_ip(buf, &addr)) {
            if (errbuf) sprintf(errbuf, "Invalid address: %s", buf);
            return 0;
        }
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) {
            if (errbuf) sprintf(errbuf, "Invalid prefix: /%d", prefix);
            return 0;
        }
        if (!prefix_to_mask(prefix, &mask)) {
            if (errbuf) strcpy(errbuf, "Prefix conversion failed");
            return 0;
        }
    } else if (space) {
        *space = '\0';
        if (!parse_ip(buf, &addr)) {
            if (errbuf) sprintf(errbuf, "Invalid address: %s", buf);
            return 0;
        }
        /* second token: netmask or prefix len */
        {
            const char *tok = space + 1;
            while (*tok == ' ') tok++;
            if (strchr(tok, '.')) {
                if (!parse_ip(tok, &mask)) {
                    if (errbuf) sprintf(errbuf, "Invalid mask: %s", tok);
                    return 0;
                }
                /* could be a wildcard (inverse) mask */
                if (!mask_to_prefix(mask, &prefix)) {
                    /* try as wildcard */
                    mask = ~mask;
                    if (!mask_to_prefix(mask, &prefix)) {
                        if (errbuf) strcpy(errbuf, "Non-contiguous mask");
                        return 0;
                    }
                }
            } else {
                prefix = atoi(tok);
                if (prefix < 0 || prefix > 32) {
                    if (errbuf) sprintf(errbuf, "Invalid prefix: %s", tok);
                    return 0;
                }
                prefix_to_mask(prefix, &mask);
            }
        }
    } else {
        /* bare IP: assume /32 */
        if (!parse_ip(buf, &addr)) {
            if (errbuf) sprintf(errbuf, "Invalid address: %s", buf);
            return 0;
        }
        prefix = 32;
        mask   = 0xFFFFFFFFUL;
    }

    r->addr    = addr;
    r->mask    = mask;
    r->prefix  = prefix;
    r->wildcard   = ~mask;
    r->network    = addr & mask;
    r->broadcast  = r->network | r->wildcard;

    if (prefix >= 31) {
        r->host_min = r->network;
        r->host_max = r->broadcast;
        r->n_hosts  = (prefix == 32) ? 1UL : 2UL;
    } else {
        r->host_min = r->network + 1;
        r->host_max = r->broadcast - 1;
        r->n_hosts  = r->host_max - r->host_min + 1;
    }

    r->is_hostroute = (prefix == 32);
    r->is_p2p       = (prefix == 31);

    /* network class (based on network address) */
    if      (r->network < octet_to_ul(128,   0, 0, 0)) r->net_class = 'A';
    else if (r->network < octet_to_ul(192,   0, 0, 0)) r->net_class = 'B';
    else if (r->network < octet_to_ul(224,   0, 0, 0)) r->net_class = 'C';
    else if (r->network < octet_to_ul(240,   0, 0, 0)) r->net_class = 'D';
    else                                                r->net_class = 'E';

    /* special ranges */
    r->is_loopback   = ((r->network & 0xFF000000UL) == octet_to_ul(127, 0, 0, 0));
    r->is_linklocal  = ((r->network & 0xFFFF0000UL) == octet_to_ul(169, 254, 0, 0));
    r->is_multicast  = (r->net_class == 'D');
    r->is_private    =
        ((r->network & 0xFF000000UL) == octet_to_ul( 10,   0, 0, 0)) ||
        ((r->network & 0xFFF00000UL) == octet_to_ul(172,  16, 0, 0)) ||
        ((r->network & 0xFFFF0000UL) == octet_to_ul(192, 168, 0, 0));

    return 1;
}

/* ------------------------------------------------------------------ */
/* Format results into a text buffer                                   */
/* ------------------------------------------------------------------ */

static void format_results(const IpInfo *r, char *out, int outsz)
{
    char addr_s[20], mask_s[20], wild_s[20];
    char net_s[20],  bcast_s[20], hmin_s[20], hmax_s[20];
    char addr_b[40], mask_b[40];
    char type_s[64];
    char hosts_s[16];
    int  n;

    ul_to_dot(r->addr,      addr_s);
    ul_to_dot(r->mask,      mask_s);
    ul_to_dot(r->wildcard,  wild_s);
    ul_to_dot(r->network,   net_s);
    ul_to_dot(r->broadcast, bcast_s);
    ul_to_dot(r->host_min,  hmin_s);
    ul_to_dot(r->host_max,  hmax_s);
    ul_to_binary(r->addr, addr_b);
    ul_to_binary(r->mask, mask_b);

    sprintf(hosts_s, "%lu", r->n_hosts);

    if      (r->is_loopback)  strcpy(type_s, "Loopback");
    else if (r->is_linklocal) strcpy(type_s, "Link-local (APIPA)");
    else if (r->is_multicast) strcpy(type_s, "Multicast");
    else if (r->net_class == 'E') strcpy(type_s, "Reserved");
    else if (r->is_private)   strcpy(type_s, "Private (RFC 1918)");
    else                      strcpy(type_s, "Public");

    if (r->is_hostroute) strcat(type_s, ", host route");
    if (r->is_p2p)       strcat(type_s, ", point-to-point");

    n = sprintf(out,
        "Address:   %-18s\r\n"
        "Netmask:   %-18s = /%d\r\n"
        "Wildcard:  %-18s\r\n"
        "\r\n"
        "Network:   %s/%d\r\n"
        "Broadcast: %-18s\r\n"
        "HostMin:   %-18s\r\n"
        "HostMax:   %-18s\r\n"
        "Hosts/Net: %s\r\n"
        "\r\n"
        "Class:     %c\r\n"
        "Type:      %s\r\n"
        "\r\n"
        "Address (binary):\r\n"
        "  %s\r\n"
        "Netmask (binary):\r\n"
        "  %s\r\n",
        addr_s,
        mask_s, r->prefix,
        wild_s,
        net_s, r->prefix,
        bcast_s,
        hmin_s,
        hmax_s,
        hosts_s,
        r->net_class,
        type_s,
        addr_b,
        mask_b);

    if (n < 0 || n >= outsz) out[outsz - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/* File output                                                         */
/* ------------------------------------------------------------------ */

static void write_to_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        MessageBox(NULL, "Cannot open output file.", "ipcalc", MB_OK | MB_ICONERROR);
        return;
    }
    /* strip \r from \r\n for plain text file */
    {
        const char *p = text;
        while (*p) {
            if (*p != '\r') fputc(*p, f);
            p++;
        }
    }
    fclose(f);
}

#ifndef IPC_WIN16
static void write_to_handle(HANDLE h, const char *text)
{
    DWORD w;
    WriteFile(h, text, lstrlen(text), &w, NULL);
}
#endif

/* ------------------------------------------------------------------ */
/* Save-filename mini-dialog (modal, no commdlg dependency)           */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hinst  = NULL;
static char      g_save_filename[MAX_PATH];
static HWND      g_save_dlg = NULL;
#ifndef IPC_WIN16
static int       g_theme    = 0;
static HBRUSH    g_bg_brush = NULL;
#endif

LRESULT CALLBACK WINCB SaveDlgProc(HWND hwnd, UINT msg,
                                    WPARAM wp, LPARAM lp)
{
    int id, code;
    switch (msg) {
    case WM_CREATE:
#ifndef IPC_WIN16
        if (!g_bg_brush) {
            g_theme    = aeldre_theme_load();
            g_bg_brush = CreateSolidBrush(g_aeldre_themes[g_theme].bg);
        }
#endif
        SetWindowText(hwnd, "Save Results");
        CreateWindow("STATIC", "Filename:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            8, 12, 64, 16, hwnd, (HMENU)0, g_hinst, NULL);
        CreateWindow("EDIT", "ipcalc.txt",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            76, 8, 220, 20, hwnd, (HMENU)IDC_FILENAME, g_hinst, NULL);
        CreateWindow("BUTTON", "Save",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            76, 36, 60, 22, hwnd, (HMENU)IDSAVE_OK, g_hinst, NULL);
        CreateWindow("BUTTON", "Cancel",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            144, 36, 60, 22, hwnd, (HMENU)IDSAVE_CANCEL, g_hinst, NULL);
        return 0;

    case WM_COMMAND:
        id   = CMD_ID(wp, lp);
        code = CMD_CODE(wp, lp);
        (void)code;
        if (id == IDSAVE_OK) {
            GetDlgItemText(hwnd, IDC_FILENAME,
                           g_save_filename, MAX_PATH - 1);
            g_save_filename[MAX_PATH - 1] = '\0';
            DestroyWindow(hwnd);
            g_save_dlg = NULL;
        } else if (id == IDSAVE_CANCEL) {
            g_save_filename[0] = '\0';
            DestroyWindow(hwnd);
            g_save_dlg = NULL;
        }
        return 0;

    case WM_DESTROY:
        g_save_dlg = NULL;
        return 0;
#ifndef IPC_WIN16
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wp; RECT rc;
        GetClientRect(hwnd, &rc); FillRect(hdc, &rc, g_bg_brush); return 1;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc=(HDC)wp; const AeldreTheme *t=&g_aeldre_themes[g_theme];
        SetTextColor(hdc,t->body); SetBkColor(hdc,t->bg); return (LRESULT)g_bg_brush;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc=(HDC)wp; const AeldreTheme *t=&g_aeldre_themes[g_theme];
        SetTextColor(hdc,t->body); SetBkColor(hdc,t->bg); return (LRESULT)g_bg_brush;
    }
    case WM_CTLCOLORBTN:
        SetBkColor((HDC)wp,g_aeldre_themes[g_theme].bg); return (LRESULT)g_bg_brush;
#endif
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* Returns 1 and fills g_save_filename if user confirmed */
static int ask_save_filename(HWND parent)
{
    WNDCLASS wc;
    RECT     pr;
    int      px, py, dx = 312, dy = 70;
    MSG      msg;

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = SaveDlgProc;
    wc.hInstance     = g_hinst;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = WC_SAVEDLG;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    GetWindowRect(parent, &pr);
    px = pr.left + (pr.right  - pr.left  - dx) / 2;
    py = pr.top  + (pr.bottom - pr.top   - dy) / 2;

    g_save_filename[0] = '\0';
    g_save_dlg = CreateWindow(WC_SAVEDLG, "Save Results",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        px, py, dx, dy + 30,
        parent, NULL, g_hinst, NULL);

    EnableWindow(parent, FALSE);
    while (g_save_dlg) {
        if (!GetMessage(&msg, NULL, 0, 0)) break;
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    EnableWindow(parent, TRUE);
    /* SetForegroundWindow is Win95+; BringWindowToTop works on Win16 too */
    BringWindowToTop(parent);
    SetActiveWindow(parent);

    return g_save_filename[0] != '\0';
}

/* ------------------------------------------------------------------ */
/* Main window                                                         */
/* ------------------------------------------------------------------ */

static HWND g_hwnd_input   = NULL;
static HWND g_hwnd_results = NULL;
static char g_results_buf[2048];
static IpInfo g_info;

static void do_calculate(HWND hwnd)
{
    char input[128];
    char errbuf[128];

    GetWindowText(g_hwnd_input, input, sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';

    if (!input[0]) {
        SetWindowText(g_hwnd_results, "Enter an IP address or CIDR, e.g.:\r\n"
                                      "  192.168.1.0/24\r\n"
                                      "  10.0.0.1 255.0.0.0\r\n"
                                      "  172.16.0.1/12");
        return;
    }

    errbuf[0] = '\0';
    if (!ipcalc(input, &g_info, errbuf)) {
        char msg[192];
        sprintf(msg, "Error: %s", errbuf[0] ? errbuf : "invalid input");
        SetWindowText(g_hwnd_results, msg);
        return;
    }

    format_results(&g_info, g_results_buf, sizeof(g_results_buf));
    SetWindowText(g_hwnd_results, g_results_buf);
}

static void do_copy(HWND hwnd)
{
    int   len = lstrlen(g_results_buf);
    HGLOBAL hg;
    char   *p;

    if (!len) return;
    hg = GlobalAlloc(GMEM_MOVEABLE, len + 1);
    if (!hg) return;
    p = (char *)GlobalLock(hg);
    if (!p) { GlobalFree(hg); return; }
    memcpy(p, g_results_buf, len + 1);
    GlobalUnlock(hg);

    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        SetClipboardData(CF_TEXT, hg);
        CloseClipboard();
    } else {
        GlobalFree(hg);
    }
}

static void do_save(HWND hwnd)
{
    if (!g_results_buf[0]) return;
    if (!ask_save_filename(hwnd)) return;
    write_to_file(g_save_filename, g_results_buf);
}

static void do_about(HWND hwnd)
{
    MessageBox(hwnd,
        "ipcalc " __DATE__ "\r\n\r\n"
        "IP subnet calculator for Win16/Win32s.\r\n\r\n"
        "Calculates network, broadcast, host range,\r\n"
        "prefix, wildcard, class and RFC 1918 type.\r\n\r\n"
        "Algorithm based on ipcalc by Joakim Plate\r\n"
        "(kjokjo/ipcalc) \xe2\x80\x94 released under the GPL.",
        "About ipcalc",
        MB_OK | MB_ICONINFORMATION);
}

LRESULT CALLBACK WINCB IpcWndProc(HWND hwnd, UINT msg,
                                   WPARAM wp, LPARAM lp)
{
    int id, code;
    switch (msg) {
    case WM_CREATE: {
        HWND h;
#ifndef IPC_WIN16
        g_theme    = aeldre_theme_load();
        g_bg_brush = CreateSolidBrush(g_aeldre_themes[g_theme].bg);
#endif
        /* row 1: label + input + Calc */
        CreateWindow("STATIC", "Address:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            8, 12, 60, 16, hwnd, (HMENU)0, g_hinst, NULL);
        g_hwnd_input = CreateWindow("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            70, 8, 228, 20, hwnd, (HMENU)IDC_INPUT, g_hinst, NULL);
        CreateWindow("BUTTON", "Calc",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            304, 7, 50, 22, hwnd, (HMENU)IDC_CALC, g_hinst, NULL);

        /* row 2: results */
        g_hwnd_results = CreateWindow("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            8, 36, 346, 218, hwnd, (HMENU)IDC_RESULTS, g_hinst, NULL);

        /* row 3: buttons */
        h = CreateWindow("BUTTON", "Copy",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            8, 262, 60, 22, hwnd, (HMENU)IDC_COPY, g_hinst, NULL);
        (void)h;
        CreateWindow("BUTTON", "Save...",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            74, 262, 60, 22, hwnd, (HMENU)IDC_SAVE, g_hinst, NULL);
        CreateWindow("BUTTON", "About",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            140, 262, 60, 22, hwnd, (HMENU)IDC_ABOUT, g_hinst, NULL);
        CreateWindow("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            294, 262, 60, 22, hwnd, (HMENU)IDC_CLOSE, g_hinst, NULL);

        /* prompt */
        SetWindowText(g_hwnd_results,
            "Enter an IP address or CIDR, then click Calc.\r\n\r\n"
            "Examples:\r\n"
            "  192.168.1.0/24\r\n"
            "  10.0.0.1 255.0.0.0\r\n"
            "  172.16.0.1/12");
        return 0;
    }

    case WM_SIZE: {
        /* reflow controls if window is resized */
        int w = (int)LOWORD(lp);
        int h = (int)HIWORD(lp);
        int brow = h - 30;
        if (g_hwnd_input) {
            MoveWindow(g_hwnd_input,   70, 8, w - 134, 20, TRUE);
            MoveWindow(g_hwnd_results, 8, 36, w - 16, h - 80, TRUE);
            SetWindowPos(GetDlgItem(hwnd, IDC_CALC),  NULL,
                         w - 62, 7,  0, 0, SWP_NOSIZE | SWP_NOZORDER);
            SetWindowPos(GetDlgItem(hwnd, IDC_CLOSE),   NULL,
                         w - 68, brow, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        }
        return 0;
    }

    case WM_COMMAND:
        id   = CMD_ID(wp, lp);
        code = CMD_CODE(wp, lp);
        (void)code;
        if (id == IDC_CALC)  { do_calculate(hwnd); return 0; }
        if (id == IDC_COPY)  { do_copy(hwnd);      return 0; }
        if (id == IDC_SAVE)  { do_save(hwnd);      return 0; }
        if (id == IDC_ABOUT) { do_about(hwnd);     return 0; }
        if (id == IDC_CLOSE)   { DestroyWindow(hwnd); return 0; }
        return 0;

    case WM_DESTROY:
#ifndef IPC_WIN16
        if (g_bg_brush) { DeleteObject(g_bg_brush); g_bg_brush = NULL; }
#endif
        PostQuitMessage(0);
        return 0;
#ifndef IPC_WIN16
    case WM_ERASEBKGND: {
        HDC hdc=(HDC)wp; RECT rc;
        GetClientRect(hwnd,&rc); FillRect(hdc,&rc,g_bg_brush); return 1;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc=(HDC)wp; const AeldreTheme *t=&g_aeldre_themes[g_theme];
        SetTextColor(hdc,t->body); SetBkColor(hdc,t->bg); return (LRESULT)g_bg_brush;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc=(HDC)wp; const AeldreTheme *t=&g_aeldre_themes[g_theme];
        SetTextColor(hdc,t->body); SetBkColor(hdc,t->bg); return (LRESULT)g_bg_brush;
    }
    case WM_CTLCOLORBTN:
        SetBkColor((HDC)wp,g_aeldre_themes[g_theme].bg); return (LRESULT)g_bg_brush;
#endif
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* Command-line parsing and CLI mode                                   */
/* ------------------------------------------------------------------ */

#define MY_ARGC_MAX 16
static int   my_argc = 0;
static char *my_argv[MY_ARGC_MAX];
static char  my_cmdline[1024];
#ifdef IPC_WIN16
static LPSTR g_lpcmd16 = "";   /* set at WinMain entry from lpCmdLine */
#endif

static void parse_cmdline(void)
{
    char *p;
#ifdef IPC_WIN16
    /* Win16 WinMain lpCmdLine already has the program name stripped  */
    strncpy(my_cmdline, g_lpcmd16, sizeof(my_cmdline) - 1);
    p = my_cmdline;
#else
    /* Win32: GetCommandLine includes the program name; skip it       */
    p = GetCommandLine();
    strncpy(my_cmdline, p, sizeof(my_cmdline) - 1);
    p = my_cmdline;
    if (*p == '"') {
        p++;
        while (*p && *p != '"') p++;
        if (*p) p++;
    } else {
        while (*p && *p != ' ') p++;
    }
#endif
    while (*p && my_argc < MY_ARGC_MAX - 1) {
        while (*p == ' ') p++;
        if (!*p) break;
        my_argv[my_argc++] = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
    }
    my_argv[my_argc] = NULL;
}

/* ------------------------------------------------------------------ */
/* WinMain                                                             */
/* ------------------------------------------------------------------ */

int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nShow)
{
    WNDCLASS wc;
    HWND     hwnd;
    MSG      msg;
    char    *target_arg  = NULL;
    char    *mask_arg    = NULL;
    char    *outfile_arg = NULL;
    static char combined_target[256];
    int      i;

    (void)hPrev;
    g_hinst = hInst;
#ifdef IPC_WIN16
    g_lpcmd16 = lpCmdLine ? lpCmdLine : "";
#else
    (void)lpCmdLine;
#endif

    parse_cmdline();

    for (i = 0; i < my_argc; i++) {
        if (strcmp(my_argv[i], "-o") == 0 && i + 1 < my_argc)
            outfile_arg = my_argv[++i];
        else if (my_argv[i][0] != '-' && !target_arg)
            target_arg = my_argv[i];
        else if (my_argv[i][0] != '-' && !mask_arg)
            mask_arg = my_argv[i];
    }

    /* Two positional args: "192.168.1.0" "255.255.255.0" → join with space */
    if (target_arg && mask_arg) {
        snprintf(combined_target, sizeof(combined_target),
                 "%s %s", target_arg, mask_arg);
        target_arg = combined_target;
    }

    /* CLI mode ---------------------------------------------------- */
    if (target_arg) {
        IpInfo   info;
        char     errbuf[128];
        char     text[2048];

        errbuf[0] = '\0';
        if (!ipcalc(target_arg, &info, errbuf)) {
            MessageBox(NULL, errbuf[0] ? errbuf : "Invalid input.",
                       "ipcalc", MB_OK | MB_ICONERROR);
            return 1;
        }
        format_results(&info, text, sizeof(text));

        if (outfile_arg)
            write_to_file(outfile_arg, text);

#ifndef IPC_WIN16
        /* Win32: always write to stdout; exit headless if it is not a real
           console (i.e. stdout is a pipe or captured by a parent process). */
        {
            HANDLE h    = GetStdHandle(STD_OUTPUT_HANDLE);
            DWORD  mode = 0;
            if (h && h != INVALID_HANDLE_VALUE)
                write_to_handle(h, text);
            if (!h || h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode))
                return 0;   /* stdout piped/captured — no GUI needed */
        }
#endif
        if (outfile_arg)
            return 0;   /* -o specified: caller wants headless output only */

        /* fall through: show GUI with pre-computed result */
        memcpy(&g_info, &info, sizeof(info));
        memcpy(g_results_buf, text, sizeof(text));
    }

    /* GUI mode ---------------------------------------------------- */
    if (!hPrev) {
        memset(&wc, 0, sizeof(wc));
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = IpcWndProc;
        wc.hInstance     = hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = WC_IPCALC;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
        if (!RegisterClass(&wc)) {
            MessageBox(NULL, "RegisterClass failed.", "ipcalc",
                       MB_OK | MB_ICONERROR);
            return 1;
        }
    }

    hwnd = CreateWindow(WC_IPCALC, "ipcalc  \xe2\x80\x94  IP Subnet Calculator",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 380, 330,
        NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;

    /* if we have a pre-computed result, populate the edit box */
    if (target_arg) {
        SetWindowText(g_hwnd_input, target_arg);
        SetWindowText(g_hwnd_results, g_results_buf);
    }

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    /* IsDialogMessage routes Enter to BS_DEFPUSHBUTTON (IDC_CALC) and
       handles Tab focus traversal — works on Win16 and Win32 alike.   */
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return (int)msg.wParam;
}
