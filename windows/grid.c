/*
 * grid.c  --  Win32/Win32s network port scanner
 *
 * GUI subsystem (required for Win32s). WinMain entry.
 * Scan engine: async non-blocking connect pool, select()-polled, no threads.
 * Compatible with Winsock 1.1 / Win32s / WFW 3.11 through Windows NT 4.
 *
 * Mode detection (auto, at startup):
 *   stdout attached to a console  --  CLI: text progress + tab-delimited output
 *   stdout redirected to file     --  quiet: tab-delimited only, no window
 *   no stdout (Program Manager)   --  GUI: interactive window with input form
 *
 * CLI / redirected usage:
 *   grid <target> -p <ports> [-t ms] [-b] [-q] [-T n]
 *
 *   target   x.x.x.x | x.x.x.x/n | x.x.x.lo-hi | hostname
 *   -p       80 | 1-1024 | 22,80,443 | 1-100,443
 *   -t ms    connect timeout ms (default 500)
 *   -b       banner grab (first line after connect)
 *   -q       quiet: tab-delimited only, no window, no progress
 *   -T n     pool size / max concurrent connects (default 64, max 256)
 *
 * GUI mode: command-line args pre-fill the form; scan starts automatically
 * when both target and -p are supplied.
 *
 * Tab-delimited stdout line (CLI / redirected):
 *   HOST<TAB>PORT/tcp<TAB>open<TAB>SERVICE<TAB>BANNER
 */

#define FD_SETSIZE 256
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define MAX_POOL        256
#define DEF_POOL        64
#define DEF_TIMEOUT_MS  500
#define BANNER_TIMEOUT  300
#define BANNER_LEN      80
#define MAX_PORTS       65536
#define MAX_HOSTS_EXP   (1 << 16)
#define SVC_HASH        4096
#define SVC_HASH_MASK   (SVC_HASH - 1)

/* existing result-window control IDs */
#define IDC_LIST        101
#define IDC_STATUS      102
#define IDC_STOPBTN     103

/* interactive GUI control IDs */
#define IDC_TARGET      201
#define IDC_PORTS_ED    202
#define IDC_TIMEOUT_ED  203
#define IDC_POOL_ED     204
#define IDC_BANNER_CHK  205
#define IDC_SCAN        206
#define IDC_COPY        207
#define IDC_SAVE        208
#define IDC_CLOSE_BTN   209

#define WC_GRID         "GridScan"

/* top panel + bottom bar heights (pixels) */
#define PANEL_H  62
#define BBAR_H   26
#define CTRL_H   20

/* ------------------------------------------------------------------ */
/* Service table                                                       */
/* ------------------------------------------------------------------ */

typedef struct SvcEntry {
    unsigned short  port;
    char            name[24];
    struct SvcEntry *next;
} SvcEntry;

static SvcEntry *g_svc_hash[SVC_HASH];

static void svc_insert(unsigned short port, const char *name)
{
    unsigned h = port & SVC_HASH_MASK;
    SvcEntry *e;
    for (e = g_svc_hash[h]; e; e = e->next)
        if (e->port == port) return;
    e = (SvcEntry *)malloc(sizeof(SvcEntry));
    if (!e) return;
    e->port = port;
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    e->next = g_svc_hash[h];
    g_svc_hash[h] = e;
}

static const char *svc_lookup(unsigned short port)
{
    unsigned h = port & SVC_HASH_MASK;
    SvcEntry *e;
    for (e = g_svc_hash[h]; e; e = e->next)
        if (e->port == port) return e->name;
    return "";
}

static void load_services(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[256], name[64], proto[16];
    int  port;
    char *p;
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0' || *p == '\n') continue;
        if (sscanf(p, "%63s %d/%15s", name, &port, proto) == 3) {
            if (strcmp(proto, "tcp") == 0 && port > 0 && port < 65536)
                svc_insert((unsigned short)port, name);
        }
    }
    fclose(f);
}

static void find_and_load_services(void)
{
    char path[MAX_PATH];
    char *env;
    DWORD n;

    n = GetModuleFileName(NULL, path, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        char *sl = strrchr(path, '\\');
        if (sl) {
            strcpy(sl + 1, "SERVICES.DAT");
            if (GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES) {
                load_services(path);
                return;
            }
        }
    }
    env = getenv("GRIDDATA");
    if (env) {
        sprintf(path, "%.200s\\SERVICES.DAT", env);
        load_services(path);
    }
}

/* ------------------------------------------------------------------ */
/* Port list                                                           */
/* ------------------------------------------------------------------ */

static unsigned short g_ports[MAX_PORTS];
static int            g_nports = 0;

static void port_add(int p)
{
    if (p < 1 || p > 65535 || g_nports >= MAX_PORTS) return;
    g_ports[g_nports++] = (unsigned short)p;
}

static int parse_ports(const char *spec)
{
    const char *p = spec;
    while (*p) {
        char *end;
        int lo, hi, i;
        lo = (int)strtol(p, &end, 10);
        if (end == p) return 0;
        p = end;
        if (*p == '-') {
            p++;
            hi = (int)strtol(p, &end, 10);
            if (end == p) return 0;
            p = end;
        } else {
            hi = lo;
        }
        if (lo > hi) return 0;
        for (i = lo; i <= hi; i++) port_add(i);
        if (*p == ',') p++;
    }
    return g_nports > 0;
}

/* ------------------------------------------------------------------ */
/* Host list                                                           */
/* ------------------------------------------------------------------ */

static unsigned long *g_hosts    = NULL;
static int            g_nhosts   = 0;
static int            g_hostsmax = 0;

static void host_add(unsigned long ip)
{
    if (g_nhosts >= g_hostsmax) {
        int nm = g_hostsmax ? g_hostsmax * 2 : 256;
        unsigned long *t = (unsigned long *)realloc(g_hosts,
                                nm * sizeof(unsigned long));
        if (!t) return;
        g_hosts    = t;
        g_hostsmax = nm;
    }
    if (g_nhosts < MAX_HOSTS_EXP)
        g_hosts[g_nhosts++] = ip;
}

static int parse_target(const char *spec)
{
    char buf[128];
    const char *sl;
    int a, b, c, lo, hi, i;
    unsigned long base;

    strncpy(buf, spec, 127); buf[127] = '\0';

    sl = strchr(buf, '/');
    if (sl) {
        int bits;
        char ipbuf[64];
        unsigned long mask;
        strncpy(ipbuf, buf, (int)(sl - buf));
        ipbuf[sl - buf] = '\0';
        bits = atoi(sl + 1);
        if (bits < 0 || bits > 32) return 0;
        base = ntohl(inet_addr(ipbuf));
        if (base == INADDR_NONE) return 0;
        mask = bits ? (0xFFFFFFFFUL << (32 - bits)) : 0;
        base &= mask;
        for (i = 1; i < (int)(1UL << (32 - bits)) - 1; i++) {
            if (g_nhosts >= MAX_HOSTS_EXP) break;
            host_add(htonl(base + i));
        }
        return g_nhosts > 0;
    }

    if (sscanf(buf, "%d.%d.%d.%d-%d", &a, &b, &c, &lo, &hi) == 5) {
        for (i = lo; i <= hi; i++) {
            char tmp[32];
            sprintf(tmp, "%d.%d.%d.%d", a, b, c, i);
            base = inet_addr(tmp);
            if (base != INADDR_NONE) host_add(base);
        }
        return g_nhosts > 0;
    }

    base = inet_addr(buf);
    if (base != INADDR_NONE) { host_add(base); return 1; }

    {
        struct hostent *he = gethostbyname(buf);
        if (!he) return 0;
        memcpy(&base, he->h_addr, 4);
        host_add(base);
        return 1;
    }
}

/* ------------------------------------------------------------------ */
/* Scan pool                                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    SOCKET         s;
    unsigned long  host_ip;
    unsigned short port;
    DWORD          deadline;
    int            active;
} Slot;

static Slot g_pool[MAX_POOL];
static int  g_pool_active = 0;
static int  g_pool_size   = DEF_POOL;

static int g_timeout_ms = DEF_TIMEOUT_MS;
static int g_banner     = 0;
static int g_quiet      = 0;

static int  g_work_idx   = 0;
static int  g_work_total = 0;
static int  g_done       = 0;
static int  g_open_count = 0;
static int  g_stop       = 0;

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

static HANDLE g_out_h       = INVALID_HANDLE_VALUE;
static int    g_out_ok      = 0;
static int    g_out_console = 0;
static int    g_gui_mode    = 0;

static HWND   g_hwnd_frame      = NULL;
static HWND   g_hwnd_list       = NULL;
static HWND   g_hwnd_status     = NULL;
static HWND   g_hwnd_stop       = NULL;
static HWND   g_hwnd_target     = NULL;
static HWND   g_hwnd_ports_ed   = NULL;
static HWND   g_hwnd_timeout_ed = NULL;
static HWND   g_hwnd_pool_ed    = NULL;
static HWND   g_hwnd_banner_chk = NULL;
static HWND   g_hwnd_scan       = NULL;
static HWND   g_hwnd_copy       = NULL;
static HWND   g_hwnd_save       = NULL;
static HWND   g_hwnd_close      = NULL;
static HINSTANCE g_hinst        = NULL;

/* pre-fill values from command-line args */
static char g_pre_target[256] = "";
static char g_pre_ports[256]  = "";
static char g_pre_timeout[16] = "500";
static char g_pre_pool[16]    = "64";
static int  g_pre_banner      = 0;
static int  g_autoscan        = 0;

static void out_write(const char *s, int len)
{
    DWORD w;
    if (g_out_ok && len > 0)
        WriteFile(g_out_h, s, len, &w, NULL);
}

static void out_result(const char *host, unsigned short port,
                       const char *svc, const char *banner)
{
    char line[320];
    int  n;

    if (g_out_console)
        out_write("\r                                                  \r", 52);

    /* tab-delimited for stdout (CLI / redirected) */
    n = sprintf(line, "%s\t%u/tcp\topen\t%s\t%s\r\n",
                host, (unsigned)port, svc, banner);
    if (g_out_ok)
        out_write(line, n);

    /* fixed-width display for GUI listbox */
    if (g_hwnd_list) {
        char lb[320];
        int cnt;
        sprintf(lb, "%-16s %-5u/tcp  %-20s  %s",
                host, (unsigned)port, svc, banner);
        SendMessage(g_hwnd_list, LB_ADDSTRING, 0, (LPARAM)lb);
        cnt = (int)SendMessage(g_hwnd_list, LB_GETCOUNT, 0, 0);
        SendMessage(g_hwnd_list, LB_SETTOPINDEX, cnt - 1, 0);
    }
    g_open_count++;
}

static void out_progress(void)
{
    char buf[80];
    int  n;
    if (g_hwnd_status) {
        sprintf(buf, "  %d / %d  open: %d", g_done, g_work_total, g_open_count);
        SetWindowText(g_hwnd_status, buf);
    }
    if (g_out_console) {
        n = sprintf(buf, "  %d/%d  open: %d  \r", g_done, g_work_total, g_open_count);
        out_write(buf, n);
    }
}

/* ------------------------------------------------------------------ */
/* Banner grab                                                         */
/* ------------------------------------------------------------------ */

static void grab_banner(SOCKET s, char *out, int outlen)
{
    fd_set rs;
    struct timeval tv;
    int n;
    char *p;
    out[0] = '\0';
    FD_ZERO(&rs); FD_SET(s, &rs);
    tv.tv_sec  = 0;
    tv.tv_usec = BANNER_TIMEOUT * 1000;
    if (select(0, &rs, NULL, NULL, &tv) <= 0) return;
    n = recv(s, out, outlen - 1, 0);
    if (n <= 0) { out[0] = '\0'; return; }
    out[n] = '\0';
    for (p = out; *p; p++) {
        if (*p == '\r' || *p == '\n') { *p = '\0'; break; }
        if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e) *p = '.';
    }
}

/* ------------------------------------------------------------------ */
/* Slot management                                                     */
/* ------------------------------------------------------------------ */

static void slot_close(int i)
{
    if (!g_pool[i].active) return;
    closesocket(g_pool[i].s);
    g_pool[i].active = 0;
    g_pool_active--;
    g_done++;
}

static void slot_open(int i, unsigned long ip, unsigned short port)
{
    SOCKET s;
    u_long nb = 1;
    struct sockaddr_in sa;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { g_done++; return; }

    ioctlsocket(s, FIONBIO, &nb);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = ip;
    connect(s, (struct sockaddr *)&sa, sizeof(sa));

    g_pool[i].s        = s;
    g_pool[i].host_ip  = ip;
    g_pool[i].port     = port;
    g_pool[i].deadline = GetTickCount() + (DWORD)g_timeout_ms;
    g_pool[i].active   = 1;
    g_pool_active++;
}

/* ------------------------------------------------------------------ */
/* One scan tick                                                       */
/* ------------------------------------------------------------------ */

static void scan_tick(void)
{
    fd_set wfds, efds;
    struct timeval tv;
    int i;
    DWORD now;

    for (i = 0; i < g_pool_size && g_work_idx < g_work_total; i++) {
        if (!g_pool[i].active) {
            int hi = g_work_idx / g_nports;
            int pi = g_work_idx % g_nports;
            slot_open(i, g_hosts[hi], g_ports[pi]);
            g_work_idx++;
        }
    }

    if (g_pool_active == 0) return;

    FD_ZERO(&wfds); FD_ZERO(&efds);
    for (i = 0; i < g_pool_size; i++) {
        if (g_pool[i].active) {
            FD_SET(g_pool[i].s, &wfds);
            FD_SET(g_pool[i].s, &efds);
        }
    }

    tv.tv_sec  = 0;
    tv.tv_usec = 10000;
    select(0, NULL, &wfds, &efds, &tv);

    now = GetTickCount();
    for (i = 0; i < g_pool_size; i++) {
        if (!g_pool[i].active) continue;

        if (FD_ISSET(g_pool[i].s, &wfds)) {
            int err = 0, elen = sizeof(err);
            getsockopt(g_pool[i].s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen);
            if (err == 0) {
                char banner[BANNER_LEN + 1];
                struct in_addr ia;
                char host_str[20];
                if (g_banner) grab_banner(g_pool[i].s, banner, BANNER_LEN);
                else banner[0] = '\0';
                ia.s_addr = g_pool[i].host_ip;
                strncpy(host_str, inet_ntoa(ia), sizeof(host_str) - 1);
                out_result(host_str, g_pool[i].port,
                           svc_lookup(g_pool[i].port), banner);
            }
            slot_close(i);
        } else if (FD_ISSET(g_pool[i].s, &efds)) {
            slot_close(i);
        } else if ((long)(now - g_pool[i].deadline) >= 0) {
            slot_close(i);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Main scan loop                                                      */
/* ------------------------------------------------------------------ */

static void do_scan(void)
{
    MSG  msg;
    int  last_done = -1;

    g_work_total = g_nhosts * g_nports;

    while ((g_work_idx < g_work_total || g_pool_active > 0) && !g_stop) {
        scan_tick();

        if (g_done != last_done) {
            out_progress();
            last_done = g_done;
        }

        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (!IsDialogMessage(g_hwnd_frame, &msg)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            if (msg.message == WM_QUIT) { g_stop = 1; break; }
        }
    }

    if (g_out_console)
        out_write("\r\n", 2);
}

/* ------------------------------------------------------------------ */
/* Scan state reset (call before each new scan)                       */
/* ------------------------------------------------------------------ */

static void scan_reset(void)
{
    int i;
    for (i = 0; i < MAX_POOL; i++) {
        if (g_pool[i].active) { closesocket(g_pool[i].s); g_pool[i].active = 0; }
    }
    g_pool_active = 0;
    free(g_hosts); g_hosts = NULL; g_nhosts = 0; g_hostsmax = 0;
    g_nports     = 0;
    g_work_idx   = 0;
    g_work_total = 0;
    g_done       = 0;
    g_open_count = 0;
    g_stop       = 0;
}

/* ------------------------------------------------------------------ */
/* GUI: start a scan from the input form                              */
/* ------------------------------------------------------------------ */

static void gui_do_scan(HWND hwnd)
{
    char tbuf[256], pbuf[256], tobuf[16], pobuf[16];

    GetWindowText(g_hwnd_target,     tbuf,  sizeof(tbuf));
    GetWindowText(g_hwnd_ports_ed,   pbuf,  sizeof(pbuf));
    GetWindowText(g_hwnd_timeout_ed, tobuf, sizeof(tobuf));
    GetWindowText(g_hwnd_pool_ed,    pobuf, sizeof(pobuf));

    if (!tbuf[0] || !pbuf[0]) {
        MessageBox(hwnd, "Enter a target and port specification.",
                   "Grid", MB_OK | MB_ICONINFORMATION);
        return;
    }

    g_banner     = (int)(SendMessage(g_hwnd_banner_chk, BM_GETCHECK, 0, 0)
                         == BST_CHECKED);
    g_timeout_ms = atoi(tobuf);
    if (g_timeout_ms < 50) g_timeout_ms = 50;
    g_pool_size  = atoi(pobuf);
    if (g_pool_size < 1)          g_pool_size = 1;
    if (g_pool_size > MAX_POOL)   g_pool_size = MAX_POOL;

    scan_reset();

    if (!parse_ports(pbuf)) {
        MessageBox(hwnd, "Bad port specification.", "Grid", MB_OK | MB_ICONERROR);
        return;
    }
    if (!parse_target(tbuf)) {
        MessageBox(hwnd, "Cannot resolve target.", "Grid", MB_OK | MB_ICONERROR);
        return;
    }

    /* clear previous results */
    SendMessage(g_hwnd_list, LB_RESETCONTENT, 0, 0);
    SendMessage(g_hwnd_list, LB_SETHORIZONTALEXTENT, 1200, 0);

    /* lock input during scan */
    EnableWindow(g_hwnd_scan,       FALSE);
    EnableWindow(g_hwnd_target,     FALSE);
    EnableWindow(g_hwnd_ports_ed,   FALSE);
    EnableWindow(g_hwnd_timeout_ed, FALSE);
    EnableWindow(g_hwnd_pool_ed,    FALSE);
    EnableWindow(g_hwnd_banner_chk, FALSE);
    SetWindowText(g_hwnd_stop, "Stop");
    EnableWindow(g_hwnd_stop, TRUE);

    do_scan();

    /* unlock after scan */
    EnableWindow(g_hwnd_scan,       TRUE);
    EnableWindow(g_hwnd_target,     TRUE);
    EnableWindow(g_hwnd_ports_ed,   TRUE);
    EnableWindow(g_hwnd_timeout_ed, TRUE);
    EnableWindow(g_hwnd_pool_ed,    TRUE);
    EnableWindow(g_hwnd_banner_chk, TRUE);
    SetWindowText(g_hwnd_stop, "Done");
    EnableWindow(g_hwnd_stop, FALSE);

    {
        char buf[80];
        sprintf(buf, "  Done.  %d / %d  open: %d",
                g_done, g_work_total, g_open_count);
        SetWindowText(g_hwnd_status, buf);
    }
}

/* ------------------------------------------------------------------ */
/* GUI: copy results to clipboard                                     */
/* ------------------------------------------------------------------ */

static void gui_copy(HWND hwnd)
{
    int    count = (int)SendMessage(g_hwnd_list, LB_GETCOUNT, 0, 0);
    int    i, total = 0;
    char   tmp[512];
    HGLOBAL hg;
    char   *p;

    if (!count) return;

    for (i = 0; i < count; i++)
        total += (int)SendMessage(g_hwnd_list, LB_GETTEXTLEN, i, 0) + 2;

    hg = GlobalAlloc(GMEM_MOVEABLE, (DWORD)(total + 1));
    if (!hg) return;
    p = (char *)GlobalLock(hg);
    if (!p) { GlobalFree(hg); return; }

    for (i = 0; i < count; i++) {
        int n;
        SendMessage(g_hwnd_list, LB_GETTEXT, i, (LPARAM)tmp);
        n = lstrlen(tmp);
        memcpy(p, tmp, n); p += n;
        *p++ = '\r'; *p++ = '\n';
    }
    *p = '\0';
    GlobalUnlock(hg);

    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        SetClipboardData(CF_TEXT, hg);
        CloseClipboard();
    } else {
        GlobalFree(hg);
    }
}

/* ------------------------------------------------------------------ */
/* GUI: save results to file                                          */
/* ------------------------------------------------------------------ */

static void gui_save(HWND hwnd)
{
    OPENFILENAME ofn;
    char   path[MAX_PATH] = "";
    FILE  *f;
    char   tmp[512];
    int    i, count;

    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = hwnd;
    ofn.lpstrFilter = "Text files\0*.txt\0All files\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrDefExt = "txt";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (!GetSaveFileName(&ofn)) return;

    f = fopen(path, "w");
    if (!f) {
        MessageBox(hwnd, "Cannot create file.", "Grid", MB_OK | MB_ICONERROR);
        return;
    }
    count = (int)SendMessage(g_hwnd_list, LB_GETCOUNT, 0, 0);
    for (i = 0; i < count; i++) {
        SendMessage(g_hwnd_list, LB_GETTEXT, i, (LPARAM)tmp);
        fprintf(f, "%s\n", tmp);
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Main window procedure                                              */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK GridWndProc(HWND hwnd, UINT msg,
                                     WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        /* ---- Row 1: Target edit, Ports edit ---- */
        CreateWindow("STATIC", "Target:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            4, 8, 46, 16, hwnd, NULL, g_hinst, NULL);
        g_hwnd_target = CreateWindow("EDIT", g_pre_target,
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            54, 6, 300, CTRL_H, hwnd, (HMENU)IDC_TARGET, g_hinst, NULL);
        CreateWindow("STATIC", "Ports:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            362, 8, 40, 16, hwnd, NULL, g_hinst, NULL);
        g_hwnd_ports_ed = CreateWindow("EDIT", g_pre_ports,
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            406, 6, 226, CTRL_H, hwnd, (HMENU)IDC_PORTS_ED, g_hinst, NULL);

        /* ---- Row 2: Timeout, Banner, Pool, Scan, Stop ---- */
        CreateWindow("STATIC", "Timeout:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            4, 32, 52, 16, hwnd, NULL, g_hinst, NULL);
        g_hwnd_timeout_ed = CreateWindow("EDIT", g_pre_timeout,
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
            60, 30, 44, CTRL_H, hwnd, (HMENU)IDC_TIMEOUT_ED, g_hinst, NULL);
        CreateWindow("STATIC", "ms",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            108, 32, 20, 16, hwnd, NULL, g_hinst, NULL);
        g_hwnd_banner_chk = CreateWindow("BUTTON", "Banner grab",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            134, 30, 94, CTRL_H, hwnd, (HMENU)IDC_BANNER_CHK, g_hinst, NULL);
        if (g_pre_banner)
            SendMessage(g_hwnd_banner_chk, BM_SETCHECK, BST_CHECKED, 0);
        CreateWindow("STATIC", "Pool:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            234, 32, 36, 16, hwnd, NULL, g_hinst, NULL);
        g_hwnd_pool_ed = CreateWindow("EDIT", g_pre_pool,
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
            274, 30, 44, CTRL_H, hwnd, (HMENU)IDC_POOL_ED, g_hinst, NULL);
        g_hwnd_scan = CreateWindow("BUTTON", "Scan",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            326, 28, 148, 24, hwnd, (HMENU)IDC_SCAN, g_hinst, NULL);
        g_hwnd_stop = CreateWindow("BUTTON", "Stop",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
            478, 28, 154, 24, hwnd, (HMENU)IDC_STOPBTN, g_hinst, NULL);

        /* ---- Results list box ---- */
        g_hwnd_list = CreateWindow("LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | WS_BORDER |
            LBS_NOINTEGRALHEIGHT | LBS_NOSEL,
            0, PANEL_H, 100, 100,
            hwnd, (HMENU)IDC_LIST, g_hinst, NULL);
        SendMessage(g_hwnd_list, WM_SETFONT,
            (WPARAM)GetStockObject(ANSI_FIXED_FONT), FALSE);
        SendMessage(g_hwnd_list, LB_SETHORIZONTALEXTENT, 1200, 0);

        /* ---- Bottom bar: status, Copy, Save, Close ---- */
        g_hwnd_status = CreateWindow("STATIC", "  Ready.",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            4, 0, 100, 20, hwnd, (HMENU)IDC_STATUS, g_hinst, NULL);
        g_hwnd_copy = CreateWindow("BUTTON", "Copy",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 76, 22, hwnd, (HMENU)IDC_COPY, g_hinst, NULL);
        g_hwnd_save = CreateWindow("BUTTON", "Save...",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 76, 22, hwnd, (HMENU)IDC_SAVE, g_hinst, NULL);
        g_hwnd_close = CreateWindow("BUTTON", "Close",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 88, 22, hwnd, (HMENU)IDC_CLOSE_BTN, g_hinst, NULL);
        return 0;

    case WM_SIZE: {
        int cw = (int)LOWORD(lp);
        int ch = (int)HIWORD(lp);
        int by = ch - BBAR_H;

        /* stretch target edit to fill row 1, ports edit anchored right */
        if (g_hwnd_target)
            MoveWindow(g_hwnd_target,   54, 6, cw - 290, CTRL_H, TRUE);
        if (g_hwnd_ports_ed)
            MoveWindow(g_hwnd_ports_ed, cw - 232, 6, 228, CTRL_H, TRUE);
        /* anchor Scan + Stop buttons to right of row 2 */
        if (g_hwnd_scan)
            MoveWindow(g_hwnd_scan, cw - 318, 28, 148, 24, TRUE);
        if (g_hwnd_stop)
            MoveWindow(g_hwnd_stop, cw - 166, 28, 162, 24, TRUE);

        /* list box fills the middle */
        if (g_hwnd_list)
            MoveWindow(g_hwnd_list, 0, PANEL_H, cw, by - PANEL_H, TRUE);

        /* bottom bar */
        if (g_hwnd_status)
            MoveWindow(g_hwnd_status, 4, by + 3, cw - 256, 20, TRUE);
        if (g_hwnd_copy)
            MoveWindow(g_hwnd_copy,   cw - 252, by + 2, 76, 22, TRUE);
        if (g_hwnd_save)
            MoveWindow(g_hwnd_save,   cw - 172, by + 2, 76, 22, TRUE);
        if (g_hwnd_close)
            MoveWindow(g_hwnd_close,  cw - 92,  by + 2, 88, 22, TRUE);
        return 0;
    }

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mm = (MINMAXINFO *)lp;
        mm->ptMinTrackSize.x = 500;
        mm->ptMinTrackSize.y = 320;
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_SCAN:
            gui_do_scan(hwnd);
            break;
        case IDC_STOPBTN:
            g_stop = 1;
            break;
        case IDC_COPY:
            gui_copy(hwnd);
            break;
        case IDC_SAVE:
            gui_save(hwnd);
            break;
        case IDC_CLOSE_BTN:
            DestroyWindow(hwnd);
            break;
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* Command-line parser                                                 */
/* ------------------------------------------------------------------ */

#define MY_ARGC_MAX 64
static int   my_argc = 0;
static char *my_argv[MY_ARGC_MAX];
static char  my_cmdline[2048];

static void parse_cmdline(void)
{
    char *p = GetCommandLine();
    strncpy(my_cmdline, p, sizeof(my_cmdline) - 1);
    p = my_cmdline;

    if (*p == '"') {
        p++;
        while (*p && *p != '"') p++;
        if (*p) p++;
    } else {
        while (*p && *p != ' ') p++;
    }

    while (*p && my_argc < MY_ARGC_MAX - 1) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '"') {
            my_argv[my_argc++] = ++p;
            while (*p && *p != '"') p++;
            if (*p) *p++ = '\0';
        } else {
            my_argv[my_argc++] = p;
            while (*p && *p != ' ') p++;
            if (*p) *p++ = '\0';
        }
    }
    my_argv[my_argc] = NULL;
}

/* ------------------------------------------------------------------ */
/* Usage (shown in CLI mode when args are missing)                    */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    MessageBox(NULL,
        "Usage: grid <target> -p <ports> [options]\r\n\r\n"
        "  target   x.x.x.x | x.x.x.x/24 | x.x.x.1-254 | hostname\r\n"
        "  -p       80 | 1-1024 | 22,80,443 | 1-100,443\r\n"
        "  -t ms    connect timeout ms (default 500)\r\n"
        "  -b       banner grab\r\n"
        "  -q       quiet / parseable (no window, stdout only)\r\n"
        "  -T n     pool size (default 64, max 256)\r\n\r\n"
        "Launched without a console: opens interactive GUI.\r\n"
        "Output: HOST<TAB>PORT/tcp<TAB>open<TAB>SERVICE<TAB>BANNER",
        "Grid", MB_OK | MB_ICONINFORMATION);
}

/* ------------------------------------------------------------------ */
/* WinMain                                                             */
/* ------------------------------------------------------------------ */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nShow)
{
    WSADATA   wsa;
    const char *target_arg = NULL;
    const char *ports_arg  = NULL;
    int        i;
    MSG        msg;

    (void)hPrev; (void)lpCmdLine; (void)nShow;
    g_hinst = hInst;

    parse_cmdline();

    /* parse args (apply to both CLI and GUI pre-fill) */
    for (i = 0; i < my_argc; i++) {
        if (strcmp(my_argv[i], "-p") == 0 && i + 1 < my_argc) {
            ports_arg = my_argv[++i];
        } else if (strcmp(my_argv[i], "-t") == 0 && i + 1 < my_argc) {
            g_timeout_ms = atoi(my_argv[++i]);
            if (g_timeout_ms < 50) g_timeout_ms = 50;
        } else if (strcmp(my_argv[i], "-b") == 0) {
            g_banner = 1; g_pre_banner = 1;
        } else if (strcmp(my_argv[i], "-q") == 0) {
            g_quiet = 1;
        } else if (strcmp(my_argv[i], "-T") == 0 && i + 1 < my_argc) {
            g_pool_size = atoi(my_argv[++i]);
            if (g_pool_size < 1)        g_pool_size = 1;
            if (g_pool_size > MAX_POOL) g_pool_size = MAX_POOL;
        } else if (my_argv[i][0] != '-') {
            target_arg = my_argv[i];
        }
    }

    /* detect stdout / console */
    g_out_h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_out_h && g_out_h != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        g_out_ok = 1;
        if (GetConsoleMode(g_out_h, &mode))
            g_out_console = 1;
    }

    /*
     * Mode selection:
     *   console stdout  -> CLI text mode (requires args)
     *   redirected      -> quiet TSV mode (requires args)
     *   no stdout       -> interactive GUI
     */
    if (g_out_ok || g_quiet) {
        /* CLI / redirected: need target + ports */
        if (!target_arg || !ports_arg) {
            usage();
            return 1;
        }
    } else {
        /* GUI mode */
        g_gui_mode = 1;
        if (target_arg) strncpy(g_pre_target, target_arg, sizeof(g_pre_target) - 1);
        if (ports_arg)  strncpy(g_pre_ports,  ports_arg,  sizeof(g_pre_ports)  - 1);
        if (g_timeout_ms != DEF_TIMEOUT_MS)
            sprintf(g_pre_timeout, "%d", g_timeout_ms);
        if (g_pool_size != DEF_POOL)
            sprintf(g_pre_pool, "%d", g_pool_size);
        if (target_arg && ports_arg)
            g_autoscan = 1;
    }

    if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0) {
        MessageBox(NULL, "WSAStartup failed.", "Grid", MB_OK | MB_ICONERROR);
        return 1;
    }

    find_and_load_services();

    if (g_gui_mode) {
        WNDCLASS wc;
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = GridWndProc;
        wc.hInstance     = g_hinst;
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = WC_GRID;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hIcon         = LoadIcon(g_hinst, MAKEINTRESOURCE(1));
        RegisterClass(&wc);

        g_hwnd_frame = CreateWindow(
            WC_GRID, "Grid \x97 Port Scanner",
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 660, 460,
            NULL, NULL, g_hinst, NULL);

        if (!g_hwnd_frame) {
            MessageBox(NULL, "CreateWindow failed.", "Grid", MB_OK | MB_ICONERROR);
            WSACleanup();
            return 1;
        }
        UpdateWindow(g_hwnd_frame);

        if (g_autoscan)
            PostMessage(g_hwnd_frame, WM_COMMAND, IDC_SCAN, 0);

        while (GetMessage(&msg, NULL, 0, 0)) {
            if (!IsDialogMessage(g_hwnd_frame, &msg)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    } else {
        /* CLI / redirected */
        if (!parse_ports(ports_arg)) {
            MessageBox(NULL, "Bad port specification.", "Grid", MB_OK | MB_ICONERROR);
            WSACleanup();
            return 1;
        }
        if (!parse_target(target_arg)) {
            MessageBox(NULL, "Cannot resolve target.", "Grid", MB_OK | MB_ICONERROR);
            WSACleanup();
            return 1;
        }
        do_scan();
    }

    for (i = 0; i < MAX_POOL; i++)
        if (g_pool[i].active) closesocket(g_pool[i].s);
    free(g_hosts);
    WSACleanup();
    return 0;
}
