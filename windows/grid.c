/*
 * grid.c  --  Win32/Win32s network port scanner
 *
 * GUI subsystem (required for Win32s). WinMain entry.
 * Scan engine: async non-blocking connect pool, select()-polled, no threads.
 * Compatible with Winsock 1.1 / Win32s / WFW 3.11 through Windows NT 4.
 *
 * Output modes (auto-detected at startup):
 *   stdout is a console  --  formatted progress + results (NT / Win95)
 *   stdout redirected    --  plain tab-delimited text, no progress noise
 *   no stdout            --  results window (Win32s from Program Manager)
 *
 * Usage: grid <target> -p <ports> [-t ms] [-b] [-q] [-T n]
 *
 *   target   x.x.x.x | x.x.x.x/n | x.x.x.lo-hi | hostname
 *   -p       80 | 1-1024 | 22,80,443 | 1-100,443
 *   -t ms    connect timeout ms (default 500)
 *   -b       banner grab (first line after connect)
 *   -q       quiet: tab-delimited only, no window, no progress
 *   -T n     pool size / max concurrent connects (default 64, max 256)
 *
 * Tab-delimited result line (all modes):
 *   HOST<TAB>PORT/tcp<TAB>open<TAB>SERVICE<TAB>BANNER
 */

#define FD_SETSIZE 256
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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
#define MAX_HOSTS_EXP   (1 << 16)   /* sanity cap: /16 is 65534 hosts */
#define SVC_HASH        4096
#define SVC_HASH_MASK   (SVC_HASH - 1)

#define IDC_LIST        101
#define IDC_STATUS      102
#define IDC_STOPBTN     103
#define WC_GRID         "GridScan"

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

static HWND   g_hwnd_frame  = NULL;
static HWND   g_hwnd_list   = NULL;
static HWND   g_hwnd_status = NULL;
static HWND   g_hwnd_stop   = NULL;
static HINSTANCE g_hinst    = NULL;

static void out_write(const char *s, int len)
{
    DWORD w;
    if (g_out_ok && len > 0)
        WriteFile(g_out_h, s, len, &w, NULL);
}

static void out_result(const char *host, unsigned short port,
                       const char *svc, const char *banner)
{
    char line[300];
    int  n;
    /* clear progress line first if console interactive */
    if (g_out_console)
        out_write("\r                                                  \r", 52);
    n = sprintf(line, "%s\t%u/tcp\topen\t%s\t%s\r\n",
                host, (unsigned)port, svc, banner);
    out_write(line, n);
    if (g_hwnd_list) {
        /* strip \r\n for listbox */
        char lb[280];
        sprintf(lb, "%s\t%u/tcp\topen\t%s\t%s", host, (unsigned)port, svc, banner);
        {
            int cnt;
            SendMessage(g_hwnd_list, LB_ADDSTRING, 0, (LPARAM)lb);
            cnt = (int)SendMessage(g_hwnd_list, LB_GETCOUNT, 0, 0);
            SendMessage(g_hwnd_list, LB_SETTOPINDEX, cnt - 1, 0);
        }
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

    /* fill empty slots from work queue */
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
    tv.tv_usec = 10000;     /* 10 ms poll */
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

        /* cooperative message pump — keeps Win32s happy */
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) { g_stop = 1; break; }
        }
    }

    if (g_out_console)
        out_write("\r\n", 2);

    if (g_hwnd_stop)
        SetWindowText(g_hwnd_stop, "Close");
    if (g_hwnd_status) {
        char buf[80];
        sprintf(buf, "  Done.  %d / %d  open: %d",
                g_done, g_work_total, g_open_count);
        SetWindowText(g_hwnd_status, buf);
    }
}

/* ------------------------------------------------------------------ */
/* Results window                                                      */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK GridWndProc(HWND hwnd, UINT msg,
                                    WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        g_hwnd_list = CreateWindow(
            "LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER |
            LBS_NOINTEGRALHEIGHT | LBS_NOTIFY,
            0, 0, 100, 100,
            hwnd, (HMENU)IDC_LIST, g_hinst, NULL);
        g_hwnd_status = CreateWindow(
            "STATIC", "  Initialising...",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            0, 0, 100, 20,
            hwnd, (HMENU)IDC_STATUS, g_hinst, NULL);
        g_hwnd_stop = CreateWindow(
            "BUTTON", "Stop",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 60, 20,
            hwnd, (HMENU)IDC_STOPBTN, g_hinst, NULL);
        return 0;

    case WM_SIZE: {
        int w = (int)LOWORD(lp);
        int h = (int)HIWORD(lp);
        int bh = 24;
        if (g_hwnd_list)
            MoveWindow(g_hwnd_list, 0, 0, w, h - bh, TRUE);
        if (g_hwnd_status)
            MoveWindow(g_hwnd_status, 0, h - bh, w - 64, bh, TRUE);
        if (g_hwnd_stop)
            MoveWindow(g_hwnd_stop, w - 64, h - bh, 64, bh, TRUE);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wp) == IDC_STOPBTN) {
            if (g_done < g_work_total)
                g_stop = 1;
            else
                DestroyWindow(hwnd);
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static void create_window(const char *title)
{
    WNDCLASS wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = GridWndProc;
    wc.hInstance     = g_hinst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = WC_GRID;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    g_hwnd_frame = CreateWindow(
        WC_GRID, title,
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 400,
        NULL, NULL, g_hinst, NULL);
}

/* ------------------------------------------------------------------ */
/* Command-line parser (GUI apps have no argv on Win32s)              */
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

    /* skip program name */
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
/* Usage                                                               */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    MessageBox(NULL,
        "Usage: grid <target> -p <ports> [options]\r\n\r\n"
        "  target   x.x.x.x | x.x.x.x/24 | x.x.x.1-254 | hostname\r\n"
        "  -p       80 | 1-1024 | 22,80,443 | 1-100,443\r\n"
        "  -t ms    connect timeout ms (default 500)\r\n"
        "  -b       banner grab\r\n"
        "  -q       quiet / parseable (stdout only, no window)\r\n"
        "  -T n     pool size (default 64, max 256)\r\n\r\n"
        "Output: HOST<TAB>PORT/tcp<TAB>open<TAB>SERVICE<TAB>BANNER",
        "Grid", MB_OK | MB_ICONINFORMATION);
}

/* ------------------------------------------------------------------ */
/* WinMain                                                             */
/* ------------------------------------------------------------------ */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nShow)
{
    WSADATA wsa;
    const char *target   = NULL;
    const char *portspec = NULL;
    char title[128];
    int  i;
    MSG  msg;

    (void)hPrev; (void)lpCmdLine; (void)nShow;
    g_hinst = hInst;

    parse_cmdline();

    if (my_argc < 1) { usage(); return 1; }

    for (i = 0; i < my_argc; i++) {
        if (strcmp(my_argv[i], "-p") == 0 && i + 1 < my_argc) {
            portspec = my_argv[++i];
        } else if (strcmp(my_argv[i], "-t") == 0 && i + 1 < my_argc) {
            g_timeout_ms = atoi(my_argv[++i]);
            if (g_timeout_ms < 50) g_timeout_ms = 50;
        } else if (strcmp(my_argv[i], "-b") == 0) {
            g_banner = 1;
        } else if (strcmp(my_argv[i], "-q") == 0) {
            g_quiet = 1;
        } else if (strcmp(my_argv[i], "-T") == 0 && i + 1 < my_argc) {
            g_pool_size = atoi(my_argv[++i]);
            if (g_pool_size < 1)          g_pool_size = 1;
            if (g_pool_size > MAX_POOL)   g_pool_size = MAX_POOL;
        } else if (my_argv[i][0] != '-') {
            target = my_argv[i];
        }
    }

    if (!target || !portspec) {
        usage();
        return 1;
    }

    if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0) {
        MessageBox(NULL, "WSAStartup failed.", "Grid", MB_OK | MB_ICONERROR);
        return 1;
    }

    find_and_load_services();

    if (!parse_ports(portspec)) {
        MessageBox(NULL, "Bad port specification.", "Grid", MB_OK | MB_ICONERROR);
        WSACleanup();
        return 1;
    }

    if (!parse_target(target)) {
        MessageBox(NULL, "Cannot resolve target.", "Grid", MB_OK | MB_ICONERROR);
        WSACleanup();
        return 1;
    }

    /* detect stdout */
    g_out_h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_out_h && g_out_h != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        g_out_ok = 1;
        if (GetConsoleMode(g_out_h, &mode))
            g_out_console = 1;
    }

    /* create window unless quiet mode or stdout is usable */
    if (!g_quiet && !g_out_ok) {
        sprintf(title, "Grid  \xe2\x80\x94  %s  ports %s", target, portspec);
        create_window(title);
        if (!g_hwnd_frame) {
            MessageBox(NULL, "CreateWindow failed.", "Grid", MB_OK | MB_ICONERROR);
            WSACleanup();
            return 1;
        }
        /* initial paint */
        UpdateWindow(g_hwnd_frame);
    }

    do_scan();

    /* if window is open, run message loop until user closes it */
    if (g_hwnd_frame) {
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    /* close any still-active sockets */
    for (i = 0; i < g_pool_size; i++)
        if (g_pool[i].active) closesocket(g_pool[i].s);

    free(g_hosts);
    WSACleanup();
    return 0;
}
