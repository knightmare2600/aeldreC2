/*
 * grid32.c  --  AeldreC2 Grid port scanner -- Win32 / Win95 / NT console
 *
 * TCP connect scanner for Win95 and NT 3.1+.  Console subsystem; run from
 * cmd.exe or command.com.  Deployable on target via tank 'put' for remote
 * pivoted scanning; the tank 'grid' command runs it and streams output back
 * to Joshua.
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 -fo=grid32.obj grid32.c
 *   wlink system nt file grid32.obj library wsock32.lib name grid32.exe
 *
 * Usage: grid32 <target> -p <ports> [options]
 */

#define WIN32_LEAN_AND_MEAN
#define FD_SETSIZE 256
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Port-scanner core (shared with grid.c)                              */
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
/* Console output                                                      */
/* ------------------------------------------------------------------ */

static HANDLE g_con_out = INVALID_HANDLE_VALUE;

static void con_write(const char *s)
{
    DWORD w;
    int   n = (int)strlen(s);
    if (g_con_out != INVALID_HANDLE_VALUE && n > 0)
        WriteFile(g_con_out, s, (DWORD)n, &w, NULL);
}

static void out_result(const char *host, unsigned short port,
                       const char *svc, const char *banner)
{
    char line[320];
    CONSOLE_SCREEN_BUFFER_INFO ci;
    BOOL  has_color = FALSE;
    WORD  old_attr  = 0;
    if (!g_quiet)
        con_write("\r                                                    \r");
    sprintf(line, "%s\t%u/tcp\topen\t%s\t%s\r\n",
            host, (unsigned)port, svc, banner);
    if (!g_quiet && g_con_out != INVALID_HANDLE_VALUE &&
        GetConsoleScreenBufferInfo(g_con_out, &ci)) {
        old_attr  = ci.wAttributes;
        has_color = TRUE;
        SetConsoleTextAttribute(g_con_out, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    }
    con_write(line);
    if (has_color) SetConsoleTextAttribute(g_con_out, old_attr);
    g_open_count++;
}

static void out_progress(void)
{
    if (g_quiet) return;
    {
        char buf[80];
        sprintf(buf, "  %d/%d  open: %d  \r", g_done, g_work_total, g_open_count);
        con_write(buf);
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
/* Scan tick                                                           */
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

static void do_scan(void)
{
    int last_done = -1;
    g_work_total = g_nhosts * g_nports;
    while ((g_work_idx < g_work_total || g_pool_active > 0) && !g_stop) {
        scan_tick();
        if (g_done != last_done) {
            out_progress();
            last_done = g_done;
        }
    }
    if (!g_quiet) con_write("\r\n");
}

/* ------------------------------------------------------------------ */
/* main()                                                              */
/* ------------------------------------------------------------------ */

static BOOL WINAPI ctrl_handler(DWORD type) { (void)type; g_stop = 1; return TRUE; }

int main(int argc, char **argv)
{
    WSADATA   wsa;
    const char *target_arg = NULL;
    const char *ports_arg  = NULL;
    int        i;

    g_con_out = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            ports_arg = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            g_timeout_ms = atoi(argv[++i]);
            if (g_timeout_ms < 50) g_timeout_ms = 50;
        } else if (strcmp(argv[i], "-b") == 0) {
            g_banner = 1;
        } else if (strcmp(argv[i], "-q") == 0) {
            g_quiet = 1;
        } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            g_pool_size = atoi(argv[++i]);
            if (g_pool_size < 1)        g_pool_size = 1;
            if (g_pool_size > MAX_POOL) g_pool_size = MAX_POOL;
        } else if (argv[i][0] != '-') {
            target_arg = argv[i];
        }
    }

    if (!target_arg || !ports_arg) {
        fprintf(stderr,
            "Usage: gridcli <target> -p <ports> [options]\r\n\r\n"
            "  target   x.x.x.x | x.x.x.x/24 | x.x.x.1-254 | hostname\r\n"
            "  -p       80 | 1-1024 | 22,80,443 | 1-100,443\r\n"
            "  -t ms    connect timeout ms (default 500)\r\n"
            "  -b       banner grab\r\n"
            "  -q       quiet / machine-readable\r\n"
            "  -T n     pool size (default 64, max 256)\r\n\r\n"
            "Output: HOST<TAB>PORT/tcp<TAB>open<TAB>SERVICE<TAB>BANNER\r\n");
        return 1;
    }

    if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed.\r\n");
        return 1;
    }

    find_and_load_services();

    if (!parse_ports(ports_arg)) {
        fprintf(stderr, "Bad port specification.\r\n");
        WSACleanup(); return 1;
    }
    if (!parse_target(target_arg)) {
        fprintf(stderr, "Cannot resolve target.\r\n");
        WSACleanup(); return 1;
    }

    do_scan();

    for (i = 0; i < MAX_POOL; i++)
        if (g_pool[i].active) closesocket(g_pool[i].s);
    free(g_hosts);
    WSACleanup();
    return 0;
}
