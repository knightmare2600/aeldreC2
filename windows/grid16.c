/*
 * grid16.c  --  AeldreC2 Grid Win16 port scanner (WFW 3.11)
 *
 * TCP connect scanner for Windows 3.1 / WFW 3.11.  Runs from the DOS Prompt
 * (COMMAND.COM), output goes to the DOS box window via inherited stdout.
 * Can also be deployed on a WFW target and driven by tank16 via the 'grid'
 * command, which captures the output and sends it back to Joshua.
 *
 * Usage:
 *   grid16.exe <target> -p <ports> [options]
 *
 *   target   x.x.x.x | x.x.x.x/24 | x.x.x.1-254 | hostname
 *   -p       80 | 1-1024 | 22,80,443 | 1-100,443,8080
 *   -t ms    connect timeout ms (default 1000)
 *   -b       banner grab
 *   -q       quiet / machine-readable (TAB-delimited, no progress)
 *   -T n     pool size (default 8, max 16 -- Win16 socket limit)
 *
 * Output (quiet mode): HOST<TAB>PORT/tcp<TAB>open<TAB>SERVICE<TAB>BANNER
 *
 * Requires WINSOCK.DLL (Trumpet Winsock or MS TCP/IP for WFW 3.11).
 *
 * Build:
 *   wcc -ml -bt=windows -zu -s -I/opt/watcom/h/win -fo=grid16.obj grid16.c
 *   wlink system windows name grid16.exe file grid16.obj library winsock.lib
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dos.h>    /* _dos_write, _lopen, _lread, _lclose */

/* Win16 windows.h does not define MAX_PATH */
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#include <conio.h>  /* kbhit, getch */
#include <io.h>     /* _lseek */

/* ----------------------------------------------------------------
 * Win16 Winsock 1.1 -- inlined declarations
 * ---------------------------------------------------------------- */
typedef unsigned int SOCKET;
#define INVALID_SOCKET  ((SOCKET)(~0))
#define SOCKET_ERROR    (-1)
#define AF_INET         2
#define SOCK_STREAM     1
#define IPPROTO_TCP     6
#define SOL_SOCKET      0xFFFF
#define SO_ERROR        0x1007
#define FIONBIO         0x8004667EL

typedef struct { unsigned char s_b1,s_b2,s_b3,s_b4; } W16_IN_ADDR;
typedef struct {
    short          sin_family;
    unsigned short sin_port;
    W16_IN_ADDR    sin_addr;
    char           sin_zero[8];
} W16_SOCKADDR_IN;
typedef struct {
    char  *h_name; char **h_aliases;
    short  h_addrtype, h_length; char **h_addr_list;
} W16_HOSTENT;
typedef struct { unsigned char opcode,pstrlen; unsigned short version,maxsockets,maxudp; char *vendor_info; } W16_WSADATA;

#define W16_FD_SETSIZE 32
typedef struct { unsigned int fd_count; SOCKET fd_array[W16_FD_SETSIZE]; } W16_FD_SET;
typedef struct { long tv_sec; long tv_usec; } W16_TIMEVAL;
#define W16_FD_ZERO(p)    ((p)->fd_count = 0)
#define W16_FD_SET_(p,s)  ((p)->fd_array[(p)->fd_count++] = (s))

typedef unsigned long  (*pfn_inet_addr)(const char *);
typedef unsigned long  (*pfn_htonl)(unsigned long);
typedef unsigned short (*pfn_htons)(unsigned short);
typedef unsigned long  (*pfn_ntohl)(unsigned long);
typedef unsigned short (*pfn_ntohs)(unsigned short);
typedef SOCKET         (*pfn_socket)(int,int,int);
typedef int            (*pfn_connect)(SOCKET,void*,int);
typedef int            (*pfn_closesocket)(SOCKET);
typedef int            (*pfn_recv)(SOCKET,char*,int,int);
typedef W16_HOSTENT*   (*pfn_gethostbyname)(const char*);
typedef char*          (*pfn_inet_ntoa)(W16_IN_ADDR);
typedef int            (*pfn_ioctlsocket)(SOCKET,long,unsigned long*);
typedef int            (*pfn_getsockopt)(SOCKET,int,int,char*,int*);
typedef int            (*pfn_select)(int,W16_FD_SET*,W16_FD_SET*,W16_FD_SET*,W16_TIMEVAL*);
typedef int            (*pfn_WSAStartup)(unsigned short,W16_WSADATA*);
typedef int            (*pfn_WSACleanup)(void);

static HINSTANCE        g_wsock      = NULL;
static pfn_inet_addr    w_inet_addr  = NULL;
static pfn_htonl        w_htonl      = NULL;
static pfn_htons        w_htons      = NULL;
static pfn_ntohl        w_ntohl      = NULL;
static pfn_socket       w_socket     = NULL;
static pfn_connect      w_connect    = NULL;
static pfn_closesocket  w_closesock  = NULL;
static pfn_recv         w_recv       = NULL;
static pfn_gethostbyname w_gethost   = NULL;
static pfn_inet_ntoa    w_inet_ntoa  = NULL;
static pfn_ioctlsocket  w_ioctl      = NULL;
static pfn_getsockopt   w_getsockopt = NULL;
static pfn_select       w_select     = NULL;
static pfn_WSAStartup   w_startup    = NULL;
static pfn_WSACleanup   w_cleanup    = NULL;

static int winsock_load(void)
{
    W16_WSADATA wsd;
    g_wsock = LoadLibrary("WINSOCK.DLL");
    if (!g_wsock || (unsigned)g_wsock < 32) { g_wsock = NULL; return 0; }
#define GF(v,n) v=(void*)GetProcAddress(g_wsock,n); if(!v) return 0;
    GF(w_inet_addr,  "inet_addr")
    GF(w_htonl,      "htonl")
    GF(w_htons,      "htons")
    GF(w_ntohl,      "ntohl")
    GF(w_socket,     "socket")
    GF(w_connect,    "connect")
    GF(w_closesock,  "closesocket")
    GF(w_recv,       "recv")
    GF(w_gethost,    "gethostbyname")
    GF(w_inet_ntoa,  "inet_ntoa")
    GF(w_ioctl,      "ioctlsocket")
    GF(w_getsockopt, "getsockopt")
    GF(w_select,     "select")
    GF(w_startup,    "WSAStartup")
    GF(w_cleanup,    "WSACleanup")
#undef GF
    return w_startup(0x0101, &wsd) == 0;
}

/* ----------------------------------------------------------------
 * Console I/O (inherited DOS handles from COMMAND.COM)
 * ---------------------------------------------------------------- */
static void con_out(const char *text)
{
    unsigned written; int len = strlen(text);
    if (len > 0) _dos_write(1, text, (unsigned)len, &written);
}

/* ----------------------------------------------------------------
 * Win16 cooperative yield
 * ---------------------------------------------------------------- */
static int g_stop = 0;

static void win16_yield(void)
{
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) g_stop = 1;
        DispatchMessage(&msg);
    }
}

/* ----------------------------------------------------------------
 * Service name table (loaded from SERVICES.DAT)
 * ---------------------------------------------------------------- */
#define SVC_HASH 256
typedef struct SvcEntry { unsigned short port; char name[20]; struct SvcEntry *next; } SvcEntry;
static SvcEntry *g_svc[SVC_HASH];

static void svc_insert(unsigned short port, const char *name)
{
    unsigned h = port & (SVC_HASH-1);
    SvcEntry *e;
    for (e = g_svc[h]; e; e = e->next) if (e->port == port) return;
    e = (SvcEntry*)malloc(sizeof(SvcEntry));
    if (!e) return;
    e->port = port;
    strncpy(e->name, name, sizeof(e->name)-1); e->name[sizeof(e->name)-1] = '\0';
    e->next = g_svc[h]; g_svc[h] = e;
}

static const char *svc_lookup(unsigned short port)
{
    unsigned h = port & (SVC_HASH-1);
    SvcEntry *e;
    for (e = g_svc[h]; e; e = e->next) if (e->port == port) return e->name;
    return "";
}

static void load_services(const char *path)
{
    HFILE hf; char line[256]; long fsz; int n;
    hf = _lopen(path, OF_READ);
    if (hf == HFILE_ERROR) return;
    fsz = _llseek(hf, 0, 2); _llseek(hf, 0, 0);
    while (fsz > 0) {
        char *p, name[48], proto[8];
        unsigned int port;
        for (n = 0; n < (int)sizeof(line)-1 && fsz > 0; n++) {
            int rd = _lread(hf, line+n, 1);
            if (rd <= 0) break;
            fsz--;
            if (line[n] == '\n') { n++; break; }
        }
        line[n] = '\0';
        p = line; while (*p==' '||*p=='\t') p++;
        if (*p=='#'||!*p) continue;
        if (sscanf(p, "%47s %u/%7s", name, &port, proto)==3)
            if (strcmp(proto,"tcp")==0 && port>=1)  /* port<=65535 always true for 16-bit uint */
                svc_insert((unsigned short)port, name);
    }
    _lclose(hf);
}

static void find_services(HINSTANCE hInst)
{
    char path[MAX_PATH]; int n;
    n = GetModuleFileName(hInst, path, MAX_PATH);
    if (n > 0) {
        char *sl = strrchr(path, '\\');
        if (sl) { strcpy(sl+1, "SERVICES.DAT"); load_services(path); }
    }
}

/* ----------------------------------------------------------------
 * Port and host lists
 * ---------------------------------------------------------------- */
#define MAX_PORTS16  1024
#define MAX_HOSTS16  512

static unsigned short g_ports[MAX_PORTS16];
static int            g_nports = 0;

static unsigned long  g_hosts[MAX_HOSTS16];
static int            g_nhosts = 0;

static void port_add(unsigned int p)
{
    if (p<1||g_nports>=MAX_PORTS16) return;  /* p>65535 always false for 16-bit uint */
    g_ports[g_nports++] = (unsigned short)p;
}

static int parse_ports(const char *spec)
{
    const char *p = spec;
    while (*p) {
        char *end; unsigned long lo, hi; unsigned int i;
        lo = strtoul(p,&end,10); if(end==p) return 0; p=end;
        hi = (*p=='-') ? (p++, strtoul(p,&end,10)) : lo; if(end==p&&hi!=lo) return 0; p=end;
        if(lo>hi||lo<1||hi>65535) return 0;
        for(i=(unsigned int)lo; i<=(unsigned int)hi; i++) port_add(i);
        if(*p==',') p++;
    }
    return g_nports>0;
}

static void host_add(unsigned long ip)
{
    if (g_nhosts < MAX_HOSTS16) g_hosts[g_nhosts++] = ip;
}

static int parse_target(const char *spec)
{
    char buf[128]; const char *sl; int a,b,c,lo,hi,i;
    unsigned long base;
    strncpy(buf, spec, 127); buf[127] = '\0';

    sl = strchr(buf, '/');
    if (sl) {
        int bits; char ipbuf[32]; unsigned long mask;
        strncpy(ipbuf, buf, (int)(sl-buf)); ipbuf[sl-buf] = '\0';
        bits = atoi(sl+1); if(bits<0||bits>32) return 0;
        base = w_ntohl(w_inet_addr(ipbuf));
        if (base == 0xFFFFFFFFUL) return 0;
        mask = bits ? (0xFFFFFFFFUL<<(32-bits)) : 0;
        base &= mask;
        for (i=1; i<(int)(1UL<<(32-bits))-1; i++) {
            if(g_nhosts>=MAX_HOSTS16) break;
            host_add(w_htonl(base+i));
        }
        return g_nhosts>0;
    }
    if (sscanf(buf, "%d.%d.%d.%d-%d", &a,&b,&c,&lo,&hi)==5) {
        for(i=lo;i<=hi;i++) {
            char tmp[24]; unsigned long ip;
            sprintf(tmp,"%d.%d.%d.%d",a,b,c,i);
            ip = w_inet_addr(tmp);
            if (ip != 0xFFFFFFFFUL) host_add(ip);
        }
        return g_nhosts>0;
    }
    base = w_inet_addr(buf);
    if (base != 0xFFFFFFFFUL) { host_add(base); return 1; }
    { W16_HOSTENT *he = w_gethost(buf); if(!he) return 0;
      memcpy(&base, he->h_addr_list[0], 4); host_add(base); return 1; }
}

/* ----------------------------------------------------------------
 * Scan pool
 * ---------------------------------------------------------------- */
#define MAX_POOL16  16
#define DEF_POOL16  8

typedef struct {
    SOCKET         s;
    unsigned long  host_ip;
    unsigned short port;
    unsigned long  deadline;
    int            active;
} Slot16;

static Slot16 g_pool[MAX_POOL16];
static int    g_pool_active = 0;
static int    g_pool_size   = DEF_POOL16;
static int    g_timeout_ms  = 1000;
static int    g_banner      = 0;
static int    g_quiet       = 0;
static long   g_work_idx    = 0;
static long   g_work_total  = 0;
static long   g_done        = 0;
static int    g_open_count  = 0;

#define BANNER_LEN16 64

static void grab_banner16(SOCKET s, char *out, int outlen)
{
    W16_FD_SET rs; W16_TIMEVAL tv; int n; char *p;
    out[0] = '\0';
    W16_FD_ZERO(&rs); W16_FD_SET_(&rs, s);
    tv.tv_sec = 0; tv.tv_usec = 300000L;
    if (w_select(1, &rs, NULL, NULL, &tv) <= 0) return;
    n = w_recv(s, out, outlen-1, 0);
    if (n <= 0) { out[0] = '\0'; return; }
    out[n] = '\0';
    for (p=out; *p; p++) {
        if (*p=='\r'||*p=='\n') { *p='\0'; break; }
        if ((unsigned char)*p<0x20||(unsigned char)*p>0x7e) *p='.';
    }
}

/* ANSI colour codes -- only emitted in interactive (non-quiet) mode.
 * ANSI.SYS is loaded by default on most WFW 3.11 systems; if absent
 * the codes appear as harmless printable chars in the DOS box. */
#define ANSI_GREEN  "\033[1;32m"
#define ANSI_RESET  "\033[0m"

static void out_result(unsigned long host_ip, unsigned short port,
                       const char *svc, const char *banner)
{
    W16_IN_ADDR ia; char line[256];
    ia.s_b1=(unsigned char)(host_ip>>24); ia.s_b2=(unsigned char)(host_ip>>16);
    ia.s_b3=(unsigned char)(host_ip>>8);  ia.s_b4=(unsigned char)(host_ip);
    if (!g_quiet) con_out("\r                                        \r");
    sprintf(line, "%s\t%u/tcp\topen\t%s\t%s\r\n",
            w_inet_ntoa(ia), (unsigned)port, svc, banner);
    if (!g_quiet) con_out(ANSI_GREEN);
    con_out(line);
    if (!g_quiet) con_out(ANSI_RESET);
    g_open_count++;
}

static void out_progress(void)
{
    if (!g_quiet) {
        char buf[64];
        sprintf(buf, "  %ld/%ld  open: %d  \r", g_done, g_work_total, g_open_count);
        con_out(buf);
    }
}

static void slot_close16(int i)
{
    if (!g_pool[i].active) return;
    w_closesock(g_pool[i].s);
    g_pool[i].active = 0; g_pool_active--; g_done++;
}

static void slot_open16(int i, unsigned long ip, unsigned short port)
{
    SOCKET s; unsigned long nb = 1;
    W16_SOCKADDR_IN sa;
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { g_done++; return; }
    w_ioctl(s, FIONBIO, &nb);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = w_htons(port);
    memcpy(&sa.sin_addr, &ip, 4);
    w_connect(s, (void*)&sa, sizeof(sa));
    g_pool[i].s        = s;
    g_pool[i].host_ip  = ip;
    g_pool[i].port     = port;
    g_pool[i].deadline = GetTickCount() + (unsigned long)g_timeout_ms;
    g_pool[i].active   = 1;
    g_pool_active++;
}

static void scan_tick16(void)
{
    W16_FD_SET wfds, efds; W16_TIMEVAL tv; int i; unsigned long now;

    for (i = 0; i < g_pool_size && g_work_idx < g_work_total; i++) {
        if (!g_pool[i].active) {
            int hi = (int)(g_work_idx / (long)g_nports);
            int pi = (int)(g_work_idx % (long)g_nports);
            slot_open16(i, g_hosts[hi], g_ports[pi]);
            g_work_idx++;
        }
    }
    if (g_pool_active == 0) return;

    W16_FD_ZERO(&wfds); W16_FD_ZERO(&efds);
    for (i = 0; i < g_pool_size; i++) {
        if (g_pool[i].active) {
            W16_FD_SET_(&wfds, g_pool[i].s);
            W16_FD_SET_(&efds, g_pool[i].s);
        }
    }
    tv.tv_sec = 0; tv.tv_usec = 10000L;
    w_select(1, NULL, &wfds, &efds, &tv);

    now = GetTickCount();
    for (i = 0; i < g_pool_size; i++) {
        unsigned int j; int hit_w=0, hit_e=0;
        if (!g_pool[i].active) continue;
        for (j=0;j<wfds.fd_count;j++) if(wfds.fd_array[j]==g_pool[i].s){hit_w=1;break;}
        for (j=0;j<efds.fd_count;j++) if(efds.fd_array[j]==g_pool[i].s){hit_e=1;break;}
        if (hit_w) {
            int err=0, elen=sizeof(err);
            w_getsockopt(g_pool[i].s, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
            if (err == 0) {
                char banner[BANNER_LEN16+1]; unsigned long hip;
                if (g_banner) grab_banner16(g_pool[i].s, banner, BANNER_LEN16);
                else banner[0] = '\0';
                /* host_ip is in network byte order; convert for display */
                hip = w_ntohl(g_pool[i].host_ip);
                out_result(hip, g_pool[i].port,
                           svc_lookup(g_pool[i].port), banner);
            }
            slot_close16(i);
        } else if (hit_e) {
            slot_close16(i);
        } else if ((long)(now - g_pool[i].deadline) >= 0) {
            slot_close16(i);
        }
    }
}

/* ----------------------------------------------------------------
 * WinMain
 * ---------------------------------------------------------------- */
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow)
{
    char *p = lpCmdLine;
    const char *target = NULL, *ports_spec = NULL;
    char target_buf[128];

    (void)hPrev; (void)nCmdShow;

    /* Parse args */
    while (*p) {
        while (*p==' ') p++;
        if (!*p) break;
        if (*p=='-') {
            char flag = *(p+1); p += 2;
            while (*p==' ') p++;
            if (flag=='p') { ports_spec=p; while(*p&&*p!=' ') p++; if(*p)*p++='\0'; }
            else if(flag=='t') { g_timeout_ms=atoi(p); while(*p&&*p!=' ') p++; if(*p)*p++='\0'; }
            else if(flag=='T') { g_pool_size=atoi(p); while(*p&&*p!=' ') p++; if(*p)*p++='\0'; }
            else if(flag=='b') { g_banner=1; }
            else if(flag=='q') { g_quiet=1; }
        } else {
            char *tok=p; while(*p&&*p!=' ') p++; if(*p)*p++='\0';
            strncpy(target_buf,tok,sizeof(target_buf)-1); target=target_buf;
        }
    }

    if (!target || !ports_spec) {
        con_out("Usage: grid16.exe <target> -p <ports> [options]\r\n"
                "  target   x.x.x.x | x.x.x.x/24 | x.x.x.1-254 | hostname\r\n"
                "  -p       80 | 1-1024 | 22,80,443\r\n"
                "  -t ms    timeout ms (default 1000)\r\n"
                "  -b       banner grab\r\n"
                "  -q       quiet / tab-delimited output\r\n"
                "  -T n     pool size (default 8, max 16)\r\n");
        return 1;
    }
    if (g_pool_size < 1) g_pool_size = 1;
    if (g_pool_size > MAX_POOL16) g_pool_size = MAX_POOL16;

    if (!winsock_load()) {
        con_out("[WINSOCK.DLL not found -- install Trumpet Winsock or MS TCP/IP for WFW]\r\n");
        return 1;
    }

    find_services(hInst);

    if (!parse_ports(ports_spec)) { con_out("Bad port specification.\r\n"); w_cleanup(); FreeLibrary(g_wsock); return 1; }
    if (!parse_target(target))    { con_out("Cannot resolve target.\r\n");  w_cleanup(); FreeLibrary(g_wsock); return 1; }

    g_work_total = (long)g_nhosts * (long)g_nports;
    {
        char info[80];
        sprintf(info, "Scanning %d host(s) x %d port(s)  pool=%d\r\n",
                g_nhosts, g_nports, g_pool_size);
        if (!g_quiet) con_out(info);
    }

    while ((g_work_idx < g_work_total || g_pool_active > 0) && !g_stop) {
        scan_tick16();
        out_progress();
        win16_yield();
        if (kbhit()) { int c=getch(); if(c==3||c==27){con_out("\r\n[Interrupted]\r\n");break;} }
    }
    if (!g_quiet) con_out("\r\n");

    { int i; for(i=0;i<MAX_POOL16;i++) if(g_pool[i].active) w_closesock(g_pool[i].s); }
    w_cleanup();
    FreeLibrary(g_wsock);
    return 0;
}
