/*
 * arp.c  --  AeldreC2  --  ARP table viewer + ping sweep
 *
 * Shows the local ARP cache and optionally sends ICMP echo requests to
 * a subnet to populate it (ping sweep).
 *
 * NT 4.0+: uses GetIpNetTable from iphlpapi.dll (loaded dynamically so
 *           the binary still loads on NT 3.1/3.51 which lack iphlpapi).
 * NT 3.1/3.51: falls back to spawning "arp -a" and parsing its output,
 *               or just shows what the fallback provides.
 *
 * Usage:
 *   arp -a                   Show ARP cache
 *   arp -s <subnet/cidr>     Ping sweep, then show ARP
 *   arp -s <x.x.x.1-254>    Same with range notation
 *   arp -t <ms>              Ping timeout (default 200ms)
 *   arp -T <n>               Concurrent ping pool size (default 64)
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 arp.c wsock32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define FD_SETSIZE 256
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* iphlpapi dynamic load                                               */
/* ------------------------------------------------------------------ */

#define MIB_IPNET_TYPE_OTHER   1
#define MIB_IPNET_TYPE_INVALID 2
#define MIB_IPNET_TYPE_DYNAMIC 3
#define MIB_IPNET_TYPE_STATIC  4

#pragma pack(1)
typedef struct {
    DWORD dwIndex;
    DWORD dwPhysAddrLen;
    BYTE  bPhysAddr[8];
    DWORD dwAddr;
    DWORD dwType;
} MIB_IPNETROW;
#pragma pack()

typedef struct {
    DWORD       dwNumEntries;
    MIB_IPNETROW table[1];
} MIB_IPNETTABLE;

typedef DWORD (WINAPI *PFN_GetIpNetTable)(MIB_IPNETTABLE *, DWORD *, BOOL);

static PFN_GetIpNetTable pfn_GetIpNetTable = NULL;
static HMODULE           g_iphlp = NULL;

static int iphlp_load(void)
{
    g_iphlp = LoadLibrary("iphlpapi.dll");
    if (!g_iphlp) return 0;
    pfn_GetIpNetTable = (PFN_GetIpNetTable)GetProcAddress(g_iphlp, "GetIpNetTable");
    return pfn_GetIpNetTable != NULL;
}

/* ------------------------------------------------------------------ */
/* ARP table display via iphlpapi                                      */
/* ------------------------------------------------------------------ */

static void show_arp_iphlp(void)
{
    DWORD            sz = 0, ret;
    MIB_IPNETTABLE  *tbl;

    pfn_GetIpNetTable(NULL, &sz, FALSE);
    tbl = (MIB_IPNETTABLE *)malloc(sz + 4096);
    if (!tbl) { fprintf(stderr, "arp: out of memory\n"); return; }

    ret = pfn_GetIpNetTable(tbl, &sz, FALSE);
    if (ret != 0 && ret != 234 /*ERROR_MORE_DATA*/) {
        fprintf(stderr, "arp: GetIpNetTable failed (%lu)\n", ret);
        free(tbl); return;
    }

    printf("  %-18s  %-18s  %s\n", "IP Address", "MAC Address", "Type");
    printf("  %-18s  %-18s  %s\n", "----------", "-----------", "----");

    {
        DWORD i;
        for (i = 0; i < tbl->dwNumEntries; i++) {
            MIB_IPNETROW *r = &tbl->table[i];
            struct in_addr ia;
            char ipstr[20], macstr[24];
            const char *type_str;

            ia.s_addr = r->dwAddr;
            strncpy(ipstr, inet_ntoa(ia), sizeof(ipstr) - 1);

            if (r->dwPhysAddrLen >= 6)
                sprintf(macstr, "%02X-%02X-%02X-%02X-%02X-%02X",
                        r->bPhysAddr[0], r->bPhysAddr[1], r->bPhysAddr[2],
                        r->bPhysAddr[3], r->bPhysAddr[4], r->bPhysAddr[5]);
            else
                strcpy(macstr, "??-??-??-??-??-??");

            switch (r->dwType) {
            case MIB_IPNET_TYPE_DYNAMIC: type_str = "dynamic"; break;
            case MIB_IPNET_TYPE_STATIC:  type_str = "static";  break;
            case MIB_IPNET_TYPE_INVALID: type_str = "invalid"; break;
            default:                     type_str = "other";   break;
            }

            printf("  %-18s  %-18s  %s\n", ipstr, macstr, type_str);
        }
        printf("\n%lu entries.\n", tbl->dwNumEntries);
    }
    free(tbl);
}

/* ------------------------------------------------------------------ */
/* ARP display fallback: parse "arp -a" output (NT 3.1/3.51)          */
/* ------------------------------------------------------------------ */

static void show_arp_fallback(void)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;
    HANDLE hRead, hWrite;
    char   buf[4096];
    DWORD  nread;

    memset(&sa, 0, sizeof(sa)); sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        fprintf(stderr, "arp: cannot create pipe\n"); return;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;
    si.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcess(NULL, "arp -a", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        fprintf(stderr, "arp: cannot spawn arp.exe\n"); return;
    }
    CloseHandle(hWrite);
    CloseHandle(pi.hThread);

    while (ReadFile(hRead, buf, sizeof(buf) - 1, &nread, NULL) && nread > 0) {
        buf[nread] = '\0';
        printf("%s", buf);
    }
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(hRead);
}

/* ------------------------------------------------------------------ */
/* ICMP ping sweep                                                     */
/* ------------------------------------------------------------------ */

#define ICMP_ECHO         8
#define ICMP_ECHO_REPLY   0

#pragma pack(1)
typedef struct { BYTE type; BYTE code; WORD cksum; WORD id; WORD seq; } IcmpHdr;
typedef struct { BYTE vhl; BYTE tos; WORD len; WORD id; WORD off; BYTE ttl; BYTE proto; WORD cksum; DWORD src; DWORD dst; } IpHdr;
#pragma pack()

static WORD ip_checksum(const void *buf, int len)
{
    const WORD *p = (const WORD *)buf;
    DWORD       sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(BYTE *)p;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (WORD)(~sum);
}

typedef struct { DWORD ip; int done; } PingSlot;

#define MAX_PING_POOL 64

static void ping_sweep(unsigned long *hosts, int nhosts, DWORD timeout_ms)
{
    SOCKET raw;
    PingSlot pool[MAX_PING_POOL];
    int pool_sz = MAX_PING_POOL;
    int idx = 0, active = 0;
    WORD my_id = (WORD)GetCurrentProcessId();

    raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw == INVALID_SOCKET) {
        fprintf(stderr, "arp: raw socket failed — need admin rights for ping sweep\n");
        fprintf(stderr, "     (NT 3.1/3.51: raw sockets require admin; NT 4+: same)\n");
        return;
    }

    printf("Pinging %d host(s)...\r", nhosts); fflush(stdout);

    memset(pool, 0, sizeof(pool));
    {   u_long nb = 1; ioctlsocket(raw, FIONBIO, &nb); }

    while (idx < nhosts || active > 0) {
        int i;
        /* Fill pool */
        for (i = 0; i < pool_sz && idx < nhosts; i++) {
            if (!pool[i].done && pool[i].ip == 0) {
                IcmpHdr pkt;
                struct sockaddr_in dst;
                pkt.type  = ICMP_ECHO; pkt.code = 0;
                pkt.id    = my_id; pkt.seq = (WORD)idx;
                pkt.cksum = 0; pkt.cksum = ip_checksum(&pkt, sizeof(pkt));
                memset(&dst, 0, sizeof(dst));
                dst.sin_family = AF_INET;
                dst.sin_addr.s_addr = hosts[idx];
                sendto(raw, (char *)&pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst));
                pool[i].ip   = hosts[idx];
                pool[i].done = 0;
                active++;
                idx++;
            }
        }

        /* Receive */
        {
            fd_set rs; struct timeval tv;
            FD_ZERO(&rs); FD_SET(raw, &rs);
            tv.tv_sec = 0; tv.tv_usec = (long)(timeout_ms * 1000);
            if (select(0, &rs, NULL, NULL, &tv) > 0) {
                char recvbuf[1024];
                struct sockaddr_in src;
                int srclen = sizeof(src);
                int n = recvfrom(raw, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&src, &srclen);
                if (n >= (int)(sizeof(IpHdr) + sizeof(IcmpHdr))) {
                    IcmpHdr *ih = (IcmpHdr *)(recvbuf + sizeof(IpHdr));
                    if (ih->type == ICMP_ECHO_REPLY && ih->id == my_id) {
                        /* Found a live host — mark pool slot done */
                        for (i = 0; i < pool_sz; i++) {
                            if (pool[i].ip == src.sin_addr.s_addr && !pool[i].done) {
                                pool[i].done = 1; active--; break;
                            }
                        }
                    }
                }
            } else {
                /* Timeout: clear all active slots */
                for (i = 0; i < pool_sz; i++) {
                    if (pool[i].ip && !pool[i].done) {
                        pool[i].ip = 0; pool[i].done = 0; active--;
                    }
                }
            }
        }
    }

    closesocket(raw);
    printf("Sweep complete.  ARP cache updated.\n\n");
}

/* ------------------------------------------------------------------ */
/* Host list from CIDR / range                                         */
/* ------------------------------------------------------------------ */

static unsigned long *g_hosts = NULL;
static int            g_nhosts = 0;

static void host_add(unsigned long ip) {
    g_hosts = (unsigned long *)realloc(g_hosts, (g_nhosts + 1) * sizeof(unsigned long));
    if (g_hosts) g_hosts[g_nhosts++] = ip;
}

static void parse_target(const char *spec)
{
    char buf[128];
    strncpy(buf, spec, 127); buf[127] = '\0';

    /* CIDR */
    if (strchr(buf, '/')) {
        char ipbuf[64]; int bits; unsigned long base, mask;
        const char *sl = strchr(buf, '/');
        strncpy(ipbuf, buf, (int)(sl - buf)); ipbuf[sl - buf] = '\0';
        bits = atoi(sl + 1);
        if (bits < 1 || bits > 30) return;
        base = ntohl(inet_addr(ipbuf));
        mask = 0xFFFFFFFFUL << (32 - bits);
        base &= mask;
        { int i; for (i = 1; i < (int)(1UL << (32 - bits)) - 1; i++) host_add(htonl(base + i)); }
        return;
    }

    /* x.x.x.lo-hi */
    {
        int a, b, c, lo, hi;
        if (sscanf(buf, "%d.%d.%d.%d-%d", &a, &b, &c, &lo, &hi) == 5) {
            int i;
            for (i = lo; i <= hi; i++) {
                char tmp[32]; sprintf(tmp, "%d.%d.%d.%d", a, b, c, i);
                host_add(inet_addr(tmp));
            }
            return;
        }
    }

    /* Single IP */
    { unsigned long ip = inet_addr(buf); if (ip != INADDR_NONE) { host_add(ip); return; } }
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    WSADATA wsa;
    int     do_arp = 0, do_sweep = 0;
    char    sweep_spec[256] = "";
    DWORD   timeout_ms = 200;
    int     i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            do_arp = 1;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            do_sweep = 1;
            strncpy(sweep_spec, argv[++i], sizeof(sweep_spec) - 1);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            timeout_ms = (DWORD)atol(argv[++i]);
        } else if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("arp  --  AeldreC2 ARP viewer + ping sweep\n\n"
                   "Usage:\n"
                   "  arp -a                   Show ARP cache\n"
                   "  arp -s <subnet/cidr>     Ping sweep + show ARP\n"
                   "  arp -s <x.x.x.1-254>    Range notation\n"
                   "  arp -t <ms>              Ping timeout (default 200)\n");
            return 0;
        } else if (argv[i][0] != '-') {
            /* bare argument: treat as subnet for sweep */
            do_sweep = 1;
            strncpy(sweep_spec, argv[i], sizeof(sweep_spec) - 1);
        }
    }

    if (!do_arp && !do_sweep) { do_arp = 1; }

    WSAStartup(MAKEWORD(1, 1), &wsa);

    if (do_sweep && sweep_spec[0]) {
        parse_target(sweep_spec);
        if (g_nhosts > 0) {
            printf("Sweeping %s (%d hosts)...\n", sweep_spec, g_nhosts);
            ping_sweep(g_hosts, g_nhosts, timeout_ms);
        }
        if (g_hosts) { free(g_hosts); g_hosts = NULL; g_nhosts = 0; }
    }

    /* Always show ARP after sweep */
    if (do_arp || do_sweep) {
        if (iphlp_load())
            show_arp_iphlp();
        else
            show_arp_fallback();
        if (g_iphlp) FreeLibrary(g_iphlp);
    }

    WSACleanup();
    return 0;
}
