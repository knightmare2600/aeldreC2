/*
 * netstatN.c  --  AeldreC2 netstat for Windows NT 3.1+
 *
 * Shows active TCP/UDP connections and listening ports.
 *
 * Platforms:
 *   NT 4 / Win95+  : iphlpapi.dll GetTcpTable / GetUdpTable
 *   NT 3.x         : dynamic load attempted; falls back to exec
 *                    the system netstat.exe already present on NT 3.x
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox netstatN.c wsock32.lib
 *   (NT-only console binary; NT stub applied by Makefile)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * iphlpapi types (defined inline — no SDK header required)
 * ----------------------------------------------------------------------- */
typedef struct { DWORD dwState,dwLocalAddr,dwLocalPort,dwRemoteAddr,dwRemotePort; } NS_TCPROW;
typedef struct { DWORD dwNumEntries; NS_TCPROW  table[1]; } NS_TCPTABLE;
typedef DWORD (WINAPI *pfGetTcpTable)(PVOID, PDWORD, BOOL);

typedef struct { DWORD dwLocalAddr, dwLocalPort; } NS_UDPROW;
typedef struct { DWORD dwNumEntries; NS_UDPROW  table[1]; } NS_UDPTABLE;
typedef DWORD (WINAPI *pfGetUdpTable)(PVOID, PDWORD, BOOL);

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
    struct in_addr a;
    a.s_addr = ip;
    sprintf(out, "%s:%u", inet_ntoa(a), ntohs((WORD)port));
}

/* -----------------------------------------------------------------------
 * Exec the system netstat.exe as fallback on NT 3.x
 * ----------------------------------------------------------------------- */
static void exec_system_netstat(void)
{
    char path[MAX_PATH + 16];
    char sysdir[MAX_PATH];
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;

    GetSystemDirectory(sysdir, MAX_PATH);
    wsprintf(path, "%s\\netstat.exe -an", sysdir);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    if (CreateProcess(NULL, path, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    system("netstat -an 2>nul");
}

/* -----------------------------------------------------------------------
 * Main display via iphlpapi
 * ----------------------------------------------------------------------- */
static void show_connections(int show_all)
{
    HMODULE hIP = LoadLibrary("iphlpapi.dll");
    pfGetTcpTable fTCP = hIP ? (pfGetTcpTable)GetProcAddress(hIP, "GetTcpTable") : NULL;
    pfGetUdpTable fUDP = hIP ? (pfGetUdpTable)GetProcAddress(hIP, "GetUdpTable") : NULL;
    void  *buf;
    DWORD  sz;
    DWORD  i;

    if (!fTCP || !fUDP) {
        if (hIP) FreeLibrary(hIP);
        exec_system_netstat();
        return;
    }

    printf("Proto  Local Address          Foreign Address        State\n");
    printf("------ ---------------------- ---------------------- -----------\n");

    sz = 8192; buf = malloc(sz);
    if (buf && fTCP(buf, &sz, TRUE) == 0) {
        NS_TCPTABLE *t = (NS_TCPTABLE *)buf;
        for (i = 0; i < t->dwNumEntries; i++) {
            char la[28], ra[28];
            DWORD state = t->table[i].dwState;
            if (!show_all && state != 5 /* ESTABLISHED */ && state != 2 /* LISTEN */)
                continue;
            fmt_ep(la, t->table[i].dwLocalAddr,  t->table[i].dwLocalPort);
            fmt_ep(ra, t->table[i].dwRemoteAddr, t->table[i].dwRemotePort);
            printf("TCP    %-22s %-22s %s\n", la, ra, tcp_state(state));
        }
    }
    free(buf);

    if (show_all) {
        sz = 8192; buf = malloc(sz);
        if (buf && fUDP(buf, &sz, TRUE) == 0) {
            NS_UDPTABLE *t = (NS_UDPTABLE *)buf;
            for (i = 0; i < t->dwNumEntries; i++) {
                char la[28];
                struct in_addr a; a.s_addr = t->table[i].dwLocalAddr;
                sprintf(la, "%s:%u", inet_ntoa(a), ntohs((WORD)t->table[i].dwLocalPort));
                printf("UDP    %-22s *:*\n", la);
            }
        }
        free(buf);
    }

    FreeLibrary(hIP);
}

/* -----------------------------------------------------------------------
 * Entry point
 * ----------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    WSADATA wsd;
    int show_all = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (argv[i][0]=='-'||argv[i][0]=='/') {
            if (argv[i][1]=='a'||argv[i][1]=='A') show_all = 1;
            if (argv[i][1]=='?'||argv[i][1]=='h') {
                printf("Usage: netstatN [-a]\n"
                       "  -a  Show all connections and listening ports (incl. UDP)\n");
                return 0;
            }
        }
    }

    WSAStartup(0x0101, &wsd);
    show_connections(show_all);
    WSACleanup();
    return 0;
}
