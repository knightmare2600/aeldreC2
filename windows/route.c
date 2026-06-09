/*
 * route.c  --  AeldreC2 route
 *
 * Shows and manipulates the IP routing table.
 *
 * Platforms:
 *   NT 4 / Win95+  : iphlpapi.dll GetIpForwardTable; add/delete via
 *                    CreateIpForwardEntry / DeleteIpForwardEntry
 *   NT 3.x         : dynamic load attempted; falls back to exec the
 *                    system route.exe already present on NT 3.x,
 *                    or reads persistent routes from registry
 *   Win32s / WFW   : exec fallback; message if not available
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 route.c wsock32.lib advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * iphlpapi types (inline — no SDK header required)
 * ----------------------------------------------------------------------- */
typedef struct {
    DWORD dwForwardDest,dwForwardMask,dwForwardPolicy,dwForwardNextHop;
    DWORD dwForwardIfIndex,dwForwardType,dwForwardProto,dwForwardAge;
    DWORD dwForwardNextHopAS;
    DWORD dwForwardMetric1,dwForwardMetric2,dwForwardMetric3;
    DWORD dwForwardMetric4,dwForwardMetric5;
} RT_FWDROW;

typedef struct { DWORD dwNumEntries; RT_FWDROW table[1]; } RT_FWDTABLE;

typedef DWORD (WINAPI *pfGetIpForwardTable)(PVOID, PDWORD, BOOL);
typedef DWORD (WINAPI *pfCreateIpForwardEntry)(RT_FWDROW *);
typedef DWORD (WINAPI *pfDeleteIpForwardEntry)(RT_FWDROW *);

/* -----------------------------------------------------------------------
 * Helper: convert DWORD IP to dotted string (caller must NOT free result)
 * ----------------------------------------------------------------------- */
static const char *ip4(DWORD ip, char *tmp)
{
    struct in_addr a; a.s_addr = ip;
    lstrcpy(tmp, inet_ntoa(a));
    return tmp;
}

/* -----------------------------------------------------------------------
 * Exec the system route.exe as fallback on NT 3.x
 * ----------------------------------------------------------------------- */
static void exec_system_route(const char *args)
{
    char path[MAX_PATH + 64];
    char sysdir[MAX_PATH];
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;

    GetSystemDirectory(sysdir, MAX_PATH);
    wsprintf(path, "%s\\route.exe %s", sysdir, args ? args : "print");

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    if (CreateProcess(NULL, path, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    system("route print 2>nul");
}

/* -----------------------------------------------------------------------
 * Show persistent routes from registry (NT 3.x fallback for 'print')
 * ----------------------------------------------------------------------- */
static void show_persistent_registry(void)
{
    HKEY hk;
    DWORD idx;
    char  dname[256], ddata[512];
    DWORD namesz, datasz, vtype;
    int   found = 0;

    /* NT 3.x stores persistent routes under this key */
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\PersistentRoutes",
            0, KEY_READ, &hk) != ERROR_SUCCESS)
        return;

    printf("Persistent routes (registry):\n");
    printf("%-17s %-17s %-17s %s\n", "Destination", "Mask", "Gateway", "Metric");

    for (idx=0; ; idx++) {
        namesz = sizeof(dname); datasz = sizeof(ddata); vtype = 0;
        if (RegEnumValue(hk, idx, dname, &namesz, NULL, &vtype,
                         (BYTE*)ddata, &datasz) != ERROR_SUCCESS) break;
        if (vtype == REG_SZ) {
            /* key name encodes route; value is additional data */
            printf("  %s = %s\n", dname, ddata);
            found++;
        }
    }
    RegCloseKey(hk);
    if (!found) printf("  (none)\n");
}

/* -----------------------------------------------------------------------
 * Print the routing table
 * ----------------------------------------------------------------------- */
static void cmd_print(void)
{
    HMODULE hIP = LoadLibrary("iphlpapi.dll");
    pfGetIpForwardTable fGetRT = hIP
        ? (pfGetIpForwardTable)GetProcAddress(hIP, "GetIpForwardTable") : NULL;
    void  *buf;
    DWORD  sz;
    DWORD  i;
    char   d[16], m[16], g[16];

    if (!fGetRT) {
        if (hIP) FreeLibrary(hIP);
        /* NT 3.x: try system route, then registry */
        exec_system_route("print");
        show_persistent_registry();
        return;
    }

    sz = 16384; buf = malloc(sz);
    if (!buf) { FreeLibrary(hIP); return; }

    if (fGetRT(buf, &sz, TRUE) == 0) {
        RT_FWDTABLE *t = (RT_FWDTABLE *)buf;
        printf("%-17s %-17s %-17s %3s  %s\n",
               "Destination", "Mask", "Gateway", "If", "Metric");
        printf("%-17s %-17s %-17s %3s  %s\n",
               "-----------", "----", "-------", "--", "------");
        for (i = 0; i < t->dwNumEntries; i++) {
            lstrcpy(d, ip4(t->table[i].dwForwardDest,    d));
            lstrcpy(m, ip4(t->table[i].dwForwardMask,    m));
            lstrcpy(g, ip4(t->table[i].dwForwardNextHop, g));
            printf("%-17s %-17s %-17s %3lu  %lu\n",
                   d, m, g,
                   t->table[i].dwForwardIfIndex,
                   t->table[i].dwForwardMetric1);
        }
    }
    free(buf);
    FreeLibrary(hIP);
}

/* -----------------------------------------------------------------------
 * Add a route: route add <dest> mask <mask> <gateway> [metric <n>]
 * ----------------------------------------------------------------------- */
static void cmd_add(int argc, char **argv)
{
    HMODULE hIP;
    pfCreateIpForwardEntry fAdd;
    RT_FWDROW row;
    DWORD  rc;
    char  *dest, *mask, *gw;
    DWORD  metric = 1;
    int    i;

    if (argc < 4) {
        fprintf(stderr, "Usage: route add <dest> mask <mask> <gateway> [metric <n>]\n");
        return;
    }
    dest = argv[1]; mask = NULL; gw = NULL;
    for (i = 2; i < argc; i++) {
        if (lstrcmpi(argv[i], "mask")   == 0 && i+1 < argc) { mask   = argv[++i]; continue; }
        if (lstrcmpi(argv[i], "metric") == 0 && i+1 < argc) { metric = atoi(argv[++i]); continue; }
        if (!gw && argv[i][0]!='/' && argv[i][0]!='-') gw = argv[i];
    }
    if (!mask || !gw) { fprintf(stderr,"route add: missing mask or gateway\n"); return; }

    hIP  = LoadLibrary("iphlpapi.dll");
    fAdd = hIP ? (pfCreateIpForwardEntry)GetProcAddress(hIP, "CreateIpForwardEntry") : NULL;
    if (!fAdd) {
        if (hIP) FreeLibrary(hIP);
        exec_system_route(GetCommandLine() + 6);   /* relay whole command */
        return;
    }

    memset(&row, 0, sizeof(row));
    row.dwForwardDest    = inet_addr(dest);
    row.dwForwardMask    = inet_addr(mask);
    row.dwForwardNextHop = inet_addr(gw);
    row.dwForwardType    = 4;   /* indirect */
    row.dwForwardProto   = 3;   /* NETMGMT */
    row.dwForwardMetric1 = metric;
    row.dwForwardIfIndex = 0;   /* let the stack pick */

    rc = fAdd(&row);
    if (rc == 0)
        printf("Route added.\n");
    else
        fprintf(stderr, "CreateIpForwardEntry failed: %lu\n", rc);

    FreeLibrary(hIP);
}

/* -----------------------------------------------------------------------
 * Delete a route
 * ----------------------------------------------------------------------- */
static void cmd_delete(int argc, char **argv)
{
    HMODULE hIP;
    pfDeleteIpForwardEntry fDel;
    pfGetIpForwardTable    fGet;
    void  *buf;
    DWORD  sz, i, rc;
    char  *dest;

    if (argc < 2) { fprintf(stderr, "Usage: route delete <dest>\n"); return; }
    dest = argv[1];

    hIP  = LoadLibrary("iphlpapi.dll");
    fDel = hIP ? (pfDeleteIpForwardEntry) GetProcAddress(hIP,"DeleteIpForwardEntry") : NULL;
    fGet = hIP ? (pfGetIpForwardTable)    GetProcAddress(hIP,"GetIpForwardTable")    : NULL;
    if (!fDel || !fGet) {
        if (hIP) FreeLibrary(hIP);
        exec_system_route(GetCommandLine() + 7);
        return;
    }

    sz = 16384; buf = malloc(sz);
    if (!buf) { FreeLibrary(hIP); return; }
    if (fGet(buf, &sz, FALSE) != 0) { free(buf); FreeLibrary(hIP); return; }

    {
        RT_FWDTABLE *t = (RT_FWDTABLE *)buf;
        DWORD dest_ip = inet_addr(dest);
        int deleted = 0;
        for (i = 0; i < t->dwNumEntries; i++) {
            if (t->table[i].dwForwardDest == dest_ip) {
                rc = fDel(&t->table[i]);
                if (rc == 0) { printf("Route deleted.\n"); deleted++; }
                else fprintf(stderr, "DeleteIpForwardEntry: %lu\n", rc);
            }
        }
        if (!deleted) fprintf(stderr, "route delete: destination not found\n");
    }
    free(buf);
    FreeLibrary(hIP);
}

/* -----------------------------------------------------------------------
 * Entry point
 * ----------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    WSADATA wsd;
    WSAStartup(0x0101, &wsd);

    if (argc < 2 || lstrcmpi(argv[1], "print") == 0) {
        cmd_print();
    } else if (lstrcmpi(argv[1], "add")    == 0) {
        cmd_add(argc - 1, argv + 1);
    } else if (lstrcmpi(argv[1], "delete") == 0 ||
               lstrcmpi(argv[1], "del")    == 0) {
        cmd_delete(argc - 1, argv + 1);
    } else {
        printf("Usage: route [print | add | delete]\n"
               "  print                              Display routing table\n"
               "  add <dest> mask <m> <gw> [metric]  Add route\n"
               "  delete <dest>                      Remove route(s)\n");
    }

    WSACleanup();
    return 0;
}
