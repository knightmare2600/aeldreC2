/*
 * svcany.c  --  AeldreC2  --  NT Service Manager
 *
 * Install, remove, start, stop, query, or list any executable as a
 * Windows NT service.  Works on NT 3.1 / 3.51 / 4.0 and later.
 * Also runs on Windows 95 Service Pack / OSR2 (which shipped SCM).
 * Win 3.11 / WFW / bare Win95 have no SCM — the tool detects this
 * and exits cleanly.
 *
 * Usage:
 *   svcany install <name> <displayname> <exepath> [auto|manual|disabled]
 *   svcany remove  <name>
 *   svcany start   <name> [arg1 arg2 ...]
 *   svcany stop    <name>
 *   svcany query   <name>
 *   svcany list
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 svcany.c advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void die(const char *msg, DWORD err)
{
    char errbuf[256] = "";
    if (err) {
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, err, 0, errbuf, sizeof(errbuf) - 1, NULL);
        /* strip trailing CRLF */
        { int l = (int)strlen(errbuf);
          while (l > 0 && (errbuf[l-1]=='\r'||errbuf[l-1]=='\n')) errbuf[--l]='\0'; }
    }
    if (err)
        fprintf(stderr, "svcany: %s (error %lu: %s)\n", msg, err, errbuf);
    else
        fprintf(stderr, "svcany: %s\n", msg);
    exit(1);
}

static SC_HANDLE open_scm(DWORD access)
{
    SC_HANDLE h = OpenSCManager(NULL, NULL, access);
    if (!h) die("cannot open Service Control Manager", GetLastError());
    return h;
}

static SC_HANDLE open_svc(SC_HANDLE scm, const char *name, DWORD access)
{
    SC_HANDLE h = OpenService(scm, name, access);
    if (!h) die("cannot open service", GetLastError());
    return h;
}

/* ------------------------------------------------------------------ */
/* install                                                             */
/* ------------------------------------------------------------------ */

static void cmd_install(int argc, char **argv)
{
    /* svcany install <name> <displayname> <path> [auto|manual|disabled] */
    SC_HANDLE  scm, svc;
    const char *name, *display, *path;
    DWORD      start_type = SERVICE_AUTO_START;

    if (argc < 4) { die("install: need <name> <displayname> <path> [start]", 0); }
    name    = argv[0];
    display = argv[1];
    path    = argv[2];
    if (argc >= 4) {
        if (_stricmp(argv[3], "manual") == 0)   start_type = SERVICE_DEMAND_START;
        if (_stricmp(argv[3], "disabled") == 0) start_type = SERVICE_DISABLED;
    }

    scm = open_scm(SC_MANAGER_CREATE_SERVICE);
    svc = CreateService(scm,
                        name, display,
                        SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS,
                        start_type,
                        SERVICE_ERROR_NORMAL,
                        path,
                        NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        DWORD e = GetLastError();
        CloseServiceHandle(scm);
        if (e == ERROR_SERVICE_EXISTS)
            die("service already exists", 0);
        die("CreateService failed", e);
    }
    printf("Service '%s' installed.\n  Display: %s\n  Path:    %s\n  Start:   %s\n",
           name, display, path,
           (start_type == SERVICE_AUTO_START)   ? "auto"     :
           (start_type == SERVICE_DEMAND_START) ? "manual"   : "disabled");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ------------------------------------------------------------------ */
/* remove                                                              */
/* ------------------------------------------------------------------ */

static void cmd_remove(const char *name)
{
    SC_HANDLE scm, svc;
    scm = open_scm(SC_MANAGER_CONNECT);
    svc = open_svc(scm, name, DELETE);
    if (!DeleteService(svc)) {
        DWORD e = GetLastError(); CloseServiceHandle(svc); CloseServiceHandle(scm);
        die("DeleteService failed", e);
    }
    printf("Service '%s' removed.\n", name);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ------------------------------------------------------------------ */
/* start                                                               */
/* ------------------------------------------------------------------ */

static void cmd_start(const char *name, int extra_argc, char **extra_argv)
{
    SC_HANDLE       scm, svc;
    SERVICE_STATUS  ss;
    DWORD           waited = 0;

    scm = open_scm(SC_MANAGER_CONNECT);
    svc = open_svc(scm, name, SERVICE_START | SERVICE_QUERY_STATUS);

    if (!StartService(svc, (DWORD)extra_argc, (const char **)extra_argv)) {
        DWORD e = GetLastError();
        CloseServiceHandle(svc); CloseServiceHandle(scm);
        if (e == ERROR_SERVICE_ALREADY_RUNNING) { printf("Service '%s' already running.\n", name); return; }
        die("StartService failed", e);
    }

    printf("Starting '%s'", name);
    fflush(stdout);
    while (QueryServiceStatus(svc, &ss) &&
           ss.dwCurrentState == SERVICE_START_PENDING &&
           waited < 30000) {
        Sleep(500); waited += 500; printf("."); fflush(stdout);
    }
    QueryServiceStatus(svc, &ss);
    printf("\n");
    if (ss.dwCurrentState == SERVICE_RUNNING)
        printf("Service '%s' started.\n", name);
    else
        printf("Service '%s' state: %lu (expected SERVICE_RUNNING=4)\n", name, ss.dwCurrentState);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ------------------------------------------------------------------ */
/* stop                                                                */
/* ------------------------------------------------------------------ */

static void cmd_stop(const char *name)
{
    SC_HANDLE      scm, svc;
    SERVICE_STATUS ss;
    DWORD          waited = 0;

    scm = open_scm(SC_MANAGER_CONNECT);
    svc = open_svc(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS);

    if (!ControlService(svc, SERVICE_CONTROL_STOP, &ss)) {
        DWORD e = GetLastError();
        CloseServiceHandle(svc); CloseServiceHandle(scm);
        if (e == ERROR_SERVICE_NOT_ACTIVE) { printf("Service '%s' not running.\n", name); return; }
        die("ControlService(STOP) failed", e);
    }

    printf("Stopping '%s'", name);
    fflush(stdout);
    while (QueryServiceStatus(svc, &ss) &&
           ss.dwCurrentState == SERVICE_STOP_PENDING &&
           waited < 30000) {
        Sleep(500); waited += 500; printf("."); fflush(stdout);
    }
    QueryServiceStatus(svc, &ss);
    printf("\n");
    if (ss.dwCurrentState == SERVICE_STOPPED)
        printf("Service '%s' stopped.\n", name);
    else
        printf("Service '%s' state: %lu\n", name, ss.dwCurrentState);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ------------------------------------------------------------------ */
/* query                                                               */
/* ------------------------------------------------------------------ */

static const char *state_str(DWORD s)
{
    switch (s) {
    case SERVICE_STOPPED:          return "STOPPED";
    case SERVICE_START_PENDING:    return "START_PENDING";
    case SERVICE_STOP_PENDING:     return "STOP_PENDING";
    case SERVICE_RUNNING:          return "RUNNING";
    case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:    return "PAUSE_PENDING";
    case SERVICE_PAUSED:           return "PAUSED";
    default:                       return "UNKNOWN";
    }
}

static const char *start_str(DWORD s)
{
    switch (s) {
    case SERVICE_BOOT_START:   return "boot";
    case SERVICE_SYSTEM_START: return "system";
    case SERVICE_AUTO_START:   return "auto";
    case SERVICE_DEMAND_START: return "manual";
    case SERVICE_DISABLED:     return "disabled";
    default:                   return "?";
    }
}

static void cmd_query(const char *name)
{
    SC_HANDLE          scm, svc;
    SERVICE_STATUS     ss;
    QUERY_SERVICE_CONFIG *qsc;
    DWORD              needed = 0;

    scm = open_scm(SC_MANAGER_CONNECT);
    svc = open_svc(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);

    QueryServiceStatus(svc, &ss);
    printf("Service:  %s\n", name);
    printf("State:    %s\n", state_str(ss.dwCurrentState));
    printf("PID:      %lu\n", ss.dwCurrentState == SERVICE_RUNNING ? ss.dwCheckPoint : 0);

    QueryServiceConfig(svc, NULL, 0, &needed);
    qsc = (QUERY_SERVICE_CONFIG *)malloc(needed);
    if (qsc && QueryServiceConfig(svc, qsc, needed, &needed)) {
        printf("Start:    %s\n", start_str(qsc->dwStartType));
        printf("Path:     %s\n", qsc->lpBinaryPathName ? qsc->lpBinaryPathName : "");
        printf("Display:  %s\n", qsc->lpDisplayName    ? qsc->lpDisplayName    : "");
    }
    if (qsc) free(qsc);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ------------------------------------------------------------------ */
/* list                                                                */
/* ------------------------------------------------------------------ */

static void cmd_list(void)
{
    SC_HANDLE           scm;
    ENUM_SERVICE_STATUS *ess = NULL;
    DWORD               needed = 0, returned = 0, resume = 0;
    BOOL                ok;

    scm = open_scm(SC_MANAGER_ENUMERATE_SERVICE);

    /* First call to get required buffer size */
    EnumServicesStatus(scm, SERVICE_WIN32, SERVICE_STATE_ALL,
                       NULL, 0, &needed, &returned, &resume);
    ess = (ENUM_SERVICE_STATUS *)malloc(needed + 4096);
    if (!ess) { CloseServiceHandle(scm); die("out of memory", 0); }

    resume = 0;
    ok = EnumServicesStatus(scm, SERVICE_WIN32, SERVICE_STATE_ALL,
                            ess, needed + 4096, &needed, &returned, &resume);
    if (ok || GetLastError() == ERROR_MORE_DATA) {
        DWORD i;
        printf("%-32s  %-12s  %s\n", "Name", "State", "Display");
        printf("%-32s  %-12s  %s\n", "----", "-----", "-------");
        for (i = 0; i < returned; i++) {
            printf("%-32s  %-12s  %s\n",
                   ess[i].lpServiceName,
                   state_str(ess[i].ServiceStatus.dwCurrentState),
                   ess[i].lpDisplayName);
        }
        printf("\n%lu service(s) listed.\n", returned);
    } else {
        die("EnumServicesStatus failed", GetLastError());
    }
    free(ess);
    CloseServiceHandle(scm);
}

/* ------------------------------------------------------------------ */
/* autorun: persistent startup without SCM                             */
/*                                                                     */
/* NT 3.1 / NT 4:  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion  */
/*                         \Run  (per-machine, runs as SYSTEM)         */
/* Windows 95/98:  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  */
/* WFW 3.11:       win.ini [windows] load= (via WriteProfileString)    */
/* Win 3.11:       same                                                 */
/*                                                                     */
/* Usage:                                                               */
/*   svcany autorun add    <name> <path>   Add startup entry           */
/*   svcany autorun remove <name>          Remove startup entry        */
/*   svcany autorun list                   List all startup entries    */
/* ------------------------------------------------------------------ */

static BOOL is_winnt(void)
{
    OSVERSIONINFO osv;
    memset(&osv, 0, sizeof(osv));
    osv.dwOSVersionInfoSize = sizeof(osv);
    GetVersionEx(&osv);
    return (osv.dwPlatformId == VER_PLATFORM_WIN32_NT);
}

static BOOL is_win32(void)
{
    OSVERSIONINFO osv;
    memset(&osv, 0, sizeof(osv));
    osv.dwOSVersionInfoSize = sizeof(osv);
    GetVersionEx(&osv);
    return (osv.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS);  /* Win95/98/Me */
}

static void cmd_autorun(int argc, char **argv)
{
    const char *sub;
    if (argc < 1) {
        printf("Usage:\n"
               "  svcany autorun add    <name> <path>\n"
               "  svcany autorun remove <name>\n"
               "  svcany autorun list\n\n"
               "Platform mapping:\n"
               "  NT 3.1+    HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Run\n"
               "  Win95/98   HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
               "  WFW/3.11   win.ini [windows] load= entry\n");
        return;
    }

    sub = argv[0];

    if (is_winnt() || is_win32()) {
        /* Registry-based autorun */
        HKEY  hkey;
        const char *regpath = is_winnt()
            ? "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Run"
            : "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        LONG  ret;

        if (_stricmp(sub, "list") == 0) {
            ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &hkey);
            if (ret != ERROR_SUCCESS) { fprintf(stderr, "svcany: cannot open Run key (%ld)\n", ret); return; }
            {
                DWORD idx = 0;
                char vname[256], vdata[MAX_PATH+4];
                DWORD vsz, dsz, vtype;
                printf("Autorun entries (%s):\n", regpath);
                for (;;) {
                    vsz = sizeof(vname); dsz = sizeof(vdata);
                    ret = RegEnumValue(hkey, idx++, vname, &vsz, NULL, &vtype, (BYTE*)vdata, &dsz);
                    if (ret != ERROR_SUCCESS) break;
                    printf("  %-32s  %s\n", vname, vdata);
                }
            }
            RegCloseKey(hkey);

        } else if (_stricmp(sub, "add") == 0) {
            if (argc < 3) { fprintf(stderr, "svcany autorun add: need <name> <path>\n"); return; }
            ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, NULL, 0,
                                 KEY_SET_VALUE, NULL, &hkey, NULL);
            if (ret != ERROR_SUCCESS) { fprintf(stderr, "svcany: cannot open Run key (%ld)\n", ret); return; }
            ret = RegSetValueEx(hkey, argv[1], 0, REG_SZ,
                                (BYTE*)argv[2], (DWORD)strlen(argv[2]) + 1);
            RegCloseKey(hkey);
            if (ret == ERROR_SUCCESS)
                printf("Autorun entry '%s' added: %s\n", argv[1], argv[2]);
            else
                fprintf(stderr, "svcany: RegSetValueEx failed (%ld)\n", ret);

        } else if (_stricmp(sub, "remove") == 0) {
            if (argc < 2) { fprintf(stderr, "svcany autorun remove: need <name>\n"); return; }
            ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_SET_VALUE, &hkey);
            if (ret != ERROR_SUCCESS) { fprintf(stderr, "svcany: cannot open Run key (%ld)\n", ret); return; }
            ret = RegDeleteValue(hkey, argv[1]);
            RegCloseKey(hkey);
            if (ret == ERROR_SUCCESS)
                printf("Autorun entry '%s' removed.\n", argv[1]);
            else
                fprintf(stderr, "svcany: RegDeleteValue failed (%ld)\n", ret);

        } else {
            fprintf(stderr, "svcany autorun: unknown sub-verb '%s'\n", sub);
        }

    } else {
        /* Win16 / WFW 3.11: use win.ini [windows] load= */

        if (_stricmp(sub, "list") == 0) {
            char load[2048] = "", run[2048] = "";
            GetProfileString("windows", "load", "", load, sizeof(load));
            GetProfileString("windows", "run",  "", run,  sizeof(run));
            printf("win.ini [windows]\n  load=%s\n  run=%s\n", load, run);

        } else if (_stricmp(sub, "add") == 0) {
            char existing[2048] = "", newval[2048+MAX_PATH];
            if (argc < 3) { fprintf(stderr, "svcany autorun add: need <name> <path>\n"); return; }
            GetProfileString("windows", "load", "", existing, sizeof(existing));
            if (existing[0])
                wsprintf(newval, "%s %s", existing, argv[2]);
            else
                lstrcpyn(newval, argv[2], sizeof(newval)-1);
            WriteProfileString("windows", "load", newval);
            printf("Added '%s' to win.ini [windows] load=\n", argv[2]);
            printf("Note: Changes take effect on next Windows startup.\n");

        } else if (_stricmp(sub, "remove") == 0) {
            /* Removing by name from the load= line: scan for the token */
            char existing[2048] = "", newval[2048] = "", *p, *tok;
            if (argc < 2) { fprintf(stderr, "svcany autorun remove: need <name>\n"); return; }
            GetProfileString("windows", "load", "", existing, sizeof(existing));
            p = existing;
            while (*p) {
                char *start = p;
                while (*p && *p != ' ') p++;
                if (*p) *p++ = '\0';
                /* Check if this token contains the name/path */
                if (_stricmp(start, argv[1]) != 0 &&
                    strstr(_strlwr(start), _strlwr((char*)argv[1])) == NULL) {
                    if (newval[0]) lstrcat(newval, " ");
                    lstrcat(newval, start);
                }
            }
            WriteProfileString("windows", "load", newval);
            printf("Updated win.ini [windows] load= (removed token matching '%s')\n", argv[1]);

        } else {
            fprintf(stderr, "svcany autorun: unknown sub-verb '%s'\n", sub);
        }
    }
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    /* Quick platform check: if OpenSCManager isn't available, we're
     * on Win16 / WFW / bare Win95 (no SCM). */
    {
        HMODULE ha = GetModuleHandle("advapi32.dll");
        if (!ha || !GetProcAddress(ha, "OpenSCManagerA")) {
            fprintf(stderr, "svcany: Service Control Manager not available on this platform.\n");
            fprintf(stderr, "        Requires Windows NT 3.1 or Windows 95 SR2+.\n");
            return 1;
        }
    }

    if (argc < 2) {
        fprintf(stderr,
            "svcany  --  AeldreC2 NT Service Manager\n\n"
            "Usage:\n"
            "  svcany install  <name> <displayname> <path> [auto|manual|disabled]\n"
            "  svcany remove   <name>\n"
            "  svcany start    <name> [args...]\n"
            "  svcany stop     <name>\n"
            "  svcany query    <name>\n"
            "  svcany list\n"
            "  svcany autorun  add <name> <path>   Startup entry (all platforms)\n"
            "  svcany autorun  remove <name>\n"
            "  svcany autorun  list\n\n"
            "Examples:\n"
            "  svcany install MyApp \"My Application\" C:\\App\\app.exe auto\n"
            "  svcany start  MyApp\n"
            "  svcany query  MyApp\n"
            "  svcany stop   MyApp\n"
            "  svcany remove MyApp\n");
        return 1;
    }

    /* autorun works on all platforms — check it before the SCM check */
    if (_stricmp(argv[1], "autorun") == 0) {
        cmd_autorun(argc - 2, argv + 2);
        return 0;
    }

    if (_stricmp(argv[1], "install") == 0) {
        if (argc < 5) { fprintf(stderr, "svcany install <name> <displayname> <path> [auto|manual|disabled]\n"); return 1; }
        cmd_install(argc - 2, argv + 2);
    } else if (_stricmp(argv[1], "remove") == 0) {
        if (argc < 3) { fprintf(stderr, "svcany remove <name>\n"); return 1; }
        cmd_remove(argv[2]);
    } else if (_stricmp(argv[1], "start") == 0) {
        if (argc < 3) { fprintf(stderr, "svcany start <name>\n"); return 1; }
        cmd_start(argv[2], argc - 3, argv + 3);
    } else if (_stricmp(argv[1], "stop") == 0) {
        if (argc < 3) { fprintf(stderr, "svcany stop <name>\n"); return 1; }
        cmd_stop(argv[2]);
    } else if (_stricmp(argv[1], "query") == 0) {
        if (argc < 3) { fprintf(stderr, "svcany query <name>\n"); return 1; }
        cmd_query(argv[2]);
    } else if (_stricmp(argv[1], "list") == 0) {
        cmd_list();
    } else {
        fprintf(stderr, "svcany: unknown verb '%s'\n", argv[1]);
        return 1;
    }

    return 0;
}
