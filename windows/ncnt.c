/*
 * ncnt.c  --  AeldreC2  --  Netcat for Windows NT / 95
 *
 * "The TCP/IP Swiss Army knife" for vintage Windows.
 *
 * The original Netcat for Windows NT (nc111nt.zip) was written by
 * Weld Pond (Chris Wysopal) of L0pht Heavy Industries circa 1998.
 * This is an independent clean-room implementation sharing the same spirit
 * and command-line interface.  The original is archived at:
 *   https://github.com/googleask/nc111nt
 *   https://l0pht.com  (historical archive)
 *
 * Platform notes:
 *   - Windows NT 3.1 / 3.51 / 4.0 / 2000 / XP+: full support
 *   - Windows 95 / 98 / Me: supported; WinSock 1.1 on Win95 does NOT
 *     support MSG_WAITALL in recv() — this implementation uses a
 *     blocking loop instead, which works on all platforms.
 *   - WFW 3.11 without Win32s: cannot run Win32 console apps at all.
 *     Use ncwfw.exe (Win16 GUI netcat) on bare WFW.
 *   - WFW 3.11 with Win32s: in principle works but Win32s console
 *     support is limited — ncwfw.exe is more reliable there.
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 ncnt.c wsock32.lib
 *
 * Usage:
 *   ncnt -l -p <port>              Listen, relay to stdin/stdout
 *   ncnt <host> <port>             Connect, relay to stdin/stdout
 *   ncnt -l -p <port>  -e <cmd>   Listen, exec <cmd> on connect
 *   ncnt <host> <port> -e <cmd>   Connect, exec <cmd>
 *   ncnt -l -p <port>  -k         Keep listening after client disconnects
 *   -v                             Verbose (status messages to stderr)
 *   -w <ms>                        Connect/idle timeout in milliseconds
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 ncnt.c wsock32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define FD_SETSIZE 4
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

static int    g_listen   = 0;
static int    g_port     = 0;
static char   g_host[256] = "";
static char   g_exec[MAX_PATH] = "";
static int    g_verbose  = 0;
static int    g_keep     = 0;
static DWORD  g_timeout  = 0;       /* 0 = no timeout */

static HANDLE g_con_out  = INVALID_HANDLE_VALUE;
static HANDLE g_con_in   = INVALID_HANDLE_VALUE;

/* ------------------------------------------------------------------ */
/* Console I/O helpers                                                 */
/* ------------------------------------------------------------------ */

static void con_err(const char *msg)
{
    DWORD w;
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE)
        WriteFile(h, msg, (DWORD)strlen(msg), &w, NULL);
}

static void con_out_raw(const char *buf, int len)
{
    DWORD w;
    if (g_con_out != INVALID_HANDLE_VALUE && len > 0)
        WriteFile(g_con_out, buf, (DWORD)len, &w, NULL);
}

static void vlog(const char *msg)
{
    if (g_verbose) con_err(msg);
}

/* ------------------------------------------------------------------ */
/* Relay: bidirectional pipe between socket and stdin/stdout          */
/* ------------------------------------------------------------------ */

static void relay_stdio(SOCKET s)
{
    char buf[4096];
    int  n;

    for (;;) {
        fd_set rset;
        struct timeval tv, *ptv = NULL;
        DWORD  avail;

        FD_ZERO(&rset);
        FD_SET(s, &rset);
        if (g_timeout) { tv.tv_sec = (long)(g_timeout/1000); tv.tv_usec = (g_timeout%1000)*1000; ptv = &tv; }

        /* Check if stdin has data (non-blocking peek) */
        if (g_con_in != INVALID_HANDLE_VALUE &&
            PeekNamedPipe(g_con_in, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD rd;
            DWORD want = avail > (DWORD)sizeof(buf) ? (DWORD)sizeof(buf) : avail;
            if (ReadFile(g_con_in, buf, want, &rd, NULL) && rd > 0) {
                if (send(s, buf, (int)rd, 0) == SOCKET_ERROR) return;
            }
        }

        /* Check if socket has data */
        tv.tv_sec  = 0;
        tv.tv_usec = 10000;   /* 10ms poll */
        if (select(0, &rset, NULL, NULL, &tv) > 0 && FD_ISSET(s, &rset)) {
            n = recv(s, buf, sizeof(buf), 0);
            if (n <= 0) return;
            con_out_raw(buf, n);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Exec: spawn a process with stdin/stdout piped to the socket        */
/* ------------------------------------------------------------------ */

static void relay_exec(SOCKET s, const char *cmdline)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;
    HANDLE  hProcIn_R,  hProcIn_W;
    HANDLE  hProcOut_R, hProcOut_W;
    char    buf[4096];
    DWORD   rd, avail;

    memset(&sa, 0, sizeof(sa)); sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hProcIn_R,  &hProcIn_W,  &sa, 0)) return;
    if (!CreatePipe(&hProcOut_R, &hProcOut_W, &sa, 0)) { CloseHandle(hProcIn_R); CloseHandle(hProcIn_W); return; }

    /* Don't inherit the parent-side handles */
    SetHandleInformation(hProcIn_W,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hProcOut_R, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = hProcIn_R;
    si.hStdOutput  = hProcOut_W;
    si.hStdError   = hProcOut_W;

    memset(&pi, 0, sizeof(pi));
    {
        char cmd[MAX_PATH + 8];
        strncpy(cmd, cmdline, sizeof(cmd) - 1);
        if (!CreateProcess(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hProcIn_R); CloseHandle(hProcIn_W);
            CloseHandle(hProcOut_R); CloseHandle(hProcOut_W);
            if (g_verbose) con_err("ncnt: CreateProcess failed\r\n");
            return;
        }
    }

    CloseHandle(hProcIn_R);
    CloseHandle(hProcOut_W);
    CloseHandle(pi.hThread);

    /* Relay loop */
    for (;;) {
        /* Socket → process stdin */
        {
            fd_set rset; struct timeval tv;
            FD_ZERO(&rset); FD_SET(s, &rset);
            tv.tv_sec = 0; tv.tv_usec = 5000;
            if (select(0, &rset, NULL, NULL, &tv) > 0 && FD_ISSET(s, &rset)) {
                int n = recv(s, buf, sizeof(buf), 0);
                if (n <= 0) goto done;
                WriteFile(hProcIn_W, buf, (DWORD)n, &rd, NULL);
            }
        }

        /* Process stdout → socket */
        if (PeekNamedPipe(hProcOut_R, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD want = avail > (DWORD)sizeof(buf) ? (DWORD)sizeof(buf) : avail;
            if (ReadFile(hProcOut_R, buf, want, &rd, NULL) && rd > 0) {
                if (send(s, buf, (int)rd, 0) == SOCKET_ERROR) goto done;
            }
        }

        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
            /* Process exited; flush remaining output */
            while (PeekNamedPipe(hProcOut_R, NULL, 0, NULL, &avail, NULL) && avail > 0) {
                DWORD want = avail > (DWORD)sizeof(buf) ? (DWORD)sizeof(buf) : avail;
                if (!ReadFile(hProcOut_R, buf, want, &rd, NULL) || rd == 0) break;
                send(s, buf, (int)rd, 0);
            }
            break;
        }
    }

done:
    CloseHandle(pi.hProcess);
    CloseHandle(hProcIn_W);
    CloseHandle(hProcOut_R);
}

/* ------------------------------------------------------------------ */
/* Handle a connected socket                                           */
/* ------------------------------------------------------------------ */

static void handle_conn(SOCKET s, const char *peer)
{
    char msg[192];
    sprintf(msg, "ncnt: connected %s\r\n", peer);
    vlog(msg);

    if (g_exec[0])
        relay_exec(s, g_exec);
    else
        relay_stdio(s);

    vlog("ncnt: connection closed\r\n");
}

/* ------------------------------------------------------------------ */
/* Listen mode                                                         */
/* ------------------------------------------------------------------ */

static void do_listen(void)
{
    SOCKET               ls, cs;
    struct sockaddr_in   addr, peer;
    int                  plen;
    char                 msg[128];

    ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) { con_err("ncnt: socket() failed\r\n"); return; }

    {
        int reuse = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((unsigned short)g_port);

    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        con_err("ncnt: bind() failed\r\n"); closesocket(ls); return;
    }
    if (listen(ls, 1) != 0) {
        con_err("ncnt: listen() failed\r\n"); closesocket(ls); return;
    }

    sprintf(msg, "ncnt: listening on port %d\r\n", g_port);
    vlog(msg);

    do {
        plen = sizeof(peer);
        memset(&peer, 0, sizeof(peer));
        cs = accept(ls, (struct sockaddr *)&peer, &plen);
        if (cs == INVALID_SOCKET) break;
        {
            char peer_str[64];
            sprintf(peer_str, "%s:%d", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
            handle_conn(cs, peer_str);
        }
        closesocket(cs);
    } while (g_keep);

    closesocket(ls);
}

/* ------------------------------------------------------------------ */
/* Connect mode                                                        */
/* ------------------------------------------------------------------ */

static void do_connect(void)
{
    SOCKET             s;
    struct sockaddr_in addr;
    struct hostent    *he;
    char               msg[192];

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { con_err("ncnt: socket() failed\r\n"); return; }

    /* Resolve — skip DNS for IPs */
    {
        unsigned long ip = inet_addr(g_host);
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons((unsigned short)g_port);
        if (ip != INADDR_NONE) {
            addr.sin_addr.s_addr = ip;
        } else {
            he = gethostbyname(g_host);
            if (!he) { con_err("ncnt: cannot resolve host\r\n"); closesocket(s); return; }
            memcpy(&addr.sin_addr, he->h_addr, 4);
        }
    }

    sprintf(msg, "ncnt: connecting to %s:%d\r\n", g_host, g_port);
    vlog(msg);

    if (g_timeout) {
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
    }

    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    if (g_timeout) {
        fd_set ws; struct timeval tv;
        u_long nb = 0;
        FD_ZERO(&ws); FD_SET(s, &ws);
        tv.tv_sec  = (long)(g_timeout / 1000);
        tv.tv_usec = (g_timeout % 1000) * 1000;
        if (select(0, NULL, &ws, NULL, &tv) <= 0 || !FD_ISSET(s, &ws)) {
            con_err("ncnt: connect timed out\r\n"); closesocket(s); return;
        }
        ioctlsocket(s, FIONBIO, &nb);
    }

    handle_conn(s, g_host);
    closesocket(s);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    WSADATA wsa;
    int     i;

    g_con_out = GetStdHandle(STD_OUTPUT_HANDLE);
    g_con_in  = GetStdHandle(STD_INPUT_HANDLE);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            g_listen = 1;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            g_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            strncpy(g_exec, argv[++i], sizeof(g_exec) - 1);
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-k") == 0) {
            g_keep = 1;
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            g_timeout = (DWORD)atol(argv[++i]);
        } else if (argv[i][0] != '-') {
            if (!g_host[0])
                strncpy(g_host, argv[i], sizeof(g_host) - 1);
            else if (!g_port)
                g_port = atoi(argv[i]);
        }
    }

    if (g_listen && !g_port) {
        fprintf(stderr,
            "ncnt  --  Netcat for Windows NT\n"
            "Inspired by Weld Pond (Chris Wysopal), L0pht Heavy Industries, ~1998\n\n"
            "Usage:\n"
            "  ncnt -l -p <port> [-e <cmd>] [-k] [-v] [-w ms]\n"
            "  ncnt <host> <port>           [-e <cmd>] [-v] [-w ms]\n\n"
            "  -l          listen mode\n"
            "  -p <port>   port (required in listen mode)\n"
            "  -e <cmd>    exec command on connect (shell-back)\n"
            "  -k          keep listening after disconnect\n"
            "  -v          verbose status to stderr\n"
            "  -w <ms>     connect timeout (milliseconds)\n");
        return 1;
    }
    if (!g_listen && (!g_host[0] || !g_port)) {
        fprintf(stderr,
            "ncnt  --  Netcat for Windows NT\n"
            "Inspired by Weld Pond (Chris Wysopal), L0pht Heavy Industries, ~1998\n\n"
            "Usage:\n"
            "  ncnt -l -p <port> [-e <cmd>] [-k] [-v] [-w ms]\n"
            "  ncnt <host> <port>           [-e <cmd>] [-v] [-w ms]\n");
        return 1;
    }

    if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0) {
        con_err("ncnt: WSAStartup failed\r\n"); return 1;
    }

    if (g_listen)
        do_listen();
    else
        do_connect();

    WSACleanup();
    return 0;
}
