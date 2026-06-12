/*
 * nc16.c  --  AeldreC2 Win16 Netcat (WFW 3.11)
 *
 * Pivot / relay tool deployed on a WFW 3.11 target.  Connects out to a
 * host or listens on a port, then relays raw bytes between the TCP socket
 * and the DOS Prompt console (stdout/stdin inherited from COMMAND.COM).
 *
 * Typical use: tank16 puts nc16.exe on a WFW host that sits inside a LAN
 * not otherwise reachable from the operator.  The operator then uses the
 * tank shell to run nc16.exe to reach internal services.
 *
 * Usage:
 *   nc16.exe <host> <port>     connect out to host:port
 *   nc16.exe -l <port>         listen on port, accept one connection
 *
 * Relay is raw (no line buffering): each keystroke is sent immediately.
 * Received bytes are written to stdout as-is.
 * Ctrl+C or Ctrl+Z closes the connection and exits.
 *
 * Requires WINSOCK.DLL (Trumpet Winsock or MS TCP/IP for WFW 3.11).
 *
 * Build:
 *   wcc -ml -bt=windows -zu -s -I/opt/watcom/h/win -fo=nc16.obj nc16.c
 *   wlink system windows name nc16.exe file nc16.obj library winsock.lib
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dos.h>    /* _dos_write */
#include <conio.h>  /* kbhit, getch */

/* ----------------------------------------------------------------
 * Win16 Winsock 1.1 -- inlined (same pattern as tank16.c / lman16.c)
 * ---------------------------------------------------------------- */
typedef unsigned int SOCKET;
#define INVALID_SOCKET  ((SOCKET)(~0))
#define SOCKET_ERROR    (-1)
#define AF_INET         2
#define SOCK_STREAM     1
#define IPPROTO_TCP     6

typedef struct { unsigned char s_b1, s_b2, s_b3, s_b4; } W16_IN_ADDR;

typedef struct {
    short          sin_family;
    unsigned short sin_port;
    W16_IN_ADDR    sin_addr;
    char           sin_zero[8];
} W16_SOCKADDR_IN;

typedef struct {
    char  *h_name;
    char **h_aliases;
    short  h_addrtype;
    short  h_length;
    char **h_addr_list;
} W16_HOSTENT;

typedef struct {
    unsigned char  opcode, pstrlen;
    unsigned short version, maxsockets, maxudp;
    char          *vendor_info;
} W16_WSADATA;

#define W16_FD_SETSIZE 32
typedef struct { unsigned int fd_count; SOCKET fd_array[W16_FD_SETSIZE]; } W16_FD_SET;
typedef struct { long tv_sec; long tv_usec; } W16_TIMEVAL;
#define W16_FD_ZERO(p)    ((p)->fd_count = 0)
#define W16_FD_SET_(p, s) ((p)->fd_array[(p)->fd_count++] = (s))

typedef unsigned long  (*pfn_inet_addr)(const char *);
typedef unsigned short (*pfn_htons)(unsigned short);
typedef SOCKET         (*pfn_socket)(int, int, int);
typedef int            (*pfn_connect)(SOCKET, void *, int);
typedef int            (*pfn_bind)(SOCKET, void *, int);
typedef int            (*pfn_listen)(SOCKET, int);
typedef SOCKET         (*pfn_accept)(SOCKET, void *, int *);
typedef int            (*pfn_send)(SOCKET, const char *, int, int);
typedef int            (*pfn_recv)(SOCKET, char *, int, int);
typedef int            (*pfn_closesocket)(SOCKET);
typedef W16_HOSTENT *  (*pfn_gethostbyname)(const char *);
typedef char *         (*pfn_inet_ntoa)(W16_IN_ADDR);
typedef int            (*pfn_WSAStartup)(unsigned short, W16_WSADATA *);
typedef int            (*pfn_WSACleanup)(void);
typedef int            (*pfn_select)(int, W16_FD_SET *, W16_FD_SET *,
                                     W16_FD_SET *, W16_TIMEVAL *);

/* ----------------------------------------------------------------
 * Winsock function pointers
 * ---------------------------------------------------------------- */
static HINSTANCE        g_wsock     = NULL;
static pfn_inet_addr    w_inet_addr = NULL;
static pfn_htons        w_htons     = NULL;
static pfn_socket       w_socket    = NULL;
static pfn_connect      w_connect   = NULL;
static pfn_bind         w_bind      = NULL;
static pfn_listen       w_listen    = NULL;
static pfn_accept       w_accept    = NULL;
static pfn_send         w_send      = NULL;
static pfn_recv         w_recv      = NULL;
static pfn_closesocket  w_closesock = NULL;
static pfn_gethostbyname w_gethost  = NULL;
static pfn_inet_ntoa    w_inet_ntoa = NULL;  /* optional */
static pfn_WSAStartup   w_startup   = NULL;
static pfn_WSACleanup   w_cleanup   = NULL;
static pfn_select       w_select    = NULL;

static int winsock_load(void)
{
    W16_WSADATA wsd;
    g_wsock = LoadLibrary("WINSOCK.DLL");
    if (!g_wsock || (unsigned)g_wsock < 32) { g_wsock = NULL; return 0; }
#define GF(v, n) v = (void *)GetProcAddress(g_wsock, n); if (!v) return 0;
    GF(w_inet_addr, "inet_addr")
    GF(w_htons,     "htons")
    GF(w_socket,    "socket")
    GF(w_connect,   "connect")
    GF(w_bind,      "bind")
    GF(w_listen,    "listen")
    GF(w_accept,    "accept")
    GF(w_send,      "send")
    GF(w_recv,      "recv")
    GF(w_closesock, "closesocket")
    GF(w_gethost,   "gethostbyname")
    GF(w_startup,   "WSAStartup")
    GF(w_cleanup,   "WSACleanup")
    GF(w_select,    "select")
#undef GF
    /* inet_ntoa is optional — used only to show listen-accept address */
    w_inet_ntoa = (pfn_inet_ntoa)GetProcAddress(g_wsock, "inet_ntoa");
    return w_startup(0x0101, &wsd) == 0;
}

/* ----------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------- */
static SOCKET g_sock = INVALID_SOCKET;
static int    g_run  = 1;

/* ----------------------------------------------------------------
 * Console I/O (inherited DOS file handles from COMMAND.COM)
 * ---------------------------------------------------------------- */
static void con_out(const char *text)
{
    unsigned written;
    int len = strlen(text);
    if (len > 0) _dos_write(1, text, (unsigned)len, &written);
}

/* ----------------------------------------------------------------
 * Win16 cooperative yield
 * ---------------------------------------------------------------- */
static void win16_yield(void)
{
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) g_run = 0;
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

static void win16_sleep_ms(unsigned long ms)
{
    unsigned long t0 = GetTickCount();
    while (GetTickCount() - t0 < ms)
        win16_yield();
}

/* ----------------------------------------------------------------
 * Resolve host to IP, return 0xFFFFFFFF on failure
 * ---------------------------------------------------------------- */
static unsigned long resolve(const char *host)
{
    unsigned long ip = w_inet_addr(host);
    if (ip == 0xFFFFFFFFUL) {
        W16_HOSTENT *he;
        char msg[128];
        sprintf(msg, "[Resolving %s...]\r\n", host);
        con_out(msg);
        win16_yield();
        he = w_gethost(host);
        if (!he) return 0xFFFFFFFFUL;
        memcpy(&ip, he->h_addr_list[0], 4);
    }
    return ip;
}

/* ----------------------------------------------------------------
 * Connect-out mode: connect to host:port
 * ---------------------------------------------------------------- */
static SOCKET do_connect(const char *host, int port)
{
    W16_SOCKADDR_IN addr;
    unsigned long   ip;
    char            msg[128];
    SOCKET          s;

    ip = resolve(host);
    if (ip == 0xFFFFFFFFUL) { con_out("[DNS failed]\r\n"); return INVALID_SOCKET; }

    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { con_out("[socket() failed]\r\n"); return INVALID_SOCKET; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = w_htons((unsigned short)port);
    memcpy(&addr.sin_addr, &ip, 4);

    sprintf(msg, "[Connecting to %s:%d...]\r\n", host, port);
    con_out(msg);
    win16_yield();

    if (w_connect(s, (void *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        con_out("[connect() failed]\r\n");
        w_closesock(s); return INVALID_SOCKET;
    }
    con_out("[Connected]\r\n");
    return s;
}

/* ----------------------------------------------------------------
 * Listen mode: bind on port, wait for one connection
 * ---------------------------------------------------------------- */
static SOCKET do_listen(int port)
{
    W16_SOCKADDR_IN addr;
    W16_SOCKADDR_IN peer;
    int             peer_len = sizeof(peer);
    char            msg[128];
    SOCKET          ls, cs;

    ls = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) { con_out("[socket() failed]\r\n"); return INVALID_SOCKET; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = w_htons((unsigned short)port);
    /* sin_addr = 0 = INADDR_ANY */

    if (w_bind(ls, (void *)&addr, sizeof(addr)) == SOCKET_ERROR ||
        w_listen(ls, 1) == SOCKET_ERROR) {
        sprintf(msg, "[bind/listen on port %d failed]\r\n", port);
        con_out(msg); w_closesock(ls); return INVALID_SOCKET;
    }

    sprintf(msg, "[Listening on port %d...]\r\n", port);
    con_out(msg);

    /* Poll for incoming connection, yielding cooperatively */
    while (g_run) {
        W16_FD_SET  rset;
        W16_TIMEVAL tv;
        tv.tv_sec = 0; tv.tv_usec = 0;
        W16_FD_ZERO(&rset);
        W16_FD_SET_(&rset, ls);
        if (w_select(1, &rset, NULL, NULL, &tv) > 0) break;
        win16_sleep_ms(50);
    }
    if (!g_run) { w_closesock(ls); return INVALID_SOCKET; }

    memset(&peer, 0, sizeof(peer));
    cs = w_accept(ls, (void *)&peer, &peer_len);
    w_closesock(ls);
    if (cs == INVALID_SOCKET) { con_out("[accept() failed]\r\n"); return INVALID_SOCKET; }

    if (w_inet_ntoa) {
        sprintf(msg, "[Connection from %s:%d]\r\n",
                w_inet_ntoa(peer.sin_addr),
                (int)w_htons(peer.sin_port));
    } else {
        sprintf(msg, "[Connection accepted on port %d]\r\n", port);
    }
    con_out(msg);
    return cs;
}

/* ----------------------------------------------------------------
 * Main relay loop: socket <-> stdin/stdout
 * Raw mode: each keystroke sent immediately, no line buffering.
 * ---------------------------------------------------------------- */
static void relay_loop(SOCKET s)
{
    con_out("[Connected -- Ctrl+C or Ctrl+Z to quit]\r\n");

    while (g_run) {
        int activity = 0;

        /* Receive: socket -> stdout */
        {
            W16_FD_SET  rset;
            W16_TIMEVAL tv;
            tv.tv_sec = 0; tv.tv_usec = 0;
            W16_FD_ZERO(&rset);
            W16_FD_SET_(&rset, s);
            if (w_select(1, &rset, NULL, NULL, &tv) > 0) {
                char buf[512];
                int  nr = w_recv(s, buf, (int)sizeof(buf), 0);
                if (nr > 0) {
                    unsigned written;
                    _dos_write(1, buf, (unsigned)nr, &written);
                    activity = 1;
                } else {
                    con_out("\r\n[Connection closed by remote]\r\n");
                    g_run = 0; break;
                }
            }
        }

        /* Send: stdin (keyboard) -> socket, raw, one char at a time */
        while (kbhit()) {
            int c = getch();
            if (c == 3 || c == 26) {    /* Ctrl+C or Ctrl+Z */
                con_out("\r\n[Quit]\r\n");
                g_run = 0; break;
            }
            if (c == '\r') {
                /* Send CR+LF for Enter; echo local newline */
                char crlf[2]; crlf[0] = '\r'; crlf[1] = '\n';
                w_send(s, crlf, 2, 0);
                con_out("\r\n");
            } else {
                char ch = (char)c;
                w_send(s, &ch, 1, 0);
                /* Local echo so the operator sees what they typed */
                { unsigned written; _dos_write(1, &ch, 1, &written); }
            }
            activity = 1;
        }

        win16_yield();

        if (!activity) win16_sleep_ms(20);
    }
}

/* ----------------------------------------------------------------
 * WinMain
 * ---------------------------------------------------------------- */
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow)
{
    char *p = lpCmdLine;
    int   listen_mode = 0;
    char  host[128]   = {0};
    int   port        = 0;

    (void)hInst; (void)hPrev; (void)nCmdShow;

    /* Parse: [-l] <host|port> [port] */
    while (*p == ' ') p++;
    if (*p == '-' && (*(p+1) == 'l' || *(p+1) == 'L') &&
        (*(p+2) == ' ' || *(p+2) == '\0')) {
        listen_mode = 1;
        p += 2;
        while (*p == ' ') p++;
        port = atoi(p);
    } else {
        char *tok = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
        strncpy(host, tok, sizeof(host) - 1);
        while (*p == ' ') p++;
        port = atoi(p);
    }

    if (port <= 0 || (!listen_mode && !host[0])) {
        con_out("Usage: nc16.exe <host> <port>\r\n"
                "       nc16.exe -l <port>\r\n");
        return 1;
    }

    if (!winsock_load()) {
        con_out("[WINSOCK.DLL not found or failed to initialise]\r\n"
                "[Install Trumpet Winsock or MS TCP/IP for WFW 3.11]\r\n");
        return 1;
    }

    g_sock = listen_mode ? do_listen(port) : do_connect(host, port);

    if (g_sock != INVALID_SOCKET) {
        relay_loop(g_sock);
        w_closesock(g_sock);
    }

    w_cleanup();
    FreeLibrary(g_wsock);
    return 0;
}
