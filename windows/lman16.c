/*
 * lman16.c  --  AeldreC2 Lightman Win16 CLI Operator Client (WFW 3.11)
 *
 * Runs from the WFW 3.11 DOS Prompt (COMMAND.COM).  WFW intercepts the NE
 * executable and launches it as a Win16 app; it inherits DOS file handles
 * from the DOS box so all output appears in the COMMAND.COM window, exactly
 * as WFW's own ping.exe and net.exe do.
 *
 * Usage:
 *   lman16.exe <host> <port> <8-digit-hex-key> [handle]
 *
 * Requires WINSOCK.DLL (Trumpet Winsock or MS TCP/IP for WFW 3.11).
 * Same Lightman/1 protocol as lightman.exe (NT); Joshua handles both.
 *
 * Build:
 *   wcc -ml -bt=windows -zu -s -I/opt/watcom/h/win -fo=lman16.obj lman16.c
 *   wlink system windows name lman16.exe file lman16.obj library winsock.lib
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dos.h>    /* _dos_write */
#include <conio.h>  /* kbhit, getch */

/* ----------------------------------------------------------------
 * Win16 Winsock 1.1 -- inlined; avoids winsock.h header conflicts
 * Follows the same pattern as tank16.c.
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
typedef struct {
    unsigned int fd_count;
    SOCKET       fd_array[W16_FD_SETSIZE];
} W16_FD_SET;
typedef struct { long tv_sec; long tv_usec; } W16_TIMEVAL;
#define W16_FD_ZERO(p)    ((p)->fd_count = 0)
#define W16_FD_SET_(p, s) ((p)->fd_array[(p)->fd_count++] = (s))

/* Function pointer typedefs (no FAR needed -- large model, all ptrs are far) */
typedef unsigned long  (*pfn_inet_addr)(const char *);
typedef unsigned short (*pfn_htons)(unsigned short);
typedef SOCKET         (*pfn_socket)(int, int, int);
typedef int            (*pfn_connect)(SOCKET, void *, int);
typedef int            (*pfn_send)(SOCKET, const char *, int, int);
typedef int            (*pfn_recv)(SOCKET, char *, int, int);
typedef int            (*pfn_closesocket)(SOCKET);
typedef W16_HOSTENT *  (*pfn_gethostbyname)(const char *);
typedef int            (*pfn_WSAStartup)(unsigned short, W16_WSADATA *);
typedef int            (*pfn_WSACleanup)(void);
typedef int            (*pfn_select)(int, W16_FD_SET *, W16_FD_SET *,
                                     W16_FD_SET *, W16_TIMEVAL *);

/* ----------------------------------------------------------------
 * Winsock function pointers
 * ---------------------------------------------------------------- */
static HINSTANCE         g_wsock     = NULL;
static pfn_inet_addr     w_inet_addr = NULL;
static pfn_htons         w_htons     = NULL;
static pfn_socket        w_socket    = NULL;
static pfn_connect       w_connect   = NULL;
static pfn_send          w_send      = NULL;
static pfn_recv          w_recv      = NULL;
static pfn_closesocket   w_closesock = NULL;
static pfn_gethostbyname w_gethost   = NULL;
static pfn_WSAStartup    w_startup   = NULL;
static pfn_WSACleanup    w_cleanup   = NULL;
static pfn_select        w_select    = NULL;

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
    GF(w_send,      "send")
    GF(w_recv,      "recv")
    GF(w_closesock, "closesocket")
    GF(w_gethost,   "gethostbyname")
    GF(w_startup,   "WSAStartup")
    GF(w_cleanup,   "WSACleanup")
    GF(w_select,    "select")
#undef GF
    return w_startup(0x0101, &wsd) == 0;
}

/* ----------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------- */
#define MAX_LINE 512
#define IBUF_SZ  (4 * 1024)

static SOCKET g_sock  = INVALID_SOCKET;
static int    g_run   = 1;
static char   g_host[128];
static int    g_port  = 4444;
static char   g_key[16];
static char   g_handle[64];

static char   g_ibuf[MAX_LINE];  /* keystrokes being typed */
static int    g_ilen = 0;

static char   g_accum[IBUF_SZ]; /* incoming server data accumulator */
static int    g_alen = 0;

/* ----------------------------------------------------------------
 * Console I/O
 *
 * _dos_write(1, ...) is DOS Int 21h Function 40h on file handle 1
 * (stdout).  When lman16.exe is launched from the WFW DOS Prompt,
 * handle 1 is inherited from the DOS box and writes appear there.
 *
 * kbhit() / getch() use DOS Int 21h Functions 0Bh / 08h, which
 * read from the same VDM keyboard buffer -- same mechanism WFW's
 * own ping.exe and net.exe use for their console I/O.
 * ---------------------------------------------------------------- */
static void con_out(const char *text)
{
    unsigned written;
    int len = strlen(text);
    if (len > 0) _dos_write(1, text, (unsigned)len, &written);
}

/* Blocking readline -- for prompts before the message loop starts. */
static int con_readline(const char *prompt, char *dst, int dstsz)
{
    int len = 0, c;
    con_out(prompt);
    for (;;) {
        c = getch();
        if (c == '\r' || c == '\n') { con_out("\r\n"); break; }
        if (c == 3)  return 0;   /* Ctrl+C */
        if (c == '\b') {
            if (len > 0) { len--; con_out("\b \b"); }
            continue;
        }
        if ((unsigned char)c >= 0x20 && len < dstsz - 1) {
            char ec[2]; ec[0] = (char)c; ec[1] = '\0';
            dst[len++] = (char)c;
            con_out(ec);
        }
    }
    dst[len] = '\0';
    return len > 0;
}

/* ----------------------------------------------------------------
 * Win16 cooperative yield -- must call PeekMessage periodically so
 * other WFW tasks get CPU time.
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

/* ----------------------------------------------------------------
 * Network helpers
 * ---------------------------------------------------------------- */
static void net_send(const char *line)
{
    if (g_sock != INVALID_SOCKET)
        w_send(g_sock, line, strlen(line), 0);
}

static void do_disconnect(void)
{
    if (g_sock != INVALID_SOCKET) {
        w_closesock(g_sock);
        g_sock = INVALID_SOCKET;
    }
    g_run = 0;
    con_out("[Disconnected]\r\n");
}

/* Blocking single-line recv -- only called during auth handshake,
 * before the select-based main loop takes over. */
static int recv_line_blocking(char *buf, int bufsz)
{
    int  i = 0;
    char c;
    while (i < bufsz - 1) {
        int n = w_recv(g_sock, &c, 1, 0);
        if (n <= 0) return -1;
        if (c == '\r') continue;
        buf[i++] = c;
        if (c == '\n') break;
        win16_yield();
    }
    buf[i] = '\0';
    if (i > 0 && buf[i-1] == '\n') buf[--i] = '\0';
    return i;
}

/* ----------------------------------------------------------------
 * Protocol: process one complete line from the server
 * ---------------------------------------------------------------- */
static void process_line(const char *line)
{
    if (strcmp(line, "KICKED") == 0) {
        con_out("[You have been kicked]\r\n");
        do_disconnect();
    } else {
        con_out(line); con_out("\r\n");
    }
}

static void process_recv(char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        char c = buf[i];
        if (c == '\r') continue;
        if (g_alen < IBUF_SZ - 1) g_accum[g_alen++] = c;
        if (c != '\n') continue;
        g_accum[g_alen] = '\0';
        if (g_alen > 0 && g_accum[g_alen-1] == '\n') g_accum[--g_alen] = '\0';
        process_line(g_accum);
        g_alen = 0;
    }
}

/* ----------------------------------------------------------------
 * Connect to Joshua and complete auth handshake (blocking + yield)
 * ---------------------------------------------------------------- */
static int do_connect_auth(void)
{
    W16_SOCKADDR_IN addr;
    unsigned long   ip;
    char            msg[192];
    char            line[128];

    g_sock = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_sock == INVALID_SOCKET) { con_out("[socket() failed]\r\n"); return 0; }

    ip = w_inet_addr(g_host);
    if (ip == 0xFFFFFFFFUL) {
        W16_HOSTENT *he;
        sprintf(msg, "[Resolving %s...]\r\n", g_host);
        con_out(msg);
        win16_yield();
        he = w_gethost(g_host);
        if (!he) { con_out("[DNS failed]\r\n"); return 0; }
        memcpy(&ip, he->h_addr_list[0], 4);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = w_htons((unsigned short)g_port);
    memcpy(&addr.sin_addr, &ip, 4);

    sprintf(msg, "[Connecting to %s:%d...]\r\n", g_host, g_port);
    con_out(msg);
    win16_yield();

    if (w_connect(g_sock, (void *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        con_out("[connect() failed]\r\n"); return 0;
    }
    con_out("[Connected -- authenticating...]\r\n");

    sprintf(msg, "Lightman/1 key=%s\r\n", g_key);
    net_send(msg);
    win16_yield();

    /* Wait for KEYOK */
    if (recv_line_blocking(line, sizeof(line)) < 0) {
        con_out("[recv error]\r\n"); return 0;
    }
    if (strcmp(line, "KEYOK") != 0) {
        con_out("[Authentication failed -- wrong key]\r\n"); return 0;
    }
    con_out("[Key accepted]\r\n");

    /* Send HANDLE, retry loop on HANDLEDUP */
send_handle:
    sprintf(msg, "HANDLE %s\r\n", g_handle);
    net_send(msg);
    win16_yield();

    if (recv_line_blocking(line, sizeof(line)) < 0) {
        con_out("[recv error]\r\n"); return 0;
    }
    if (strcmp(line, "HANDLEOK") == 0) {
        sprintf(msg, "[Connected as %s]\r\n", g_handle);
        con_out(msg);
        return 1;
    }
    if (strcmp(line, "HANDLEDUP") == 0) {
        con_out("[Handle already in use -- enter a different handle]\r\n");
        g_handle[0] = '\0';
        if (!con_readline("Handle (nom-de-plume): ", g_handle, sizeof(g_handle)))
            return 0;
        goto send_handle;
    }
    con_out("[Unexpected server response]\r\n");
    return 0;
}

/* ----------------------------------------------------------------
 * WinMain
 * ---------------------------------------------------------------- */
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow)
{
    char *p = lpCmdLine;
    char *tok;
    int   n = 0;

    (void)hInst; (void)hPrev; (void)nCmdShow;

    /* Parse: <host> <port> <key> [handle] */
    while (*p == ' ') p++;
    tok = p; while (*p && *p != ' ') p++; if (*p) *p++ = '\0';
    if (tok[0]) { strncpy(g_host, tok, sizeof(g_host)-1); n++; }

    while (*p == ' ') p++;
    tok = p; while (*p && *p != ' ') p++; if (*p) *p++ = '\0';
    if (tok[0]) { g_port = atoi(tok); n++; }

    while (*p == ' ') p++;
    tok = p; while (*p && *p != ' ') p++; if (*p) *p++ = '\0';
    if (tok[0]) { strncpy(g_key, tok, sizeof(g_key)-1); n++; }

    while (*p == ' ') p++;
    tok = p; while (*p && *p != ' ') p++; if (*p) *p++ = '\0';
    if (tok[0]) strncpy(g_handle, tok, sizeof(g_handle)-1);

    if (n < 3 || !g_host[0] || g_port <= 0 || !g_key[0]) {
        con_out("Usage: lman16.exe <host> <port> <key> [handle]\r\n");
        return 1;
    }

    if (!winsock_load()) {
        con_out("[WINSOCK.DLL not found or failed to initialise]\r\n");
        con_out("[Install Trumpet Winsock or MS TCP/IP for WFW 3.11]\r\n");
        return 1;
    }

    {
        char banner[128];
        sprintf(banner, "Lightman  \xe6ldreC2  [%s:%d]\r\n", g_host, g_port);
        con_out(banner);
    }

    if (!g_handle[0]) {
        if (!con_readline("Handle (nom-de-plume): ", g_handle, sizeof(g_handle)))
            goto cleanup;
    }

    if (!do_connect_auth())
        goto cleanup;

    con_out("Type commands and press Enter.  Ctrl+C to quit.\r\n");

    /* ---- Main loop: poll socket + keyboard, yield cooperatively ---- */
    while (g_run) {
        int activity = 0;

        /* Non-blocking socket poll via select() with zero timeout */
        if (g_sock != INVALID_SOCKET) {
            W16_FD_SET  rset;
            W16_TIMEVAL tv;
            tv.tv_sec = 0; tv.tv_usec = 0;
            W16_FD_ZERO(&rset);
            W16_FD_SET_(&rset, g_sock);
            if (w_select(1, &rset, NULL, NULL, &tv) > 0) {
                char buf[512];
                int  nr = w_recv(g_sock, buf, (int)sizeof(buf) - 1, 0);
                if (nr > 0) { process_recv(buf, nr); activity = 1; }
                else        { do_disconnect(); break; }
            }
        }

        /* Non-blocking keyboard poll via kbhit() */
        while (kbhit()) {
            int c = getch();
            if (c == 3) {               /* Ctrl+C */
                con_out("\r\n[Quit]\r\n");
                g_run = 0; break;
            }
            if (c == '\r' || c == '\n') {
                char sbuf[MAX_LINE + 4];
                int  slen = g_ilen;
                con_out("\r\n");
                if (slen > 0) {
                    char echo[MAX_LINE + 16];
                    g_ibuf[slen] = '\0';
                    memcpy(sbuf, g_ibuf, slen);
                    sbuf[slen] = '\r'; sbuf[slen+1] = '\n'; sbuf[slen+2] = '\0';
                    net_send(sbuf);
                    sprintf(echo, "<%s> %s\r\n", g_handle, g_ibuf);
                    con_out(echo);
                }
                g_ilen = 0;
            } else if (c == '\b') {
                if (g_ilen > 0) { g_ilen--; con_out("\b \b"); }
            } else if ((unsigned char)c >= 0x20 && g_ilen < MAX_LINE - 1) {
                char ec[2]; ec[0] = (char)c; ec[1] = '\0';
                g_ibuf[g_ilen++] = (char)c;
                con_out(ec);
            }
            activity = 1;
        }

        /* Yield to other WFW tasks */
        win16_yield();

        /* Nothing happening -- 20 ms pause via yield loop to avoid busy spin */
        if (!activity) {
            unsigned long t0 = GetTickCount();
            while (GetTickCount() - t0 < 20UL)
                win16_yield();
        }
    }

cleanup:
    if (g_sock != INVALID_SOCKET) w_closesock(g_sock);
    if (g_wsock) { w_cleanup(); FreeLibrary(g_wsock); }
    return 0;
}
