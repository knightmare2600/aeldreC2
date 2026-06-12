/*
 * lightman.c  --  AeldreC2 Lightman CLI Operator Client
 *
 * Pure console tool for NT 3.1+.  Use Flynn for GUI.
 *
 * Usage:
 *   lightman.exe <host> <port> <8-digit-hex-key> [handle]
 *
 * Handle on command line skips the stdin prompt.
 * All prompts (handle, re-handle on dup) use readline on stdin.
 *
 * A hidden HWND is created solely for WSAAsyncSelect event delivery.
 *
 * Protocol (Lightman -> Joshua):
 *   Lightman/1 key=XXXXXXXX\r\n
 *   HANDLE <nom-de-plume>\r\n
 *   <text or /command>\r\n
 *
 * Protocol (Joshua -> Lightman):
 *   KEYOK / AUTHERR / HANDLEOK / HANDLEDUP / KICKED / <text>
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ================================================================
 * Constants
 * ================================================================ */
#define WM_LM_RECV   (WM_APP + 1)   /* socket event (WSAAsyncSelect) */
#define WM_LM_DNS    (WM_APP + 2)   /* DNS result */
#define WM_LM_CTIM   (WM_APP + 3)   /* console stdin poll timer */

#define CON_POLL_MS  50
#define MAX_LINE     1024
#define IBUF_SZ      (16 * 1024)

#define ST_IDLE        0
#define ST_RESOLVING   1
#define ST_CONNECTING  2
#define ST_AUTH        3
#define ST_HANDLE      4
#define ST_CONNECTED   5

#ifndef MAXGETHOSTSTRUCT
#define MAXGETHOSTSTRUCT 1024
#endif

/* ================================================================
 * Globals
 * ================================================================ */
static HINSTANCE g_hinst  = NULL;
static HWND      g_hwnd   = NULL;   /* hidden message window for WSAAsyncSelect */

static HANDLE    g_cout   = INVALID_HANDLE_VALUE;
static HANDLE    g_cin    = INVALID_HANDLE_VALUE;

static char      g_ibuf[MAX_LINE];  /* console line being built by timer */
static int       g_ilen  = 0;

static SOCKET    g_sock  = INVALID_SOCKET;
static int       g_state = ST_IDLE;
static char      g_host[256];
static int       g_port  = 4444;
static char      g_key[16];
static char      g_handle[64];

static HANDLE    g_dns_task = NULL;
static char      g_dns_buf[MAXGETHOSTSTRUCT];
static char      g_accum[IBUF_SZ];
static int       g_accum_len = 0;

/* ================================================================
 * Console I/O
 * ================================================================ */
static void con_write(const char *text)
{
    DWORD written;
    int   len = lstrlen(text);
    if (g_cout == INVALID_HANDLE_VALUE || len <= 0) return;
    WriteFile(g_cout, text, (DWORD)len, &written, NULL);
}

/* Blocking readline — used before the message loop and for inline prompts. */
static int con_readline(const char *prompt, char *dst, int dstsz)
{
    char  buf[MAX_LINE];
    DWORD nread = 0;
    int   len;
    con_write(prompt);
    buf[0] = '\0';
    if (g_cin == INVALID_HANDLE_VALUE) return 0;
    if (!ReadFile(g_cin, buf, (DWORD)(sizeof(buf) - 1), &nread, NULL) ||
        nread == 0) return 0;
    buf[nread] = '\0';
    len = (int)nread;
    while (len > 0 && (buf[len-1] == '\r' || buf[len-1] == '\n'))
        buf[--len] = '\0';
    if (len == 0) return 0;
    lstrcpyn(dst, buf, dstsz);
    return 1;
}

/* ================================================================
 * Networking helpers
 * ================================================================ */
static void net_send(const char *line)
{
    if (g_sock != INVALID_SOCKET)
        send(g_sock, line, lstrlen(line), 0);
}

static void do_disconnect(void)
{
    if (g_sock != INVALID_SOCKET) {
        WSAAsyncSelect(g_sock, g_hwnd, 0, 0);
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }
    g_state = ST_IDLE;
    con_write("[Disconnected]\r\n");
    if (g_hwnd) DestroyWindow(g_hwnd);   /* triggers WM_DESTROY → PostQuitMessage */
}

/* ================================================================
 * Protocol: process one line received from Joshua
 * ================================================================ */
static void process_line(const char *line)
{
    if (g_state == ST_AUTH) {
        if (strcmp(line, "KEYOK") == 0) {
            char buf[MAX_LINE];
            con_write("[Key accepted]\r\n");
            g_state = ST_HANDLE;
            sprintf(buf, "HANDLE %s\r\n", g_handle);
            net_send(buf);
        } else if (strcmp(line, "AUTHERR") == 0) {
            con_write("[Authentication failed -- wrong key]\r\n");
            do_disconnect();
        } else {
            con_write(line); con_write("\r\n");
        }

    } else if (g_state == ST_HANDLE) {
        if (strcmp(line, "HANDLEOK") == 0) {
            char info[192];
            g_state = ST_CONNECTED;
            sprintf(info, "[Connected as %s]\r\n", g_handle);
            con_write(info);
        } else if (strcmp(line, "HANDLEDUP") == 0) {
            con_write("[Handle already in use -- enter a different handle]\r\n");
            g_handle[0] = '\0';
            if (con_readline("Handle (nom-de-plume): ", g_handle, sizeof(g_handle))) {
                char buf[MAX_LINE];
                sprintf(buf, "HANDLE %s\r\n", g_handle);
                net_send(buf);
            } else {
                do_disconnect();
            }
        } else {
            con_write(line); con_write("\r\n");
        }

    } else if (g_state == ST_CONNECTED) {
        if (strcmp(line, "KICKED") == 0) {
            con_write("[You have been kicked from the server]\r\n");
            do_disconnect();
        } else {
            con_write(line); con_write("\r\n");
        }
    }
}

static void process_recv(const char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        char c = buf[i];
        if (c == '\r') continue;
        if (g_accum_len < IBUF_SZ - 1)
            g_accum[g_accum_len++] = c;
        if (c != '\n') continue;
        g_accum[g_accum_len] = '\0';
        if (g_accum_len > 0 && g_accum[g_accum_len-1] == '\n')
            g_accum[g_accum_len-1] = '\0';
        process_line(g_accum);
        g_accum_len = 0;
    }
}

/* ================================================================
 * Connect sequence
 * ================================================================ */
static void do_connect(void)
{
    char msg[192];
    unsigned long ip;
    g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_sock == INVALID_SOCKET) {
        con_write("[socket() failed]\r\n"); return;
    }
    ip = inet_addr(g_host);
    if (ip != INADDR_NONE) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = ip;
        addr.sin_port        = htons((unsigned short)g_port);
        WSAAsyncSelect(g_sock, g_hwnd, WM_LM_RECV, FD_CONNECT|FD_READ|FD_CLOSE);
        connect(g_sock, (struct sockaddr *)&addr, sizeof(addr));
        g_state = ST_CONNECTING;
        sprintf(msg, "[Connecting to %s:%d...]\r\n", g_host, g_port);
        con_write(msg);
        return;
    }
    sprintf(msg, "[Resolving %s...]\r\n", g_host);
    con_write(msg);
    g_state = ST_RESOLVING;
    g_dns_task = WSAAsyncGetHostByName(g_hwnd, WM_LM_DNS,
                                       g_host, g_dns_buf, sizeof(g_dns_buf));
    if (!g_dns_task) {
        con_write("[WSAAsyncGetHostByName failed]\r\n");
        do_disconnect();
    }
}

/* ================================================================
 * Hidden message window — exists only for WSAAsyncSelect delivery
 * ================================================================ */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_CREATE:
        SetTimer(hwnd, WM_LM_CTIM, CON_POLL_MS, NULL);
        return 0;

    case WM_TIMER:
        /* Poll console for keystrokes and build a line */
        if ((int)wp == WM_LM_CTIM && g_cin != INVALID_HANDLE_VALUE) {
            INPUT_RECORD ir;
            DWORD count;
            while (PeekConsoleInput(g_cin, &ir, 1, &count) && count > 0) {
                ReadConsoleInput(g_cin, &ir, 1, &count);
                if (ir.EventType != KEY_EVENT || !ir.Event.KeyEvent.bKeyDown)
                    continue;
                {
                    char c = ir.Event.KeyEvent.uChar.AsciiChar;
                    if (c == '\r' || c == '\n') {
                        g_ibuf[g_ilen] = '\0';
                        con_write("\r\n");
                        if (g_ilen > 0) {
                            if (g_state == ST_CONNECTED) {
                                char sbuf[MAX_LINE + 4];
                                char echo[MAX_LINE + 16];
                                int  slen = g_ilen;
                                memcpy(sbuf, g_ibuf, slen);
                                sbuf[slen]   = '\r';
                                sbuf[slen+1] = '\n';
                                sbuf[slen+2] = '\0';
                                net_send(sbuf);
                                sprintf(echo, "<%s> %s\r\n", g_handle, g_ibuf);
                                con_write(echo);
                            } else {
                                con_write("[not connected]\r\n");
                            }
                        }
                        g_ilen = 0;
                    } else if (c == '\b') {
                        if (g_ilen > 0) { g_ilen--; con_write("\b \b"); }
                    } else if (c >= 0x20 && g_ilen < MAX_LINE - 1) {
                        char ec[2]; ec[0] = c; ec[1] = '\0';
                        g_ibuf[g_ilen++] = c;
                        con_write(ec);
                    }
                }
            }
        }
        return 0;

    case WM_LM_DNS: {
        struct hostent    *he;
        struct sockaddr_in addr;
        int dns_err = WSAGETASYNCERROR(lp);
        g_dns_task = NULL;
        if (dns_err) {
            char m[64]; sprintf(m, "[DNS error %d]\r\n", dns_err);
            con_write(m); do_disconnect(); return 0;
        }
        he = (struct hostent *)g_dns_buf;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);
        addr.sin_port = htons((unsigned short)g_port);
        WSAAsyncSelect(g_sock, hwnd, WM_LM_RECV, FD_CONNECT|FD_READ|FD_CLOSE);
        connect(g_sock, (struct sockaddr *)&addr, sizeof(addr));
        g_state = ST_CONNECTING;
        { char m[128]; sprintf(m, "[Connecting to %s:%d...]\r\n", g_host, g_port);
          con_write(m); }
        return 0;
    }

    case WM_LM_RECV: {
        int  event = WSAGETSELECTEVENT(lp);
        int  err   = WSAGETSELECTERROR(lp);
        char buf[4096];
        int  n;
        if (err) {
            char m[64]; sprintf(m, "[network error %d]\r\n", err);
            con_write(m); do_disconnect(); return 0;
        }
        switch (event) {
        case FD_CONNECT: {
            char banner[128];
            g_state = ST_AUTH;
            con_write("[Connected -- authenticating...]\r\n");
            sprintf(banner, "Lightman/1 key=%s\r\n", g_key);
            net_send(banner);
            break;
        }
        case FD_READ:
            n = recv(g_sock, buf, sizeof(buf) - 1, 0);
            if (n > 0) process_recv(buf, n);
            break;
        case FD_CLOSE:
            con_write("[Server closed connection]\r\n");
            do_disconnect();
            break;
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ================================================================
 * WinMain
 * ================================================================ */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WSADATA  wsd;
    WNDCLASS wc;
    MSG      msg;

    g_hinst = hInst;
    g_cout  = GetStdHandle(STD_OUTPUT_HANDLE);
    g_cin   = GetStdHandle(STD_INPUT_HANDLE);

    /* Parse: <host> <port> <key> [handle] */
    {
        char *p = lpCmdLine;
        char *tok;
        int   n = 0;

        while (*p == ' ') p++;
        tok = p; while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
        if (tok[0]) { lstrcpyn(g_host, tok, sizeof(g_host)); n++; }

        while (*p == ' ') p++;
        tok = p; while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
        if (tok[0]) { g_port = atoi(tok); n++; }

        while (*p == ' ') p++;
        tok = p; while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
        if (tok[0]) { lstrcpyn(g_key, tok, sizeof(g_key)); n++; }

        /* optional handle on CLI skips the stdin prompt */
        while (*p == ' ') p++;
        tok = p; while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
        if (tok[0]) lstrcpyn(g_handle, tok, sizeof(g_handle));

        if (n < 3 || !g_host[0] || g_port <= 0 || !g_key[0]) {
            con_write("Usage: lightman.exe <host> <port> <key> [handle]\r\n"
                      "Example: lightman.exe 10.0.0.1 4444 A3F7B291 operator\r\n");
            return 1;
        }
    }

    if (WSAStartup(MAKEWORD(1, 1), &wsd) != 0) {
        con_write("[WSAStartup failed]\r\n");
        return 1;
    }

    if (!hPrev) {
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = WndProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = "LightmanMsg";
        RegisterClass(&wc);
    }

    /* Hidden window — message pump for WSAAsyncSelect only */
    g_hwnd = CreateWindow("LightmanMsg", "",
                WS_OVERLAPPED, 0, 0, 0, 0,
                NULL, NULL, hInst, NULL);
    if (!g_hwnd) { WSACleanup(); return 1; }

    {
        char banner[256];
        sprintf(banner,
                "Lightman  \xe6ldreC2  [%s:%d]\r\n"
                "Type commands and press Enter.  Ctrl+C to quit.\r\n",
                g_host, g_port);
        con_write(banner);
    }

    /* Prompt for handle if not given on command line */
    if (!g_handle[0]) {
        if (!con_readline("Handle (nom-de-plume): ", g_handle, sizeof(g_handle))) {
            WSACleanup(); return 0;
        }
    }

    do_connect();

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    do_disconnect();
    if (!hPrev) UnregisterClass("LightmanMsg", hInst);
    WSACleanup();
    return (int)msg.wParam;
}
