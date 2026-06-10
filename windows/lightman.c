/*
 * lightman.c  --  AeldreC2 Lightman CLI Operator Client
 *
 * Connects to a Joshua C2 server as a command-line operator.
 * Runs on Win 3.11 / Win32s / NT 3.1+.  Because Win32s has no console
 * subsystem, we build as a GUI app but simulate a terminal in an EDIT
 * control.  On NT4+ a real console could be used; this version uses the
 * same GUI approach for maximum compatibility.
 *
 * Usage:
 *   lightman.exe <host> <port> <8-digit-hex-key>
 *
 * Protocol (Lightman → Joshua):
 *   Lightman/1 key=XXXXXXXX\r\n     banner + auth
 *   HANDLE <nom-de-plume>\r\n       handle registration
 *   <text>\r\n                      chat or /command
 *
 * Protocol (Joshua → Lightman):
 *   KEYOK\r\n           auth success
 *   AUTHERR\r\n         auth failure
 *   HANDLEOK\r\n        handle accepted
 *   HANDLEDUP\r\n       handle already in use
 *   KICKED\r\n          you were kicked
 *   <text>\r\n          server messages / broadcasts
 *
 * Build (Win32s / NT):
 *   wmake -f Makefile.wc lightman
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
#define IDC_OUT       100
#define IDC_IN        101
#define IDC_SEND      102

#define WM_LM_RECV    (WM_APP + 1)  /* socket data ready (WPARAM=sock) */
#define WM_LM_DNS     (WM_APP + 2)  /* DNS result */
#define WM_LM_CONTIM  (WM_APP + 3)  /* console-poll timer ID */

#define CON_POLL_MS   50            /* stdin poll interval in console mode */

#define INPUT_H       26
#define BTN_W         60
#define MAX_LINE      1024
#define IBUF_SZ       (16 * 1024)

#define ST_IDLE         0
#define ST_RESOLVING    1
#define ST_CONNECTING   2
#define ST_AUTH         3   /* waiting for KEYOK */
#define ST_HANDLE       4   /* waiting for HANDLEOK */
#define ST_CONNECTED    5   /* fully operational */

#ifndef MAXGETHOSTSTRUCT
#define MAXGETHOSTSTRUCT 1024
#endif

/* ================================================================
 * Globals
 * ================================================================ */
static HINSTANCE g_hinst    = NULL;
static HWND      g_hwnd     = NULL;
static HWND      g_out      = NULL;
static HWND      g_in       = NULL;

/* Console mode */
static int       g_con_mode = 0;
static HANDLE    g_con_out  = INVALID_HANDLE_VALUE;
static HANDLE    g_con_in   = INVALID_HANDLE_VALUE;
static char      g_con_ibuf[MAX_LINE];
static int       g_con_ilen = 0;
static SOCKET    g_sock     = INVALID_SOCKET;
static int       g_state    = ST_IDLE;
static char      g_host[256];
static int       g_port     = 4444;
static char      g_key[16];
static char      g_handle[64];
static HANDLE    g_dns_task = NULL;
static char      g_dns_buf[MAXGETHOSTSTRUCT];
static char      g_accum[IBUF_SZ];
static int       g_accum_len = 0;
static WNDPROC   g_in_orig  = NULL;

/* ================================================================
 * Console helpers
 * ================================================================ */
static void con_detect(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode;
    if (h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        g_con_mode = 1;
        g_con_out  = h;
        g_con_in   = GetStdHandle(STD_INPUT_HANDLE);
    }
}

static void con_write(const char *text)
{
    DWORD written;
    int   len = lstrlen(text);
    if (!g_con_mode || g_con_out == INVALID_HANDLE_VALUE || len <= 0) return;
    WriteFile(g_con_out, text, (DWORD)len, &written, NULL);
}

/* ================================================================
 * Helpers
 * ================================================================ */
static void out_append(const char *text)
{
    int len;
    if (g_con_mode) con_write(text);
    if (!g_out) return;
    len = GetWindowTextLength(g_out);
    SendMessage(g_out, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessage(g_out, EM_REPLACESEL, 0, (LPARAM)text);
}

static void net_send(const char *line)
{
    if (g_sock == INVALID_SOCKET) return;
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
    if (g_hwnd) SetWindowText(g_hwnd, "Lightman  \xe6ldreC2  [disconnected]");
}

/* ================================================================
 * Ask for a nom-de-plume via an input dialog
 * ================================================================ */
#define IDC_HPROMPT 200
#define IDC_HEDIT   201
#define IDC_HOK     202
static HWND  g_hdlg     = NULL;
static HWND  g_hdlg_ed  = NULL;
static int   g_hdlg_ok  = 0;

static LRESULT CALLBACK HandleDlgProc(HWND hwnd, UINT msg,
                                       WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND  hw;
        hw = CreateWindow("STATIC", "Enter your handle (nom-de-plume):",
                          WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8,10,300,18,hwnd,NULL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        g_hdlg_ed = CreateWindow("EDIT","",
                          WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                          8,32,300,22,hwnd,(HMENU)IDC_HEDIT,g_hinst,NULL);
        SendMessage(g_hdlg_ed,WM_SETFONT,(WPARAM)hf,FALSE);
        hw = CreateWindow("BUTTON","Connect",
                          WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                          100,62,100,26,hwnd,(HMENU)IDC_HOK,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        SetFocus(g_hdlg_ed);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_HOK || LOWORD(wp) == IDOK) {
            GetWindowText(g_hdlg_ed, g_handle, sizeof(g_handle));
            if (g_handle[0]) { g_hdlg_ok=1; DestroyWindow(hwnd); }
            return 0;
        }
        return 0;
    case WM_CLOSE:
        g_hdlg_ok=0; DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        g_hdlg=NULL; g_hdlg_ed=NULL;
        if (!g_hdlg_ok) PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd,msg,wp,lp);
}

static int ask_handle(void)
{
    MSG msg;
    g_hdlg_ok = 0;
    g_handle[0] = '\0';

    if (!g_hwnd) return 0;
    g_hdlg = CreateWindowEx(WS_EX_DLGMODALFRAME, "LightmanDlg",
                            "Lightman  \xe6ldreC2",
                            WS_POPUP|WS_CAPTION|WS_SYSMENU,
                            0,0,330,100, g_hwnd, NULL, g_hinst, NULL);
    if (!g_hdlg) return 0;
    {
        RECT wr, dr; int dw, dh;
        GetWindowRect(g_hwnd,&wr); GetWindowRect(g_hdlg,&dr);
        dw=dr.right-dr.left; dh=dr.bottom-dr.top;
        SetWindowPos(g_hdlg,HWND_TOP,
                     wr.left+(wr.right-wr.left-dw)/2,
                     wr.top +(wr.bottom-wr.top-dh)/2,
                     0,0,SWP_NOSIZE);
    }
    ShowWindow(g_hdlg, SW_SHOW);
    while (g_hdlg) {
        if (!GetMessage(&msg,NULL,0,0)) { g_hdlg_ok=0; break; }
        if (!IsDialogMessage(g_hdlg,&msg)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
    }
    return g_hdlg_ok && g_handle[0];
}

/* ================================================================
 * Protocol: process incoming server lines
 * ================================================================ */
static void process_line(const char *line)
{
    if (g_state == ST_AUTH) {
        if (strcmp(line, "KEYOK") == 0) {
            char buf[MAX_LINE];
            out_append("[Key accepted]\r\n");
            g_state = ST_HANDLE;
            /* Send the handle we already got from the dialog */
            sprintf(buf, "HANDLE %s\r\n", g_handle);
            net_send(buf);
        } else if (strcmp(line, "AUTHERR") == 0) {
            out_append("[Authentication failed — wrong key]\r\n");
            do_disconnect();
        } else {
            out_append(line); out_append("\r\n");
        }
    } else if (g_state == ST_HANDLE) {
        if (strcmp(line, "HANDLEOK") == 0) {
            char title[192];
            g_state = ST_CONNECTED;
            out_append("[Connected as ");
            out_append(g_handle);
            out_append("]\r\n");
            sprintf(title, "Lightman  \xe6ldreC2  [%s@%s:%d]",
                    g_handle, g_host, g_port);
            SetWindowText(g_hwnd, title);
        } else if (strcmp(line, "HANDLEDUP") == 0) {
            out_append("[Handle already in use — reconnecting with a different handle]\r\n");
            /* Ask for a new handle and try again */
            if (ask_handle()) {
                char buf[MAX_LINE];
                sprintf(buf, "HANDLE %s\r\n", g_handle);
                net_send(buf);
            } else {
                do_disconnect();
            }
        } else {
            out_append(line); out_append("\r\n");
        }
    } else if (g_state == ST_CONNECTED) {
        if (strcmp(line, "KICKED") == 0) {
            out_append("[You have been kicked from the server]\r\n");
            do_disconnect();
        } else {
            out_append(line); out_append("\r\n");
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
        /* strip trailing newline before passing to process_line */
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
        out_append("[socket() failed]\r\n"); return;
    }
    ip = inet_addr(g_host);
    if (ip != INADDR_NONE) {
        /* Already an IP address — connect directly, skip DNS */
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = ip;
        addr.sin_port        = htons((unsigned short)g_port);
        WSAAsyncSelect(g_sock, g_hwnd, WM_LM_RECV, FD_CONNECT|FD_READ|FD_CLOSE);
        connect(g_sock, (struct sockaddr *)&addr, sizeof(addr));
        g_state = ST_CONNECTING;
        sprintf(msg, "[Connecting to %s:%d...]\r\n", g_host, g_port);
        out_append(msg);
        return;
    }
    sprintf(msg, "[Resolving %s...]\r\n", g_host);
    out_append(msg);
    g_state = ST_RESOLVING;
    g_dns_task = WSAAsyncGetHostByName(g_hwnd, WM_LM_DNS,
                                       g_host, g_dns_buf, sizeof(g_dns_buf));
    if (!g_dns_task) {
        out_append("[WSAAsyncGetHostByName failed]\r\n");
        do_disconnect();
    }
}

/* ================================================================
 * Send a line the user typed
 * ================================================================ */
static void do_send(void)
{
    char buf[MAX_LINE + 4];
    int  len;
    if (!g_in) return;
    len = GetWindowText(g_in, buf, MAX_LINE);
    if (len <= 0) return;
    SetWindowText(g_in, "");
    if (g_state != ST_CONNECTED) {
        out_append("[not connected]\r\n"); return;
    }
    /* Snapshot text before appending CRLF — the send buffer is reused for
     * the echo and must be NUL-terminated at len, not mid-string '\r'. */
    {
        char echo[MAX_LINE + 8];
        sprintf(echo, "<%s> %s\r\n", g_handle, buf);  /* buf[len]=='\0' here */
        buf[len] = '\r'; buf[len+1] = '\n'; buf[len+2] = '\0';
        net_send(buf);
        out_append(echo);
    }
}

/* ================================================================
 * Input subclass — Enter key sends
 * ================================================================ */
static LRESULT CALLBACK InSubclass(HWND hwnd, UINT msg,
                                    WPARAM wp, LPARAM lp)
{
    if (msg == WM_KEYDOWN && wp == VK_RETURN) {
        do_send(); return 0;
    }
    return CallWindowProc(g_in_orig, hwnd, msg, wp, lp);
}

/* ================================================================
 * Main window proc
 * ================================================================ */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_CREATE: {
        HFONT hf = (HFONT)GetStockObject(SYSTEM_FIXED_FONT);
        if (!g_con_mode) {
            /* GUI controls only needed when not in console-only mode */
            g_out = CreateWindow("EDIT","",
                        WS_CHILD|WS_VISIBLE|WS_VSCROLL|
                        ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
                        0,0,100,100,hwnd,(HMENU)IDC_OUT,g_hinst,NULL);
            SendMessage(g_out,WM_SETFONT,(WPARAM)hf,FALSE);
            g_in = CreateWindow("EDIT","",
                        WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                        0,0,100,INPUT_H,hwnd,(HMENU)IDC_IN,g_hinst,NULL);
            SendMessage(g_in,WM_SETFONT,(WPARAM)hf,FALSE);
            g_in_orig=(WNDPROC)SetWindowLong(g_in,GWL_WNDPROC,(LONG)InSubclass);
            {
                HFONT hfb = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
                HWND btn = CreateWindow("BUTTON","Send",
                            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                            0,0,BTN_W,INPUT_H,hwnd,(HMENU)IDC_SEND,g_hinst,NULL);
                SendMessage(btn,WM_SETFONT,(WPARAM)hfb,FALSE);
            }
        }
        if (g_con_mode)
            SetTimer(hwnd, WM_LM_CONTIM, CON_POLL_MS, NULL);
        return 0;
    }

    case WM_SIZE: {
        int w=LOWORD(lp), h=HIWORD(lp), iw=w-BTN_W-2;
        MoveWindow(g_out,0,0,w,h-INPUT_H-2,TRUE);
        MoveWindow(g_in, 0,h-INPUT_H,iw>0?iw:0,INPUT_H,TRUE);
        MoveWindow(GetDlgItem(hwnd,IDC_SEND),iw>0?iw:0,h-INPUT_H,BTN_W,INPUT_H,TRUE);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wp) == IDC_SEND) { do_send(); return 0; }
        break;

    case WM_TIMER:
        if ((int)wp == WM_LM_CONTIM && g_con_mode &&
            g_con_in != INVALID_HANDLE_VALUE) {
            /* Poll stdin for key events */
            INPUT_RECORD ir;
            DWORD count;
            while (PeekConsoleInput(g_con_in, &ir, 1, &count) && count > 0) {
                ReadConsoleInput(g_con_in, &ir, 1, &count);
                if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
                    char c = ir.Event.KeyEvent.uChar.AsciiChar;
                    if (c == '\r' || c == '\n') {
                        g_con_ibuf[g_con_ilen] = '\0';
                        con_write("\r\n");
                        if (g_con_ilen > 0) {
                            if (g_state == ST_CONNECTED) {
                                char sbuf[MAX_LINE + 4];
                                int  slen = g_con_ilen;
                                char echo[MAX_LINE + 16];
                                memcpy(sbuf, g_con_ibuf, slen);
                                sbuf[slen]   = '\r';
                                sbuf[slen+1] = '\n';
                                sbuf[slen+2] = '\0';
                                net_send(sbuf);
                                sprintf(echo, "<%s> %s\r\n", g_handle, g_con_ibuf);
                                con_write(echo);
                            } else {
                                con_write("[not connected]\r\n");
                            }
                        }
                        g_con_ilen = 0;
                    } else if (c == '\b') {
                        if (g_con_ilen > 0) {
                            g_con_ilen--;
                            con_write("\b \b");
                        }
                    } else if (c >= 0x20 && g_con_ilen < MAX_LINE - 1) {
                        char echo2[2];
                        g_con_ibuf[g_con_ilen++] = c;
                        echo2[0] = c; echo2[1] = '\0';
                        con_write(echo2);
                    }
                }
            }
        }
        return 0;

    case WM_LM_DNS: {
        struct hostent    *he;
        struct sockaddr_in addr;
        int dns_err = WSAGETASYNCERROR(lp);
        g_dns_task  = NULL;
        if (dns_err) {
            char m[128]; sprintf(m,"[DNS error %d]\r\n",dns_err);
            out_append(m); do_disconnect(); return 0;
        }
        he = (struct hostent *)g_dns_buf;
        memset(&addr,0,sizeof(addr));
        addr.sin_family=AF_INET;
        memcpy(&addr.sin_addr,he->h_addr,he->h_length);
        addr.sin_port=htons((unsigned short)g_port);
        WSAAsyncSelect(g_sock,hwnd,WM_LM_RECV,FD_CONNECT|FD_READ|FD_CLOSE);
        connect(g_sock,(struct sockaddr*)&addr,sizeof(addr));
        g_state=ST_CONNECTING;
        { char m[128]; sprintf(m,"[Connecting to %s:%d...]\r\n",g_host,g_port);
          out_append(m); }
        return 0;
    }

    case WM_LM_RECV: {
        int   event = WSAGETSELECTEVENT(lp);
        int   err   = WSAGETSELECTERROR(lp);
        char  buf[4096];
        int   n;
        if (err) {
            char m[64]; sprintf(m,"[network error %d]\r\n",err);
            out_append(m); do_disconnect(); return 0;
        }
        switch (event) {
        case FD_CONNECT: {
            char banner[128];
            g_state = ST_AUTH;
            out_append("[Connected — authenticating...]\r\n");
            sprintf(banner,"Lightman/1 key=%s\r\n", g_key);
            net_send(banner);
            break;
        }
        case FD_READ:
            n = recv(g_sock, buf, sizeof(buf)-1, 0);
            if (n > 0) process_recv(buf, n);
            break;
        case FD_CLOSE:
            out_append("[Server closed connection]\r\n");
            do_disconnect();
            break;
        }
        return 0;
    }

    case WM_CLOSE:
        do_disconnect();
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd,msg,wp,lp);
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
    char     title[256];

    /* Parse command line: <host> <port> <key> */
    {
        char *p = lpCmdLine;
        char *tok;
        int   n = 0;

        while (*p == ' ') p++;
        tok = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
        if (tok[0]) { strncpy(g_host, tok, 255); n++; }

        while (*p == ' ') p++;
        tok = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
        if (tok[0]) { g_port = atoi(tok); n++; }

        while (*p == ' ') p++;
        tok = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
        if (tok[0]) { strncpy(g_key, tok, 15); n++; }

        if (n < 3 || !g_host[0] || g_port <= 0 || !g_key[0]) {
            MessageBox(NULL,
                "Usage: lightman.exe <host> <port> <key>\r\n\r\n"
                "Example: lightman.exe 10.0.0.1 4444 A3F7B291",
                "Lightman  \xe6ldreC2", MB_OK|MB_ICONSTOP);
            return 1;
        }
    }

    g_hinst = hInst;
    con_detect();

    if (WSAStartup(MAKEWORD(1,1),&wsd) != 0) {
        if (g_con_mode) con_write("WSAStartup failed.\r\n");
        else MessageBox(NULL,"WSAStartup failed.","Lightman",MB_OK|MB_ICONSTOP);
        return 1;
    }

    if (!hPrev) {
        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc   = WndProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
        wc.lpszClassName = "LightmanMain";
        RegisterClass(&wc);

        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc   = HandleDlgProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        wc.lpszClassName = "LightmanDlg";
        RegisterClass(&wc);
    }

    sprintf(title,"Lightman  \xe6ldreC2  [%s:%d]", g_host, g_port);
    g_hwnd = CreateWindow("LightmanMain", title,
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,CW_USEDEFAULT,800,600,
                NULL,NULL,hInst,NULL);
    if (!g_hwnd) return 1;

    if (g_con_mode) {
        /* Console mode: run headless, print banner to stdout */
        char banner[256];
        sprintf(banner, "Lightman  \xe6ldreC2  [%s:%d]\r\n"
                        "Type messages and press Enter. Ctrl+C to quit.\r\n",
                g_host, g_port);
        con_write(banner);
        ShowWindow(g_hwnd, SW_HIDE);
    } else {
        ShowWindow(g_hwnd, nCmdShow);
        UpdateWindow(g_hwnd);
    }

    /* Prompt for handle before connecting */
    if (!ask_handle()) {
        WSACleanup(); return 0;
    }

    do_connect();

    while (GetMessage(&msg,NULL,0,0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    do_disconnect();
    if (!hPrev) {
        UnregisterClass("LightmanMain",hInst);
        UnregisterClass("LightmanDlg", hInst);
    }
    WSACleanup();
    return (int)msg.wParam;
}
