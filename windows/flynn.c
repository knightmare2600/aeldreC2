/*
 * flynn.c  --  AeldreC2 Flynn GUI Operator Client
 *
 * GUI C2 operator client with the same protocol as Lightman.
 * Two-pane layout: left = operator list, right = output + input.
 * Connection settings entered via a dialog on startup.
 *
 * Targets Win32s / Win32 / NT 3.1+.
 *
 * Protocol is identical to lightman.c:
 *   Flynn/1 key=XXXXXXXX\r\n   banner
 *   HANDLE <nom>\r\n            handle
 *   <text>\r\n                  chat / /command
 *
 * Build:
 *   wmake -f Makefile.wc flynn
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
#define IDC_OUT         100
#define IDC_IN          101
#define IDC_SEND        102
#define IDC_OPLIST      103

/* Connect dialog */
#define IDC_CD_HOST     200
#define IDC_CD_PORT     201
#define IDC_CD_KEY      202
#define IDC_CD_HANDLE   203
#define IDC_CD_OK       204
#define IDC_CD_CANCEL   205

#define WM_FL_RECV      (WM_APP + 1)
#define WM_FL_DNS       (WM_APP + 2)

#define INPUT_H         26
#define BTN_W           60
#define OPLIST_W        160
#define MAX_LINE        1024
#define IBUF_SZ         (16 * 1024)
#define MAX_OPS         64

#define ST_IDLE         0
#define ST_RESOLVING    1
#define ST_CONNECTING   2
#define ST_AUTH         3
#define ST_HANDLE       4
#define ST_CONNECTED    5

#ifndef MAXGETHOSTSTRUCT
#define MAXGETHOSTSTRUCT 1024
#endif

/* ================================================================
 * Globals
 * ================================================================ */
static HINSTANCE g_hinst       = NULL;
static HWND      g_hwnd        = NULL;
static HWND      g_out         = NULL;
static HWND      g_in          = NULL;
static HWND      g_oplist      = NULL;
static SOCKET    g_sock        = INVALID_SOCKET;
static int       g_state       = ST_IDLE;
static char      g_host[256];
static int       g_port        = 4444;
static char      g_key[16];
static char      g_handle[64];
static HANDLE    g_dns_task    = NULL;
static char      g_dns_buf[MAXGETHOSTSTRUCT];
static char      g_accum[IBUF_SZ];
static int       g_accum_len   = 0;
static WNDPROC   g_in_orig     = NULL;

/* Connect dialog state */
static HWND  g_cdlg            = NULL;
static int   g_cdlg_ok         = 0;

/* ================================================================
 * Output helpers
 * ================================================================ */
static void out_append(const char *text)
{
    int len;
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

static void oplist_set(const char *entries[], int n)
{
    int i;
    if (!g_oplist) return;
    SendMessage(g_oplist, LB_RESETCONTENT, 0, 0);
    for (i = 0; i < n; i++)
        SendMessage(g_oplist, LB_ADDSTRING, 0, (LPARAM)entries[i]);
}

/* Parse a server "[OP] handle connected" / "[OP] handle disconnected" message
   and update the operator list accordingly. */
static char g_ops[MAX_OPS][80];
static int  g_nops = 0;

static void oplist_add(const char *handle)
{
    int i;
    if (g_nops >= MAX_OPS) return;
    for (i = 0; i < g_nops; i++)
        if (lstrcmpi(g_ops[i], handle) == 0) return;
    strncpy(g_ops[g_nops++], handle, 79);
    if (g_oplist) SendMessage(g_oplist, LB_ADDSTRING, 0, (LPARAM)handle);
}

static void oplist_remove(const char *handle)
{
    int i, idx;
    for (i = 0; i < g_nops; i++) {
        if (lstrcmpi(g_ops[i], handle) == 0) {
            memmove(g_ops[i], g_ops[i+1], (g_nops-i-1) * sizeof(g_ops[0]));
            g_nops--;
            if (g_oplist) {
                idx = (int)SendMessage(g_oplist, LB_FINDSTRINGEXACT,
                                       (WPARAM)-1, (LPARAM)handle);
                if (idx != LB_ERR)
                    SendMessage(g_oplist, LB_DELETESTRING, (WPARAM)idx, 0);
            }
            return;
        }
    }
}

static void do_disconnect(void)
{
    if (g_sock != INVALID_SOCKET) {
        WSAAsyncSelect(g_sock, g_hwnd, 0, 0);
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }
    g_state  = ST_IDLE;
    g_nops   = 0;
    if (g_oplist) SendMessage(g_oplist, LB_RESETCONTENT, 0, 0);
    if (g_hwnd) SetWindowText(g_hwnd, "Flynn  \xe6ldreC2  [disconnected]");
}

/* Forward declaration */
static void do_connect_async(void);

/* ================================================================
 * Connect dialog
 * ================================================================ */
static HWND g_cd_host  = NULL;
static HWND g_cd_port  = NULL;
static HWND g_cd_key   = NULL;
static HWND g_cd_hndl  = NULL;

static LRESULT CALLBACK ConnDlgProc(HWND hwnd, UINT msg,
                                     WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND  hw;
        int   y  = 10;
#define ROW(label,id,def,ysep) \
        hw=CreateWindow("STATIC",label,WS_CHILD|WS_VISIBLE|SS_LEFT, \
                        8,y+3,80,18,hwnd,NULL,g_hinst,NULL); \
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE); \
        hw=CreateWindow("EDIT",def,WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, \
                        94,y,220,22,hwnd,(HMENU)id,g_hinst,NULL); \
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE); \
        y += ysep;

        ROW("Joshua host:", IDC_CD_HOST,   g_host,  28)
        ROW("Port:",        IDC_CD_PORT,   "4444",   28)
        ROW("Server key:",  IDC_CD_KEY,    "",       28)
        ROW("Your handle:", IDC_CD_HANDLE, "",       28)
#undef ROW
        g_cd_host = GetDlgItem(hwnd, IDC_CD_HOST);
        g_cd_port = GetDlgItem(hwnd, IDC_CD_PORT);
        g_cd_key  = GetDlgItem(hwnd, IDC_CD_KEY);
        g_cd_hndl = GetDlgItem(hwnd, IDC_CD_HANDLE);

        y += 4;
        hw=CreateWindow("BUTTON","Connect",WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                        54,y,100,26,hwnd,(HMENU)IDC_CD_OK,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        hw=CreateWindow("BUTTON","Cancel",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                        166,y,100,26,hwnd,(HMENU)IDC_CD_CANCEL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        SetFocus(g_cd_host);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp)==IDC_CD_CANCEL||LOWORD(wp)==IDCANCEL) {
            g_cdlg_ok=0; DestroyWindow(hwnd); return 0;
        }
        if (LOWORD(wp)==IDC_CD_OK) {
            char portbuf[16];
            GetWindowText(g_cd_host, g_host, 255);
            GetWindowText(g_cd_port, portbuf, 15);
            GetWindowText(g_cd_key,  g_key,  15);
            GetWindowText(g_cd_hndl, g_handle, 63);
            g_port = atoi(portbuf);
            if (!g_host[0] || g_port<=0 || !g_key[0] || !g_handle[0]) {
                MessageBox(hwnd,"Please fill in all fields.","Flynn",MB_OK|MB_ICONWARNING);
                return 0;
            }
            g_cdlg_ok=1; DestroyWindow(hwnd); return 0;
        }
        return 0;
    case WM_CLOSE:
        g_cdlg_ok=0; DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        g_cdlg=NULL;
        g_cd_host=g_cd_port=g_cd_key=g_cd_hndl=NULL;
        if (!g_cdlg_ok) PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd,msg,wp,lp);
}

static int show_connect_dialog(void)
{
    MSG  msg;
    RECT wr, dr; int dw, dh;

    g_cdlg_ok = 0;
    g_cdlg = CreateWindowEx(WS_EX_DLGMODALFRAME, "FlynnConnDlg",
                             "Flynn  \xe6ldreC2  — Connect",
                             WS_POPUP|WS_CAPTION|WS_SYSMENU,
                             0,0,340,170, g_hwnd,NULL,g_hinst,NULL);
    if (!g_cdlg) return 0;
    GetWindowRect(g_hwnd,&wr); GetWindowRect(g_cdlg,&dr);
    dw=dr.right-dr.left; dh=dr.bottom-dr.top;
    SetWindowPos(g_cdlg,HWND_TOP,
                 wr.left+(wr.right-wr.left-dw)/2,
                 wr.top +(wr.bottom-wr.top-dh)/2,
                 0,0,SWP_NOSIZE);
    ShowWindow(g_cdlg,SW_SHOW);
    SetFocus(g_cdlg);
    while (g_cdlg) {
        if (!GetMessage(&msg,NULL,0,0)) { g_cdlg_ok=0; break; }
        if (!IsDialogMessage(g_cdlg,&msg)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
    }
    return g_cdlg_ok;
}

/* ================================================================
 * Protocol — process incoming server lines
 * ================================================================ */

/* Attempt to extract handle from "[OP] <handle> connected" lines */
static void maybe_update_oplist(const char *line)
{
    if (strncmp(line, "[OP] ", 5) == 0) {
        char handle[80];
        const char *p = line + 5;
        const char *end;
        end = strchr(p, ' ');
        if (!end) return;
        strncpy(handle, p, (int)(end-p) < 79 ? (int)(end-p) : 79);
        handle[(int)(end-p) < 79 ? (int)(end-p) : 79] = '\0';
        if (strstr(end, "connected"))
            oplist_add(handle);
        else if (strstr(end, "disconnected") || strstr(end, "kicked"))
            oplist_remove(handle);
    }
}

static void process_line(const char *line)
{
    if (g_state == ST_AUTH) {
        if (strcmp(line, "KEYOK") == 0) {
            char buf[MAX_LINE];
            out_append("[Key accepted]\r\n");
            g_state = ST_HANDLE;
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
            sprintf(title,"Flynn  \xe6ldreC2  [%s@%s:%d]",
                    g_handle,g_host,g_port);
            SetWindowText(g_hwnd, title);
            oplist_add(g_handle);
        } else if (strcmp(line, "HANDLEDUP") == 0) {
            out_append("[Handle already in use — try /reconnect with a different handle]\r\n");
            /* Re-show connect dialog so user can change their handle */
            do_disconnect();
            if (show_connect_dialog()) {
                do_connect_async();
            } else {
                PostQuitMessage(0);
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
            maybe_update_oplist(line);
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
 * Connect
 * ================================================================ */
static void do_connect_async(void)
{
    char m[192];
    g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_sock == INVALID_SOCKET) {
        out_append("[socket() failed]\r\n"); return;
    }
    sprintf(m,"[Resolving %s...]\r\n",g_host);
    out_append(m);
    g_state = ST_RESOLVING;
    g_dns_task = WSAAsyncGetHostByName(g_hwnd,WM_FL_DNS,
                                       g_host,g_dns_buf,sizeof(g_dns_buf));
    if (!g_dns_task) {
        out_append("[WSAAsyncGetHostByName failed]\r\n");
        do_disconnect();
    }
}

/* ================================================================
 * Send user input
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
    buf[len]='\r'; buf[len+1]='\n'; buf[len+2]='\0';
    net_send(buf);
    {
        char echo[MAX_LINE + 8];
        buf[len]='\0';
        sprintf(echo,"<%s> %s\r\n",g_handle,buf);
        out_append(echo);
    }
}

/* ================================================================
 * Input subclass
 * ================================================================ */
static LRESULT CALLBACK InSubclass(HWND hwnd, UINT msg,
                                    WPARAM wp, LPARAM lp)
{
    if (msg==WM_KEYDOWN && wp==VK_RETURN) { do_send(); return 0; }
    return CallWindowProc(g_in_orig,hwnd,msg,wp,lp);
}

/* ================================================================
 * Main window proc
 * ================================================================ */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_CREATE: {
        HFONT hf  = (HFONT)GetStockObject(SYSTEM_FIXED_FONT);
        HFONT hfb = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND  btn;
        g_oplist = CreateWindow("LISTBOX",NULL,
                    WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_BORDER|LBS_HASSTRINGS,
                    0,0,OPLIST_W,100,hwnd,(HMENU)IDC_OPLIST,g_hinst,NULL);
        SendMessage(g_oplist,WM_SETFONT,(WPARAM)hfb,FALSE);
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
        btn = CreateWindow("BUTTON","Send",
                    WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                    0,0,BTN_W,INPUT_H,hwnd,(HMENU)IDC_SEND,g_hinst,NULL);
        SendMessage(btn,WM_SETFONT,(WPARAM)hfb,FALSE);
        return 0;
    }

    case WM_SIZE: {
        int w   = (int)LOWORD(lp);
        int h   = (int)HIWORD(lp);
        int mw  = w > OPLIST_W ? w - OPLIST_W : 0;
        int iw  = mw - BTN_W - 2;
        MoveWindow(g_oplist, 0,     0, OPLIST_W, h, TRUE);
        MoveWindow(g_out,    OPLIST_W, 0, mw,  h-INPUT_H-2, TRUE);
        MoveWindow(g_in,     OPLIST_W, h-INPUT_H, iw>0?iw:0, INPUT_H, TRUE);
        MoveWindow(GetDlgItem(hwnd,IDC_SEND),
                   OPLIST_W+(iw>0?iw:0), h-INPUT_H, BTN_W, INPUT_H, TRUE);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wp)==IDC_SEND) { do_send(); return 0; }
        break;

    case WM_FL_DNS: {
        struct hostent    *he;
        struct sockaddr_in addr;
        int dns_err = WSAGETASYNCERROR(lp);
        g_dns_task  = NULL;
        if (dns_err) {
            char m[128]; sprintf(m,"[DNS error %d]\r\n",dns_err);
            out_append(m); do_disconnect(); return 0;
        }
        he=(struct hostent*)g_dns_buf;
        memset(&addr,0,sizeof(addr));
        addr.sin_family=AF_INET;
        memcpy(&addr.sin_addr,he->h_addr,he->h_length);
        addr.sin_port=htons((unsigned short)g_port);
        WSAAsyncSelect(g_sock,hwnd,WM_FL_RECV,FD_CONNECT|FD_READ|FD_CLOSE);
        connect(g_sock,(struct sockaddr*)&addr,sizeof(addr));
        g_state=ST_CONNECTING;
        { char m[128]; sprintf(m,"[Connecting to %s:%d...]\r\n",g_host,g_port);
          out_append(m); }
        return 0;
    }

    case WM_FL_RECV: {
        int  event = WSAGETSELECTEVENT(lp);
        int  err   = WSAGETSELECTERROR(lp);
        char buf[4096];
        int  n;
        if (err) {
            char m[64]; sprintf(m,"[network error %d]\r\n",err);
            out_append(m); do_disconnect(); return 0;
        }
        switch (event) {
        case FD_CONNECT: {
            char banner[128];
            g_state=ST_AUTH;
            out_append("[Connected — authenticating...]\r\n");
            sprintf(banner,"Flynn/1 key=%s\r\n",g_key);
            net_send(banner);
            break;
        }
        case FD_READ:
            n=recv(g_sock,buf,sizeof(buf)-1,0);
            if (n>0) process_recv(buf,n);
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

    /* Optional command-line pre-fill: <host> <port> <key> */
    if (lpCmdLine && lpCmdLine[0]) {
        char *p = lpCmdLine;
        char *tok;
        while (*p==' ') p++;
        tok=p; while(*p&&*p!=' ') p++;
        if(*p) *p++='\0';
        if(tok[0]) strncpy(g_host,tok,255);
        while(*p==' ') p++;
        tok=p; while(*p&&*p!=' ') p++;
        if(*p) *p++='\0';
        if(tok[0]) g_port=atoi(tok);
        while(*p==' ') p++;
        tok=p; while(*p&&*p!=' ') p++;
        if(*p) *p++='\0';
        if(tok[0]) strncpy(g_key,tok,15);
    }

    g_hinst = hInst;

    if (WSAStartup(MAKEWORD(1,1),&wsd)!=0) {
        MessageBox(NULL,"WSAStartup failed.","Flynn",MB_OK|MB_ICONSTOP);
        return 1;
    }

    if (!hPrev) {
        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc   = WndProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_APPWORKSPACE+1);
        wc.lpszClassName = "FlynnMain";
        RegisterClass(&wc);

        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc   = ConnDlgProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        wc.lpszClassName = "FlynnConnDlg";
        RegisterClass(&wc);
    }

    g_hwnd = CreateWindow("FlynnMain","Flynn  \xe6ldreC2",
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,CW_USEDEFAULT,900,580,
                NULL,NULL,hInst,NULL);
    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd,nCmdShow);
    UpdateWindow(g_hwnd);

    /* Show connect dialog (pre-filled if args provided) */
    if (!show_connect_dialog()) {
        WSACleanup(); return 0;
    }

    do_connect_async();

    while (GetMessage(&msg,NULL,0,0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    do_disconnect();
    if (!hPrev) {
        UnregisterClass("FlynnMain",    hInst);
        UnregisterClass("FlynnConnDlg", hInst);
    }
    WSACleanup();
    return (int)msg.wParam;
}
