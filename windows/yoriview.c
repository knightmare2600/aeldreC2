/*
 * yoriview.c  --  AeldreC2  --  Yori Remote Screen Viewer (operator side)
 *
 * Internal codename: THE_UNIVERSAL
 *
 * Named for Blur's 1995 single "The Universal" — the music video
 * stages Damon Albarn and the band as droogs lifted straight from
 * Kubrick's adaptation of A Clockwork Orange.  That's the same
 * Malcolm McDowell / Alex DeLarge likeness used as yoriview's icon
 * (yoriview.png / yoriview.ico), making the whole thing a neat loop:
 * Yori server is named for the Tron character, the viewer is the eye
 * watching through the screen, the icon is Alex staring back.
 *
 * Connects to a yori_srv running on a target machine and displays its
 * screen.  Mouse clicks and keystrokes are forwarded to the target.
 *
 * Win32 GUI app — runs on the OPERATOR's machine (Win95 / NT 4+ / 2000+).
 *
 * Usage:
 *   yoriview.exe <host> [<port>]
 *   yoriview.exe          (shows connect dialog)
 *
 * Build:
 *   wcl386 -bt=nt -l=nt_win -za99 -ox -D_WIN32 yoriview.c wsock32.lib
 */

#define THE_UNIVERSAL   /* internal codename */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "aeldre_theme.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define APP_CLASS    "YoriView"
#define APP_TITLE    "Yori  \xe6ldreC2  Remote View"

#define IDC_HOST_ED  200
#define IDC_PORT_ED  201
#define IDC_CONN_BTN 202

#define WM_YV_SOCK   (WM_APP + 1)
#define WM_YV_DNS    (WM_APP + 2)

#define ST_IDLE      0
#define ST_RESOLVING 1
#define ST_CONN      2
#define ST_AWAIT_INFO 3
#define ST_LIVE      4

#ifndef MAXGETHOSTSTRUCT
#define MAXGETHOSTSTRUCT 1024
#endif

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hinst    = NULL;
static HWND      g_hwnd     = NULL;
static int       g_theme    = 0;
static HBRUSH    g_bg_brush = NULL;
static SOCKET    g_sock  = INVALID_SOCKET;
static int       g_state = ST_IDLE;
static char      g_host[256] = "";
static int       g_port = 5353;

static HANDLE    g_dns_task = NULL;
static char      g_dns_buf[MAXGETHOSTSTRUCT];

static int       g_srv_w = 0, g_srv_h = 0, g_srv_bpp = 0;
static DWORD     g_srv_bytes = 0;

/* Decoded previous frame (XOR accumulator on viewer side) */
static BYTE     *g_frame_cur  = NULL;
static BYTE     *g_frame_prev = NULL;
static DWORD     g_frame_recv = 0;   /* bytes of RLE data received so far */
static DWORD     g_frame_need = 0;   /* total bytes expected in current FRAME */
static BYTE     *g_rle_accum  = NULL;
static int       g_in_frame   = 0;

/* Scale factor: display remote screen scaled down to fit our window */
static float     g_scale_x = 1.0f, g_scale_y = 1.0f;
static int       g_view_w = 800, g_view_h = 600;

/* Receive line buffer */
static char  g_linebuf[1024];
static int   g_linelen = 0;

/* ------------------------------------------------------------------ */
/* Decode delta-RLE frame                                              */
/* ------------------------------------------------------------------ */

static void apply_rle_frame(const BYTE *rle, DWORD rle_len)
{
    DWORD i = 0, pos = 0;
    if (!g_frame_cur || !g_frame_prev) return;

    while (i + 1 < rle_len && pos < g_srv_bytes) {
        BYTE count = rle[i++];
        BYTE val   = rle[i++];
        BYTE runs  = count ? count : 255;
        DWORD j;
        for (j = 0; j < runs && pos < g_srv_bytes; j++, pos++)
            g_frame_cur[pos] = g_frame_prev[pos] ^ val;
    }
    /* Swap */
    { BYTE *t = g_frame_prev; g_frame_prev = g_frame_cur; g_frame_cur = t; }
}

/* ------------------------------------------------------------------ */
/* Render current frame to window                                      */
/* ------------------------------------------------------------------ */

static void render_frame(HDC hdc)
{
    BITMAPINFO bmi;
    if (!g_frame_prev || g_srv_w <= 0 || g_srv_h <= 0) return;

    memset(&bmi, 0, sizeof(bmi));
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = g_srv_w;
    bmi.bmiHeader.biHeight      = -g_srv_h;  /* top-down */
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = (WORD)(g_srv_bpp);
    bmi.bmiHeader.biCompression = BI_RGB;

    /* Scale to our window */
    StretchDIBits(hdc,
                  0, 0, g_view_w, g_view_h,
                  0, 0, g_srv_w,  g_srv_h,
                  g_frame_prev, &bmi, DIB_RGB_COLORS, SRCCOPY);
}

/* ------------------------------------------------------------------ */
/* Send a line to the server                                           */
/* ------------------------------------------------------------------ */

static void srv_send(const char *line)
{
    if (g_sock != INVALID_SOCKET)
        send(g_sock, line, lstrlen(line), 0);
}

/* ------------------------------------------------------------------ */
/* Translate window coordinates → server coordinates                  */
/* ------------------------------------------------------------------ */

static int map_x(int wx) { return (g_srv_w > 0) ? (wx * g_srv_w / g_view_w) : wx; }
static int map_y(int wy) { return (g_srv_h > 0) ? (wy * g_srv_h / g_view_h) : wy; }

/* ------------------------------------------------------------------ */
/* Process a text line from the server                                 */
/* ------------------------------------------------------------------ */

static void process_server_line(const char *line)
{
    if (strncmp(line, "INFO ", 5) == 0) {
        int w, h, bpp;
        if (sscanf(line + 5, "%d %d %d", &w, &h, &bpp) == 3) {
            DWORD bytes = (DWORD)(w * h * (bpp / 8));
            g_srv_w = w; g_srv_h = h; g_srv_bpp = bpp;
            g_srv_bytes = bytes;
            /* Allocate frame buffers */
            if (g_frame_cur)  { GlobalFree((HGLOBAL)g_frame_cur);  g_frame_cur  = NULL; }
            if (g_frame_prev) { GlobalFree((HGLOBAL)g_frame_prev); g_frame_prev = NULL; }
            if (g_rle_accum)  { GlobalFree((HGLOBAL)g_rle_accum);  g_rle_accum  = NULL; }
            g_frame_cur  = (BYTE *)GlobalAlloc(GPTR, bytes);
            g_frame_prev = (BYTE *)GlobalAlloc(GPTR, bytes);
            g_rle_accum  = (BYTE *)GlobalAlloc(GPTR, bytes * 2 + 4096);
            g_state = ST_LIVE;
            {
                char title[256];
                wsprintf(title, "Yori  \xe6ldreC2  %s  (%dx%d %dbpp)",
                         g_host, w, h, bpp);
                SetWindowText(g_hwnd, title);
            }
            /* Force immediate repaint so the window stops showing "Connecting..." */
            InvalidateRect(g_hwnd, NULL, TRUE);
        }
    } else if (strncmp(line, "FRAME ", 6) == 0) {
        g_frame_need = (DWORD)atol(line + 6);
        g_frame_recv = 0;
        g_in_frame   = 1;
    } else if (strncmp(line, "CURSOR ", 7) == 0) {
        /* Cursor position — we could draw a crosshair, skip for now */
    }
}

/* ------------------------------------------------------------------ */
/* Process received data (mix of text lines and binary FRAME payloads) */
/* ------------------------------------------------------------------ */

static void process_recv(const char *buf, int len)
{
    int i = 0;
    while (i < len) {
        if (g_in_frame) {
            /* Binary frame data */
            DWORD avail = (DWORD)(len - i);
            DWORD need  = g_frame_need - g_frame_recv;
            DWORD take  = (avail < need) ? avail : need;
            if (g_rle_accum)
                memcpy(g_rle_accum + g_frame_recv, buf + i, take);
            g_frame_recv += take;
            i += (int)take;
            if (g_frame_recv >= g_frame_need) {
                if (g_rle_accum)
                    apply_rle_frame(g_rle_accum, g_frame_recv);
                g_in_frame = 0;
                InvalidateRect(g_hwnd, NULL, FALSE);
            }
        } else {
            /* Text line */
            char c = buf[i++];
            if (c == '\r') continue;
            if (g_linelen < (int)sizeof(g_linebuf) - 1)
                g_linebuf[g_linelen++] = c;
            if (c == '\n') {
                g_linebuf[g_linelen] = '\0';
                if (g_linelen > 0 && g_linebuf[g_linelen-1]=='\n') g_linebuf[--g_linelen]='\0';
                process_server_line(g_linebuf);
                g_linelen = 0;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Connect                                                             */
/* ------------------------------------------------------------------ */

static void do_connect(void)
{
    unsigned long ip;
    g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_sock == INVALID_SOCKET) return;

    ip = inet_addr(g_host);
    if (ip != INADDR_NONE) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET; addr.sin_addr.s_addr = ip;
        addr.sin_port   = htons((unsigned short)g_port);
        WSAAsyncSelect(g_sock, g_hwnd, WM_YV_SOCK, FD_CONNECT|FD_READ|FD_CLOSE);
        connect(g_sock, (struct sockaddr *)&addr, sizeof(addr));
        g_state = ST_CONN;
    } else {
        g_state = ST_RESOLVING;
        g_dns_task = WSAAsyncGetHostByName(g_hwnd, WM_YV_DNS,
                                           g_host, g_dns_buf, sizeof(g_dns_buf));
    }
}

static void do_disconnect(void)
{
    if (g_sock != INVALID_SOCKET) {
        WSAAsyncSelect(g_sock, g_hwnd, 0, 0);
        closesocket(g_sock); g_sock = INVALID_SOCKET;
    }
    g_state     = ST_IDLE;
    g_in_frame  = 0;
    g_linelen   = 0;
    SetWindowText(g_hwnd, APP_TITLE "  [disconnected]");
}

/* ------------------------------------------------------------------ */
/* Connect dialog                                                      */
/* ------------------------------------------------------------------ */

static HWND g_cd_host = NULL, g_cd_port = NULL;
static HWND g_cdlg    = NULL;
static int  g_cdlg_ok = 0;

static LRESULT CALLBACK ConnDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND hw; int y = 12;
        g_theme    = aeldre_theme_load();
        g_bg_brush = CreateSolidBrush(g_aeldre_themes[g_theme].bg);
        hw = CreateWindow("STATIC","Target host:", WS_CHILD|WS_VISIBLE|SS_LEFT, 8,y+3,100,18,hwnd,NULL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        g_cd_host = CreateWindow("EDIT",g_host[0]?g_host:"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 112,y,200,22,hwnd,(HMENU)IDC_HOST_ED,g_hinst,NULL);
        SendMessage(g_cd_host,WM_SETFONT,(WPARAM)hf,FALSE);
        y=42;
        hw = CreateWindow("STATIC","Port:", WS_CHILD|WS_VISIBLE|SS_LEFT, 8,y+3,100,18,hwnd,NULL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        {
            char pb[16]; wsprintf(pb,"%d",g_port);
            g_cd_port = CreateWindow("EDIT",pb, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_NUMBER, 112,y,80,22,hwnd,(HMENU)IDC_PORT_ED,g_hinst,NULL);
            SendMessage(g_cd_port,WM_SETFONT,(WPARAM)hf,FALSE);
        }
        y=76;
        hw=CreateWindow("BUTTON","Connect",WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 60,y,100,26,hwnd,(HMENU)IDC_CONN_BTN,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        hw=CreateWindow("BUTTON","Cancel",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 172,y,100,26,hwnd,(HMENU)IDCANCEL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        SetFocus(g_cd_host);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp)==IDCANCEL) { g_cdlg_ok=0; DestroyWindow(hwnd); return 0; }
        if (LOWORD(wp)==IDC_CONN_BTN) {
            char pb[16];
            GetWindowText(g_cd_host, g_host, 255);
            GetWindowText(g_cd_port, pb, 15);
            g_port = atoi(pb);
            if (!g_host[0] || g_port<=0) {
                MessageBox(hwnd,"Please fill in host and port.","Yori",MB_OK|MB_ICONWARNING);
                return 0;
            }
            g_cdlg_ok=1; DestroyWindow(hwnd); return 0;
        }
        return 0;
    case WM_CLOSE: g_cdlg_ok=0; DestroyWindow(hwnd); return 0;
    case WM_DESTROY: g_cdlg=NULL; if (!g_cdlg_ok) PostQuitMessage(0); return 0;
    case WM_ERASEBKGND: {
        HDC hdc=(HDC)wp; RECT rc;
        GetClientRect(hwnd,&rc); FillRect(hdc,&rc,g_bg_brush); return 1;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc=(HDC)wp; const AeldreTheme *t=&g_aeldre_themes[g_theme];
        SetTextColor(hdc,t->body); SetBkColor(hdc,t->bg); return (LRESULT)g_bg_brush;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc=(HDC)wp; const AeldreTheme *t=&g_aeldre_themes[g_theme];
        SetTextColor(hdc,t->body); SetBkColor(hdc,t->bg); return (LRESULT)g_bg_brush;
    }
    case WM_CTLCOLORBTN:
        SetBkColor((HDC)wp,g_aeldre_themes[g_theme].bg); return (LRESULT)g_bg_brush;
    }
    return DefWindowProc(hwnd,msg,wp,lp);
}

static int show_connect_dialog(void)
{
    MSG msg; RECT sr; int sw,sh,dw,dh;
    g_cdlg_ok = 0;
    g_cdlg = CreateWindowEx(WS_EX_DLGMODALFRAME,"YoriViewConnDlg",
                             "Yori  \xe6ldreC2  \x97  Connect to Target",
                             WS_POPUP|WS_CAPTION|WS_SYSMENU, 0,0,332,118,
                             g_hwnd,NULL,g_hinst,NULL);
    if (!g_cdlg) return 0;
    SystemParametersInfo(SPI_GETWORKAREA,0,&sr,0);
    sw=sr.right-sr.left; sh=sr.bottom-sr.top;
    { RECT dr; GetWindowRect(g_cdlg,&dr); dw=dr.right-dr.left; dh=dr.bottom-dr.top; }
    SetWindowPos(g_cdlg,HWND_TOP,sr.left+(sw-dw)/2,sr.top+(sh-dh)/2,0,0,SWP_NOSIZE);
    ShowWindow(g_cdlg,SW_SHOW);
    while (g_cdlg) {
        if (!GetMessage(&msg,NULL,0,0)) { g_cdlg_ok=0; break; }
        if (!IsDialogMessage(g_cdlg,&msg)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    }
    return g_cdlg_ok;
}

/* ------------------------------------------------------------------ */
/* Main window procedure                                               */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_SIZE:
        g_view_w = (int)LOWORD(lp);
        g_view_h = (int)HIWORD(lp);
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        if (g_state == ST_LIVE)
            render_frame(dc);
        else {
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(dc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
            SetTextColor(dc, RGB(0, 200, 0));
            SetBkMode(dc, TRANSPARENT);
            DrawText(dc,
                     g_state == ST_IDLE ? "Not connected  (File > Connect)" :
                     g_state == ST_RESOLVING ? "Resolving..." :
                     "Connecting...",
                     -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }

    /* Forward mouse to server */
    case WM_MOUSEMOVE: {
        char line[64];
        if (g_state != ST_LIVE) break;
        wsprintf(line, "MOVE %d %d\n", map_x(LOWORD(lp)), map_y(HIWORD(lp)));
        srv_send(line);
        return 0;
    }
    case WM_LBUTTONDOWN: { char l[64]; wsprintf(l,"DOWN %d %d 1\n",map_x(LOWORD(lp)),map_y(HIWORD(lp))); srv_send(l); SetCapture(hwnd); return 0; }
    case WM_LBUTTONUP:   { char l[64]; wsprintf(l,"UP %d %d 1\n",  map_x(LOWORD(lp)),map_y(HIWORD(lp))); srv_send(l); ReleaseCapture(); return 0; }
    case WM_RBUTTONDOWN: { char l[64]; wsprintf(l,"DOWN %d %d 2\n",map_x(LOWORD(lp)),map_y(HIWORD(lp))); srv_send(l); return 0; }
    case WM_RBUTTONUP:   { char l[64]; wsprintf(l,"UP %d %d 2\n",  map_x(LOWORD(lp)),map_y(HIWORD(lp))); srv_send(l); return 0; }

    /* Forward keyboard to server */
    case WM_KEYDOWN: { char l[32]; wsprintf(l,"KEY %d 1\n",(int)wp); srv_send(l); return 0; }
    case WM_KEYUP:   { char l[32]; wsprintf(l,"KEY %d 0\n",(int)wp); srv_send(l); return 0; }
    case WM_CHAR:    {
        if (g_state == ST_LIVE && wp >= 0x20) {
            char l[16]; l[0]='T'; l[1]='Y'; l[2]='P'; l[3]='E'; l[4]=' ';
            l[5]=(char)wp; l[6]='\n'; l[7]='\0';
            srv_send(l);
        }
        return 0;
    }

    /* Menu */
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case 1001: /* File > Connect */
            if (show_connect_dialog()) do_connect();
            break;
        case 1002: /* File > Disconnect */
            srv_send("QUIT\n");
            do_disconnect();
            break;
        case 1003: /* File > Exit */
            srv_send("QUIT\n");
            DestroyWindow(hwnd);
            break;
        }
        return 0;

    /* Network events */
    case WM_YV_DNS: {
        struct hostent *he; struct sockaddr_in addr;
        int dns_err = WSAGETASYNCERROR(lp);
        g_dns_task = NULL;
        if (dns_err) { do_disconnect(); break; }
        he = (struct hostent *)g_dns_buf;
        memset(&addr,0,sizeof(addr));
        addr.sin_family=AF_INET; addr.sin_port=htons((unsigned short)g_port);
        memcpy(&addr.sin_addr,he->h_addr,he->h_length);
        WSAAsyncSelect(g_sock,hwnd,WM_YV_SOCK,FD_CONNECT|FD_READ|FD_CLOSE);
        connect(g_sock,(struct sockaddr*)&addr,sizeof(addr));
        g_state=ST_CONN;
        return 0;
    }

    case WM_YV_SOCK: {
        int event = WSAGETSELECTEVENT(lp);
        int err   = WSAGETSELECTERROR(lp);
        char buf[8192]; int n;
        if (err) { do_disconnect(); return 0; }
        if (event==FD_CONNECT) { g_state=ST_AWAIT_INFO; return 0; }
        if (event==FD_CLOSE)   { do_disconnect(); return 0; }
        if (event==FD_READ) {
            n = recv(g_sock, buf, sizeof(buf)-1, 0);
            if (n>0) process_recv(buf, n);
        }
        return 0;
    }

    case WM_ERASEBKGND:
        if (g_bg_brush) {
            HDC hdc=(HDC)wp; RECT rc;
            GetClientRect(hwnd,&rc); FillRect(hdc,&rc,g_bg_brush); return 1;
        }
        return 0;
    case WM_CLOSE:
        srv_send("QUIT\n");
        do_disconnect();
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        if (g_bg_brush) { DeleteObject(g_bg_brush); g_bg_brush = NULL; }
        if (g_frame_cur)  GlobalFree((HGLOBAL)g_frame_cur);
        if (g_frame_prev) GlobalFree((HGLOBAL)g_frame_prev);
        if (g_rle_accum)  GlobalFree((HGLOBAL)g_rle_accum);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* WinMain                                                             */
/* ------------------------------------------------------------------ */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nCmdShow)
{
    WSADATA  wsa;
    WNDCLASS wc;
    MSG      msg;
    HMENU    mb, mf;

    (void)hPrev;
    g_hinst = hInst;

    /* Parse optional "host [port]" from command line */
    if (lpCmd && lpCmd[0]) {
        char *p = lpCmd;
        char *tok;
        while (*p==' ') p++;
        tok=p; while(*p&&*p!=' ') p++;
        if (*p) *p++='\0';
        if (tok[0]) lstrcpyn(g_host, tok, 255);
        while(*p==' ') p++;
        if (*p) g_port = atoi(p);
    }

    if (WSAStartup(MAKEWORD(1,1),&wsa)!=0) {
        MessageBox(NULL,"WSAStartup failed.","Yori",MB_OK|MB_ICONSTOP);
        return 1;
    }

    if (!hPrev) {
        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc=WndProc; wc.hInstance=hInst;
        wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.hCursor=LoadCursor(NULL,IDC_CROSS);
        wc.hIcon=LoadIcon(hInst,MAKEINTRESOURCE(1));
        wc.lpszClassName=APP_CLASS;
        RegisterClass(&wc);

        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc=ConnDlgProc; wc.hInstance=hInst;
        wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
        wc.hCursor=LoadCursor(NULL,IDC_ARROW);
        wc.lpszClassName="YoriViewConnDlg";
        RegisterClass(&wc);
    }

    mb = CreateMenu(); mf = CreatePopupMenu();
    AppendMenu(mf, MF_STRING, 1001, "&Connect...");
    AppendMenu(mf, MF_STRING, 1002, "&Disconnect");
    AppendMenu(mf, MF_SEPARATOR, 0, NULL);
    AppendMenu(mf, MF_STRING, 1003, "E&xit");
    AppendMenu(mb, MF_POPUP, (UINT_PTR)mf, "&File");

    g_hwnd = CreateWindow(APP_CLASS, APP_TITLE,
                          WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                          CW_USEDEFAULT, CW_USEDEFAULT, 900, 700,
                          NULL, mb, hInst, NULL);
    if (!g_hwnd) { WSACleanup(); return 1; }

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    /* Auto-connect if host given on command line */
    if (g_host[0]) {
        do_connect();
    } else {
        if (!show_connect_dialog()) { DestroyWindow(g_hwnd); WSACleanup(); return 0; }
        do_connect();
    }

    while (GetMessage(&msg,NULL,0,0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    do_disconnect();
    if (!hPrev) {
        UnregisterClass(APP_CLASS,   hInst);
        UnregisterClass("YoriViewConnDlg", hInst);
    }
    WSACleanup();
    return 0;
}
