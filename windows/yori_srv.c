/*
 * yori_srv.c  --  AeldreC2  --  Remote Screen & Control Server
 *
 * Captures the local screen and streams it to a connected viewer.
 * Receives mouse and keyboard events from the viewer and injects them.
 *
 * Targets:
 *   yori16.exe  -- Windows 3.1 / WFW 3.11 (Win16, no Win32s required)
 *                  Single-threaded async model: WM_TIMER + WSAAsyncSelect
 *   yori32.exe  -- Windows 3.11+Win32s, Windows 95, NT 3.1+
 *                  Same model, but with 24bpp capture and delta encoding
 *
 * Build (Win16):
 *   wcc -ml -bt=windows -zu -s -DYORI_WIN16 -I/opt/watcom/h/win yori_srv.c
 *   wlink system windows name yori16.exe file yori_srv.obj library winsock.lib
 *
 * Build (Win32s/Win32):
 *   wcl386 -bt=nt -l=nt_win -za99 -ox -D_WIN32 -DYORI_WIN32 yori_srv.c wsock32.lib
 *
 * Protocol (line-oriented, binary payload after header):
 *   Server → Client:  INFO <W> <H> <bpp>\n
 *   Server → Client:  FRAME <len>\n <len bytes of delta-encoded screen>
 *   Server → Client:  CURSOR <x> <y>\n
 *   Client → Server:  MOVE <x> <y>\n
 *   Client → Server:  DOWN <x> <y> <btn>\n      btn=1(left) 2(right) 3(mid)
 *   Client → Server:  UP   <x> <y> <btn>\n
 *   Client → Server:  KEY  <vk> <down>\n         down=1 pressed, 0 released
 *   Client → Server:  TYPE <char>\n              ASCII char to type
 *   Client → Server:  QUIT\n
 *
 * Delta encoding: each frame is (current XOR previous) → RLE zeros suppressed.
 * Format: <count> <byte>  where count=0 means 256 unchanged bytes,
 *         count=1..255 means that many copies of <byte>.
 * Receiver applies XOR against its own previous frame to reconstruct.
 */

#ifndef YORI_WIN16
#  if defined(__WINDOWS__) && !defined(WIN32)
#    define YORI_WIN16
#  endif
#endif

#ifdef YORI_WIN16
#  include <windows.h>
#  include <winsock.h>
#  include <string.h>
#  include <stdlib.h>
#  include <stdio.h>
#  ifndef MAKEWORD
#    define MAKEWORD(a,b) ((WORD)(((BYTE)(a))|(((WORD)((BYTE)(b)))<<8)))
#  endif
#  ifndef SHORT
#    define SHORT short
#  endif
#  ifndef WM_APP
#    define WM_APP 0x8000
#  endif
   /* mouse_event / keybd_event prototypes absent from some Win16 headers */
   void WINAPI mouse_event(DWORD, DWORD, DWORD, DWORD, DWORD);
   void WINAPI keybd_event(BYTE, BYTE, DWORD, DWORD);
   /* Win16 does not have MOUSEEVENTF_* in older headers */
#  ifndef MOUSEEVENTF_MOVE
#    define MOUSEEVENTF_MOVE      0x0001
#    define MOUSEEVENTF_LEFTDOWN  0x0002
#    define MOUSEEVENTF_LEFTUP    0x0004
#    define MOUSEEVENTF_RIGHTDOWN 0x0008
#    define MOUSEEVENTF_RIGHTUP   0x0010
#    define MOUSEEVENTF_MIDDLEDOWN 0x0020
#    define MOUSEEVENTF_MIDDLEUP   0x0040
#    define MOUSEEVENTF_ABSOLUTE  0x8000
#  endif
#  ifndef KEYEVENTF_KEYUP
#    define KEYEVENTF_KEYUP 0x0002
#  endif
#  define FRAME_BPP    1      /* 8bpp palette for Win16 */
#else
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock.h>
#  include <string.h>
#  include <stdlib.h>
#  include <stdio.h>
#  define FRAME_BPP    3      /* 24bpp BGR for Win32 */
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define YORI_PORT_DEFAULT 5353
#define CAPTURE_TIMER_ID  1
#define CAPTURE_INTERVAL  150    /* ms between frames */
#define MAX_FRAME_BYTES   (1280 * 1024 * FRAME_BPP)   /* max supported res */
#define RLE_BUF_EXTRA     (MAX_FRAME_BYTES / 2 + 4096)

#define WM_YORI_SOCK   (WM_APP + 1)
#define WM_YORI_ACCEPT (WM_APP + 2)

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hinst  = NULL;
static HWND      g_hwnd   = NULL;
static SOCKET    g_listen = INVALID_SOCKET;
static SOCKET    g_client = INVALID_SOCKET;
static int       g_port   = YORI_PORT_DEFAULT;
static int       g_w      = 0, g_h = 0;

static BYTE *g_prev_frame  = NULL;
static BYTE *g_cur_frame   = NULL;
static BYTE *g_rle_buf     = NULL;
static DWORD g_frame_bytes = 0;

static char  g_linebuf[1024];
static int   g_linelen = 0;

/* ------------------------------------------------------------------ */
/* Screen capture                                                      */
/* ------------------------------------------------------------------ */

#ifdef YORI_WIN16
static HDC     g_hdc_mem  = NULL;
static HBITMAP g_hbm      = NULL;
static HBITMAP g_hbm_old  = NULL;

static int screen_init(void)
{
    HDC hdc_scr;
    g_w = GetSystemMetrics(SM_CXSCREEN);
    g_h = GetSystemMetrics(SM_CYSCREEN);
    g_frame_bytes = (DWORD)g_w * g_h;  /* 8bpp */
    hdc_scr = GetDC(NULL);
    g_hdc_mem = CreateCompatibleDC(hdc_scr);
    g_hbm = CreateCompatibleBitmap(hdc_scr, g_w, g_h);
    ReleaseDC(NULL, hdc_scr);
    g_hbm_old = (HBITMAP)SelectObject(g_hdc_mem, g_hbm);
    return 1;
}

static int screen_capture(BYTE *buf)
{
    /* Win16: capture via BitBlt, then GetBitmapBits */
    HDC hdc_scr = GetDC(NULL);
    BitBlt(g_hdc_mem, 0, 0, g_w, g_h, hdc_scr, 0, 0, SRCCOPY);
    ReleaseDC(NULL, hdc_scr);
    GetBitmapBits(g_hbm, (DWORD)g_frame_bytes, (LPVOID)buf);
    return 1;
}

#else   /* Win32 */

static HDC     g_hdc_mem  = NULL;
static HBITMAP g_hbm      = NULL;
static HBITMAP g_hbm_old  = NULL;

static int screen_init(void)
{
    HDC    hdc_scr;
    g_w = GetSystemMetrics(SM_CXSCREEN);
    g_h = GetSystemMetrics(SM_CYSCREEN);
    g_frame_bytes = (DWORD)(g_w * g_h * 3);   /* 24bpp */
    hdc_scr = GetDC(NULL);
    g_hdc_mem = CreateCompatibleDC(hdc_scr);
    g_hbm     = CreateCompatibleBitmap(hdc_scr, g_w, g_h);
    ReleaseDC(NULL, hdc_scr);
    g_hbm_old = (HBITMAP)SelectObject(g_hdc_mem, g_hbm);
    return 1;
}

static int screen_capture(BYTE *buf)
{
    HDC       hdc_scr = GetDC(NULL);
    BITMAPINFO bmi;
    BitBlt(g_hdc_mem, 0, 0, g_w, g_h, hdc_scr, 0, 0, SRCCOPY);
    ReleaseDC(NULL, hdc_scr);
    memset(&bmi, 0, sizeof(bmi));
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = g_w;
    bmi.bmiHeader.biHeight      = -g_h;  /* top-down */
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 24;
    bmi.bmiHeader.biCompression = BI_RGB;
    GetDIBits(g_hdc_mem, g_hbm, 0, g_h, buf, &bmi, DIB_RGB_COLORS);
    return 1;
}
#endif

/* ------------------------------------------------------------------ */
/* Simple XOR-delta + RLE encoder                                      */
/* ------------------------------------------------------------------ */

static DWORD encode_frame(const BYTE *cur, const BYTE *prev, DWORD len, BYTE *out)
{
    DWORD i = 0, out_pos = 0;
    while (i < len) {
        BYTE  xb  = cur[i] ^ prev[i];
        BYTE  run = 1;
        while (run < 255 && i + run < len && (cur[i+run] ^ prev[i+run]) == xb)
            run++;
        out[out_pos++] = run;
        out[out_pos++] = xb;
        i += run;
    }
    return out_pos;
}

/* ------------------------------------------------------------------ */
/* Send a frame to the client                                          */
/* ------------------------------------------------------------------ */

static void send_frame_to_client(void)
{
    DWORD enc_len;
    char  hdr[64];
    int   hlen;

    if (g_client == INVALID_SOCKET) return;
    if (!g_cur_frame || !g_prev_frame || !g_rle_buf) return;

    screen_capture(g_cur_frame);

    enc_len = encode_frame(g_cur_frame, g_prev_frame, g_frame_bytes, g_rle_buf);

    /* Only send if something actually changed (encoder produces all (1,0) if identical) */
    {
        DWORD i, changed = 0;
        for (i = 1; i < enc_len && i < 128; i += 2)
            if (g_rle_buf[i] != 0) { changed = 1; break; }
        if (!changed && enc_len > 0) goto update_prev;
    }

    hlen = wsprintf(hdr, "FRAME %lu\n", enc_len);
    send(g_client, hdr, hlen, 0);
    {
        DWORD sent = 0;
        while (sent < enc_len) {
            int n = send(g_client, (char *)g_rle_buf + sent,
                         (int)(enc_len - sent), 0);
            if (n <= 0) { closesocket(g_client); g_client = INVALID_SOCKET; return; }
            sent += n;
        }
    }

    /* Send cursor position */
    {
        POINT pt;
        char csr[64];
        GetCursorPos(&pt);
        hlen = wsprintf(csr, "CURSOR %d %d\n", pt.x, pt.y);
        send(g_client, csr, hlen, 0);
    }

update_prev:
    /* Swap buffers */
    { BYTE *tmp = g_prev_frame; g_prev_frame = g_cur_frame; g_cur_frame = tmp; }
}

/* ------------------------------------------------------------------ */
/* Input injection                                                     */
/* ------------------------------------------------------------------ */

static void inject_mouse(int x, int y, int btn, int down)
{
    DWORD flags;
    /* Scale to absolute coordinates (0-65535) */
    int ax = (g_w > 0) ? (x * 65535 / g_w) : 0;
    int ay = (g_h > 0) ? (y * 65535 / g_h) : 0;

    SetCursorPos(x, y);
    if (btn == 0) {
        flags = down ? MOUSEEVENTF_LEFTDOWN   : MOUSEEVENTF_LEFTUP;
    } else if (btn == 2) {
        flags = down ? MOUSEEVENTF_RIGHTDOWN  : MOUSEEVENTF_RIGHTUP;
    } else {
        flags = down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
    }
    mouse_event(flags, (DWORD)ax, (DWORD)ay, 0, 0);
}

static void inject_key(int vk, int down)
{
    BYTE scan = (BYTE)MapVirtualKey(vk, 0);
    keybd_event((BYTE)vk, scan, down ? 0 : KEYEVENTF_KEYUP, 0);
}

static void inject_type(char c)
{
    SHORT vks = VkKeyScan(c);
    BYTE  vk  = (BYTE)(vks & 0xFF);
    BYTE  sh  = (BYTE)((vks >> 8) & 0xFF);
    if (sh & 1) { keybd_event(VK_SHIFT, 0x2A, 0, 0); }
    inject_key(vk, 1);
    inject_key(vk, 0);
    if (sh & 1) { keybd_event(VK_SHIFT, 0x2A, KEYEVENTF_KEYUP, 0); }
}

/* ------------------------------------------------------------------ */
/* Process a line received from the client                             */
/* ------------------------------------------------------------------ */

static void process_client_line(const char *line)
{
    int x, y, btn, vk, dn;
    char c;
    if (wsprintf((LPSTR)line, "") < 0) { /* just a trick to use wsprintf */ }

    if (strncmp(line, "MOVE ", 5) == 0) {
        if (sscanf(line + 5, "%d %d", &x, &y) == 2)
            SetCursorPos(x, y);
    } else if (strncmp(line, "DOWN ", 5) == 0) {
        if (sscanf(line + 5, "%d %d %d", &x, &y, &btn) == 3)
            inject_mouse(x, y, btn - 1, 1);
    } else if (strncmp(line, "UP ", 3) == 0) {
        if (sscanf(line + 3, "%d %d %d", &x, &y, &btn) == 3)
            inject_mouse(x, y, btn - 1, 0);
    } else if (strncmp(line, "KEY ", 4) == 0) {
        if (sscanf(line + 4, "%d %d", &vk, &dn) == 2)
            inject_key(vk, dn);
    } else if (strncmp(line, "TYPE ", 5) == 0) {
        if (line[5]) inject_type(line[5]);
    } else if (strcmp(line, "QUIT") == 0) {
        closesocket(g_client);
        g_client = INVALID_SOCKET;
        KillTimer(g_hwnd, CAPTURE_TIMER_ID);
    }
}

static void process_recv(const char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        char c = buf[i];
        if (c == '\r') continue;
        if (g_linelen < (int)sizeof(g_linebuf) - 1)
            g_linebuf[g_linelen++] = c;
        if (c == '\n') {
            g_linebuf[g_linelen] = '\0';
            /* strip trailing newline */
            if (g_linelen > 0 && g_linebuf[g_linelen-1]=='\n') g_linebuf[--g_linelen]='\0';
            if (g_linelen > 0) process_client_line(g_linebuf);
            g_linelen = 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Send initial INFO banner                                            */
/* ------------------------------------------------------------------ */

static void send_info(void)
{
    char info[128];
    int  n = wsprintf(info, "INFO %d %d %d\n", g_w, g_h, FRAME_BPP * 8);
    send(g_client, info, n, 0);
    /* Send first full frame by zeroing previous */
    memset(g_prev_frame, 0, g_frame_bytes);
    send_frame_to_client();
}

/* ------------------------------------------------------------------ */
/* Window procedure                                                    */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK YoriSrvProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_TIMER:
        if ((int)wp == CAPTURE_TIMER_ID && g_client != INVALID_SOCKET)
            send_frame_to_client();
        return 0;

    case WM_YORI_ACCEPT: {
        struct sockaddr_in peer; int plen = sizeof(peer);
        SOCKET cs;
        if (WSAGETSELECTERROR(lp)) break;
        if (WSAGETSELECTEVENT(lp) != FD_ACCEPT) break;
        cs = accept(g_listen, (struct sockaddr *)&peer, &plen);
        if (cs == INVALID_SOCKET) break;
        /* Only one client at a time */
        if (g_client != INVALID_SOCKET) { closesocket(cs); break; }
        g_client = cs;
        WSAAsyncSelect(g_client, hwnd, WM_YORI_SOCK, FD_READ | FD_CLOSE);
        send_info();
        SetTimer(hwnd, CAPTURE_TIMER_ID, CAPTURE_INTERVAL, NULL);
        break;
    }

    case WM_YORI_SOCK: {
        int   event = WSAGETSELECTEVENT(lp);
        int   err   = WSAGETSELECTERROR(lp);
        char  buf[4096]; int n;
        if (err || event == FD_CLOSE) {
            closesocket(g_client); g_client = INVALID_SOCKET;
            KillTimer(hwnd, CAPTURE_TIMER_ID);
            break;
        }
        if (event == FD_READ) {
            n = recv(g_client, buf, sizeof(buf) - 1, 0);
            if (n > 0) process_recv(buf, n);
        }
        break;
    }

    case WM_DESTROY:
        if (g_client != INVALID_SOCKET) { closesocket(g_client); g_client = INVALID_SOCKET; }
        if (g_listen != INVALID_SOCKET) { closesocket(g_listen); g_listen = INVALID_SOCKET; }
        if (g_prev_frame) { GlobalFree((HGLOBAL)g_prev_frame); g_prev_frame = NULL; }
        if (g_cur_frame)  { GlobalFree((HGLOBAL)g_cur_frame);  g_cur_frame  = NULL; }
        if (g_rle_buf)    { GlobalFree((HGLOBAL)g_rle_buf);    g_rle_buf    = NULL; }
#ifdef YORI_WIN16
        if (g_hdc_mem) { SelectObject(g_hdc_mem, g_hbm_old); DeleteObject(g_hbm); DeleteDC(g_hdc_mem); }
#else
        if (g_hdc_mem) { SelectObject(g_hdc_mem, g_hbm_old); DeleteObject(g_hbm); DeleteDC(g_hdc_mem); }
#endif
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* WinMain                                                             */
/* ------------------------------------------------------------------ */

#ifdef YORI_WIN16
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
#else
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
#endif
{
    WSADATA   wsa;
    WNDCLASS  wc;
    MSG       msg;
    struct sockaddr_in addr;

    (void)hPrev; (void)nShow;
    g_hinst = hInst;

    /* Parse optional port from command line */
    if (lpCmd && lpCmd[0]) {
        int p = atoi(lpCmd);
        if (p > 0 && p < 65536) g_port = p;
    }

    if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0) {
        MessageBox(NULL, "WSAStartup failed.", "yori", MB_OK | MB_ICONSTOP);
        return 1;
    }

    /* Allocate frame buffers */
    screen_init();
    g_prev_frame = (BYTE *)GlobalAlloc(GPTR, g_frame_bytes);
    g_cur_frame  = (BYTE *)GlobalAlloc(GPTR, g_frame_bytes);
    g_rle_buf    = (BYTE *)GlobalAlloc(GPTR, g_frame_bytes * 2 + 4096);
    if (!g_prev_frame || !g_cur_frame || !g_rle_buf) {
        MessageBox(NULL, "Out of memory for frame buffers.", "yori", MB_OK | MB_ICONSTOP);
        WSACleanup(); return 1;
    }
    memset(g_prev_frame, 0, g_frame_bytes);

    /* Register invisible window class */
    if (!hPrev) {
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = YoriSrvProc;
        wc.hInstance     = hInst;
        wc.lpszClassName = "YoriSrv";
        RegisterClass(&wc);
    }
    g_hwnd = CreateWindow("YoriSrv", "", WS_OVERLAPPED,
                          0, 0, 0, 0, NULL, NULL, hInst, NULL);
    if (!g_hwnd) { WSACleanup(); return 1; }

    /* Create listen socket */
    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen == INVALID_SOCKET) { DestroyWindow(g_hwnd); WSACleanup(); return 1; }
    { int r = 1; setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, (char *)&r, sizeof(r)); }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((unsigned short)g_port);
    if (bind(g_listen, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(g_listen, 1) != 0) {
        { char m[80]; wsprintf(m, "Cannot listen on port %d.", g_port);
          MessageBox(NULL, m, "yori", MB_OK | MB_ICONSTOP); }
        closesocket(g_listen); DestroyWindow(g_hwnd); WSACleanup(); return 1;
    }
    WSAAsyncSelect(g_listen, g_hwnd, WM_YORI_ACCEPT, FD_ACCEPT);

    /* Tray-style: show a minimal systray message if possible, else nothing visible */
    /* On Win16 / Win32s there's no systray API — just run hidden */
    ShowWindow(g_hwnd, SW_HIDE);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (!hPrev) UnregisterClass("YoriSrv", hInst);
    WSACleanup();
    return 0;
}
