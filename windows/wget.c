/*
 * wget.c  --  Win16/Win32s/Win32 command-line HTTP/HTTPS/FTP downloader
 *
 * Win32: tries WinInet (WININET.DLL) for HTTPS/FTP; falls back to raw
 *        TCP socket for plain HTTP if WinInet is absent (Win32s).
 * Win16: raw Winsock 1.1 HTTP only (no HTTPS, no FTP, Winsock 1.1).
 *
 * Usage:  wget <URL> [-O <outfile>] [-q]
 *
 * Build (Win32s/Win32):
 *   wcl386 -bt=nt -l=nt_win -za99 -ox -D_WIN32 wget.c wsock32.lib
 * Build (Win16):
 *   wcc -ml -bt=windows -zu -s -I/opt/watcom/h/win wget.c
 *   wlink system windows name wget16.exe file wget.obj library winsock.lib
 */

#if defined(__WINDOWS__) && !defined(WIN32)
#  define WGET_WIN16
#endif

#ifdef WGET_WIN16
#  include <windows.h>
#  include <winsock.h>
#  include <stdio.h>
#  include <string.h>
#  include <stdlib.h>
/* Win16 API has no A-suffix variants */
#  define lstrcpyA   lstrcpy
#  define lstrcpynA  lstrcpyn
#  define lstrlenA   lstrlen
#  define lstrcmpA   lstrcmp
#  define wsprintfA  wsprintf
#  ifndef MAKEWORD
#    define MAKEWORD(a,b) ((WORD)(((BYTE)(a))|(((WORD)((BYTE)(b)))<<8)))
#  endif
#else
#  include <windows.h>
#  include <winsock.h>
#  include <stdio.h>
#  include <string.h>
#  include <stdlib.h>
#endif

/* ------------------------------------------------------------------ */
/* Common URL parser                                                    */
/* ------------------------------------------------------------------ */

#define SCHEME_HTTP  1
#define SCHEME_HTTPS 2
#define SCHEME_FTP   3

typedef struct {
    int   scheme;
    char  host[256];
    int   port;
    char  path[1024];
} ParsedURL;

static int parse_url(const char *url, ParsedURL *out)
{
    const char *p = url;
    memset(out, 0, sizeof(*out));

    if (_strnicmp(p, "https://", 8) == 0) {
        out->scheme = SCHEME_HTTPS;
        out->port   = 443;
        p += 8;
    } else if (_strnicmp(p, "http://", 7) == 0) {
        out->scheme = SCHEME_HTTP;
        out->port   = 80;
        p += 7;
    } else if (_strnicmp(p, "ftp://", 6) == 0) {
        out->scheme = SCHEME_FTP;
        out->port   = 21;
        p += 6;
    } else {
        /* assume HTTP */
        out->scheme = SCHEME_HTTP;
        out->port   = 80;
    }

    /* host[:port] */
    {
        const char *slash = strchr(p, '/');
        const char *colon = strchr(p, ':');
        size_t hlen;

        if (slash == NULL) slash = p + strlen(p);

        if (colon && colon < slash) {
            hlen = (size_t)(colon - p);
            out->port = atoi(colon + 1);
        } else {
            hlen = (size_t)(slash - p);
        }
        if (hlen >= sizeof(out->host)) hlen = sizeof(out->host) - 1;
        memcpy(out->host, p, hlen);
        out->host[hlen] = '\0';

        if (*slash == '\0')
            lstrcpyA(out->path, "/");
        else
            lstrcpynA(out->path, slash, sizeof(out->path) - 1);
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Derive output filename from URL path                                 */
/* ------------------------------------------------------------------ */
static void url_to_filename(const char *path, char *buf, int bufsz)
{
    const char *p;
    const char *q;
    int len;

    p = strrchr(path, '/');
    if (p) p++;
    else    p = path;

    /* strip query string */
    q = strchr(p, '?');
    if (q)
        len = (int)(q - p);
    else
        len = (int)strlen(p);

    if (len == 0) {
        lstrcpynA(buf, "index.html", bufsz - 1);
        return;
    }
    if (len >= bufsz) len = bufsz - 1;
    memcpy(buf, p, len);
    buf[len] = '\0';
}

/* ------------------------------------------------------------------ */
/* Progress                                                             */
/* ------------------------------------------------------------------ */
static int  g_quiet   = 0;
static long g_total   = 0;
static long g_done    = 0;

static void progress_print(void)
{
    if (g_quiet) return;
    if (g_total > 0)
        fprintf(stderr, "\r%ld / %ld bytes (%ld%%)",
                g_done, g_total, g_done * 100L / g_total);
    else
        fprintf(stderr, "\r%ld bytes", g_done);
}

/* ------------------------------------------------------------------ */
/* Win16 raw HTTP via Winsock 1.1                                       */
/* ------------------------------------------------------------------ */
#ifdef WGET_WIN16

static HINSTANCE g_winsock_inst = NULL;

typedef int  (PASCAL *PFN_WSAStartup)(WORD, LPWSADATA);
typedef int  (PASCAL *PFN_WSACleanup)(void);
typedef SOCKET (PASCAL *PFN_socket)(int, int, int);
typedef int  (PASCAL *PFN_connect)(SOCKET, const struct sockaddr *, int);
typedef int  (PASCAL *PFN_send)(SOCKET, const char *, int, int);
typedef int  (PASCAL *PFN_recv)(SOCKET, char *, int, int);
typedef int  (PASCAL *PFN_closesocket)(SOCKET);
typedef struct hostent *(PASCAL *PFN_gethostbyname)(const char *);
typedef unsigned long (PASCAL *PFN_inet_addr)(const char *);
typedef u_short (PASCAL *PFN_htons)(u_short);

static PFN_WSAStartup   pfnWSAStartup;
static PFN_WSACleanup   pfnWSACleanup;
static PFN_socket       pfnSocket;
static PFN_connect      pfnConnect;
static PFN_send         pfnSend;
static PFN_recv         pfnRecv;
static PFN_closesocket  pfnClosesocket;
static PFN_gethostbyname pfnGethostbyname;
static PFN_inet_addr    pfnInet_addr;
static PFN_htons        pfnHtons;

static int winsock_load(void)
{
    WSADATA wd;
    g_winsock_inst = LoadLibrary("WINSOCK.DLL");
    if (!g_winsock_inst || (UINT)g_winsock_inst < 32) {
        fprintf(stderr, "wget: cannot load WINSOCK.DLL\n");
        return 0;
    }
    pfnWSAStartup   = (PFN_WSAStartup)  GetProcAddress(g_winsock_inst, "WSAStartup");
    pfnWSACleanup   = (PFN_WSACleanup)  GetProcAddress(g_winsock_inst, "WSACleanup");
    pfnSocket       = (PFN_socket)      GetProcAddress(g_winsock_inst, "socket");
    pfnConnect      = (PFN_connect)     GetProcAddress(g_winsock_inst, "connect");
    pfnSend         = (PFN_send)        GetProcAddress(g_winsock_inst, "send");
    pfnRecv         = (PFN_recv)        GetProcAddress(g_winsock_inst, "recv");
    pfnClosesocket  = (PFN_closesocket) GetProcAddress(g_winsock_inst, "closesocket");
    pfnGethostbyname= (PFN_gethostbyname)GetProcAddress(g_winsock_inst,"gethostbyname");
    pfnInet_addr    = (PFN_inet_addr)   GetProcAddress(g_winsock_inst, "inet_addr");
    pfnHtons        = (PFN_htons)       GetProcAddress(g_winsock_inst, "htons");

    if (!pfnWSAStartup || !pfnSocket || !pfnConnect || !pfnSend ||
        !pfnRecv || !pfnClosesocket || !pfnGethostbyname ||
        !pfnInet_addr || !pfnHtons) {
        fprintf(stderr, "wget: WINSOCK.DLL missing symbols\n");
        return 0;
    }
    if (pfnWSAStartup(MAKEWORD(1, 1), &wd) != 0) {
        fprintf(stderr, "wget: WSAStartup failed\n");
        return 0;
    }
    return 1;
}

static int win16_http_get(const ParsedURL *url, FILE *out)
{
    SOCKET sock;
    struct sockaddr_in sa;
    struct hostent *he;
    char req[1600];
    char buf[2048];
    int  n, in_body = 0;
    char *p;
    char hdr[4096];
    int  hdr_len = 0;

    sock = pfnSocket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "wget: socket() failed\n");
        return 0;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = pfnHtons((u_short)url->port);

    he = pfnGethostbyname(url->host);
    if (he)
        memcpy(&sa.sin_addr, he->h_addr, 4);
    else {
        unsigned long a = pfnInet_addr(url->host);
        if (a == INADDR_NONE) {
            fprintf(stderr, "wget: cannot resolve %s\n", url->host);
            pfnClosesocket(sock);
            return 0;
        }
        sa.sin_addr.s_addr = a;
    }

    if (pfnConnect(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "wget: connect to %s:%d failed\n", url->host, url->port);
        pfnClosesocket(sock);
        return 0;
    }

    wsprintfA(req,
        "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: wget/win16\r\n"
        "Connection: close\r\n\r\n",
        url->path, url->host);
    pfnSend(sock, req, lstrlenA(req), 0);

    /* buffer headers, then stream body */
    while (!in_body) {
        n = pfnRecv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';

        if (hdr_len + n < (int)sizeof(hdr) - 1) {
            memcpy(hdr + hdr_len, buf, n);
            hdr_len += n;
            hdr[hdr_len] = '\0';
        }

        p = strstr(hdr, "\r\n\r\n");
        if (p) {
            /* parse Content-Length */
            char *cl = strstr(hdr, "Content-Length:");
            if (!cl) cl = strstr(hdr, "content-length:");
            if (cl) g_total = atol(cl + 15);

            p += 4;
            /* body bytes already in hdr buffer */
            n = hdr_len - (int)(p - hdr);
            if (n > 0) {
                fwrite(p, 1, n, out);
                g_done += n;
                progress_print();
            }
            in_body = 1;
        }
    }

    while (in_body) {
        n = pfnRecv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        fwrite(buf, 1, n, out);
        g_done += n;
        progress_print();
    }

    pfnClosesocket(sock);
    return 1;
}

int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    char  url_arg[1024]  = "";
    char  out_arg[256]   = "";
    char  fname[256]     = "";
    char  *argv[32];
    int    argc = 0;
    char  *tok;
    FILE  *outf;
    ParsedURL pu;
    int    ok;

    (void)hInst; (void)hPrev; (void)nShow;

    /* tokenize lpCmd */
    {
        static char cmdcopy[1024];
        lstrcpynA(cmdcopy, lpCmd, sizeof(cmdcopy) - 1);
        tok = strtok(cmdcopy, " \t");
        while (tok && argc < 30) {
            argv[argc++] = tok;
            tok = strtok(NULL, " \t");
        }
        argv[argc] = NULL;
    }

    {
        int i;
        for (i = 0; i < argc; i++) {
            if (lstrcmpA(argv[i], "-O") == 0 && i + 1 < argc)
                lstrcpynA(out_arg, argv[++i], sizeof(out_arg) - 1);
            else if (lstrcmpA(argv[i], "-q") == 0)
                g_quiet = 1;
            else if (url_arg[0] == '\0')
                lstrcpynA(url_arg, argv[i], sizeof(url_arg) - 1);
        }
    }

    if (url_arg[0] == '\0') {
        MessageBox(NULL,
            "Usage: wget <URL> [-O filename] [-q]",
            "wget", MB_OK | MB_ICONINFORMATION);
        return 1;
    }

    parse_url(url_arg, &pu);

    if (pu.scheme != SCHEME_HTTP) {
        MessageBox(NULL,
            "wget16: only HTTP is supported (no HTTPS/FTP on Win16)",
            "wget", MB_OK | MB_ICONEXCLAMATION);
        return 1;
    }

    if (out_arg[0] != '\0')
        lstrcpynA(fname, out_arg, sizeof(fname) - 1);
    else
        url_to_filename(pu.path, fname, sizeof(fname));

    if (!winsock_load()) return 1;

    outf = fopen(fname, "wb");
    if (!outf) {
        char msg[512];
        wsprintfA(msg, "wget: cannot open '%s' for writing", fname);
        MessageBox(NULL, msg, "wget", MB_OK | MB_ICONEXCLAMATION);
        pfnWSACleanup();
        return 1;
    }

    if (!g_quiet)
        fprintf(stderr, "Saving to '%s'\n", fname);

    ok = win16_http_get(&pu, outf);
    fclose(outf);

    if (!g_quiet) fprintf(stderr, "\n");

    if (ok && !g_quiet) {
        char msg[512];
        wsprintfA(msg, "Saved %ld bytes to '%s'", g_done, fname);
        MessageBox(NULL, msg, "wget", MB_OK | MB_ICONINFORMATION);
    }

    pfnWSACleanup();
    return ok ? 0 : 1;
}

#else /* Win32 --------------------------------------------------------- */

/* ------------------------------------------------------------------ */
/* Win32: WinInet dynamic load                                          */
/* ------------------------------------------------------------------ */

#define INTERNET_OPEN_TYPE_PRECONFIG 0
#define INTERNET_SERVICE_HTTP        3
#define INTERNET_SERVICE_FTP         1
#define INTERNET_FLAG_RELOAD         0x80000000
#define INTERNET_FLAG_IGNORE_CERT_CN_INVALID   0x00001000
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#define INTERNET_FLAG_SECURE         0x00000800
#define INTERNET_FLAG_PASSIVE        0x08000000
#define INTERNET_FLAG_TRANSFER_BINARY 0x00000002
#define HTTP_QUERY_CONTENT_LENGTH    5
#define HTTP_QUERY_STATUS_CODE       19
#define FTP_TRANSFER_TYPE_BINARY     2

typedef WORD INTERNET_PORT;  /* from wininet.h; defined here to avoid the dependency */

typedef HANDLE (WINAPI *PFN_InternetOpen)(LPCSTR,DWORD,LPCSTR,LPCSTR,DWORD);
typedef HANDLE (WINAPI *PFN_InternetConnect)(HANDLE,LPCSTR,INTERNET_PORT,LPCSTR,LPCSTR,DWORD,DWORD,DWORD);
typedef HANDLE (WINAPI *PFN_HttpOpenRequest)(HANDLE,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPCSTR*,DWORD,DWORD);
typedef BOOL   (WINAPI *PFN_HttpSendRequest)(HANDLE,LPCSTR,DWORD,LPVOID,DWORD);
typedef BOOL   (WINAPI *PFN_HttpQueryInfo)(HANDLE,DWORD,LPVOID,LPDWORD,LPDWORD);
typedef BOOL   (WINAPI *PFN_InternetReadFile)(HANDLE,LPVOID,DWORD,LPDWORD);
typedef BOOL   (WINAPI *PFN_InternetCloseHandle)(HANDLE);
typedef HANDLE (WINAPI *PFN_FtpOpenFile)(HANDLE,LPCSTR,DWORD,DWORD,DWORD);

static HMODULE                g_wininet = NULL;
static PFN_InternetOpen       pfnInternetOpen;
static PFN_InternetConnect    pfnInternetConnect;
static PFN_HttpOpenRequest    pfnHttpOpenRequest;
static PFN_HttpSendRequest    pfnHttpSendRequest;
static PFN_HttpQueryInfo      pfnHttpQueryInfo;
static PFN_InternetReadFile   pfnInternetReadFile;
static PFN_InternetCloseHandle pfnInternetCloseHandle;
static PFN_FtpOpenFile        pfnFtpOpenFile;

static int wininet_load(void)
{
    g_wininet = LoadLibraryA("WININET.DLL");
    if (!g_wininet) return 0;

    pfnInternetOpen       = (PFN_InternetOpen)      GetProcAddress(g_wininet, "InternetOpenA");
    pfnInternetConnect    = (PFN_InternetConnect)   GetProcAddress(g_wininet, "InternetConnectA");
    pfnHttpOpenRequest    = (PFN_HttpOpenRequest)   GetProcAddress(g_wininet, "HttpOpenRequestA");
    pfnHttpSendRequest    = (PFN_HttpSendRequest)   GetProcAddress(g_wininet, "HttpSendRequestA");
    pfnHttpQueryInfo      = (PFN_HttpQueryInfo)     GetProcAddress(g_wininet, "HttpQueryInfoA");
    pfnInternetReadFile   = (PFN_InternetReadFile)  GetProcAddress(g_wininet, "InternetReadFile");
    pfnInternetCloseHandle= (PFN_InternetCloseHandle)GetProcAddress(g_wininet,"InternetCloseHandle");
    pfnFtpOpenFile        = (PFN_FtpOpenFile)       GetProcAddress(g_wininet, "FtpOpenFileA");

    return (pfnInternetOpen && pfnInternetConnect && pfnHttpOpenRequest &&
            pfnHttpSendRequest && pfnInternetReadFile && pfnInternetCloseHandle);
}

/* ------------------------------------------------------------------ */
/* Win32 GUI progress window                                            */
/* ------------------------------------------------------------------ */

#define IDC_URL_LABEL   101
#define IDC_FILE_LABEL  102
#define IDC_PROG_BAR    103
#define IDC_STAT_LABEL  104
#define IDC_STOP_BTN    105
#define WM_WGET_DONE    (WM_USER + 1)
#define WM_WGET_PROGRESS (WM_USER + 2)

static HWND   g_hwnd_prog  = NULL;
static HWND   g_hwnd_url   = NULL;
static HWND   g_hwnd_file  = NULL;
static HWND   g_hwnd_stat  = NULL;
static HWND   g_hwnd_pbar  = NULL;
static HWND   g_hwnd_stop  = NULL;
static int    g_stopped    = 0;
static HINSTANCE g_hinst   = NULL;

static void pbar_update(HWND hwnd, long done, long total)
{
    RECT rc;
    HDC  dc;
    int  w, h, filled;

    GetClientRect(hwnd, &rc);
    w = rc.right - rc.left;
    h = rc.bottom - rc.top;

    dc = GetDC(hwnd);
    if (total > 0)
        filled = (int)((long)w * done / total);
    else
        filled = 0;

    /* filled part */
    rc.right = rc.left + filled;
    SetBkColor(dc, GetSysColor(COLOR_HIGHLIGHT));
    ExtTextOut(dc, 0, 0, ETO_OPAQUE, &rc, "", 0, NULL);
    /* unfilled part */
    rc.left  = filled;
    rc.right = w;
    SetBkColor(dc, GetSysColor(COLOR_BTNFACE));
    ExtTextOut(dc, 0, 0, ETO_OPAQUE, &rc, "", 0, NULL);

    ReleaseDC(hwnd, dc);
}

static LRESULT CALLBACK ProgWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        g_hwnd_url  = CreateWindow("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            8, 8, 380, 16, hwnd, (HMENU)IDC_URL_LABEL,  g_hinst, NULL);
        g_hwnd_file = CreateWindow("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            8, 28, 380, 16, hwnd, (HMENU)IDC_FILE_LABEL, g_hinst, NULL);
        g_hwnd_pbar = CreateWindow("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT | WS_BORDER,
            8, 52, 380, 16, hwnd, (HMENU)IDC_PROG_BAR,  g_hinst, NULL);
        g_hwnd_stat = CreateWindow("STATIC", "Connecting...",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            8, 76, 380, 16, hwnd, (HMENU)IDC_STAT_LABEL, g_hinst, NULL);
        g_hwnd_stop = CreateWindow("BUTTON", "Stop",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            160, 100, 80, 24, hwnd, (HMENU)IDC_STOP_BTN, g_hinst, NULL);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wp) == IDC_STOP_BTN)
            g_stopped = 1;
        return 0;

    case WM_WGET_PROGRESS: {
        char stat[128];
        long done  = (long)wp;
        long total = (long)lp;
        pbar_update(g_hwnd_pbar, done, total);
        if (total > 0)
            wsprintfA(stat, "%ld / %ld bytes (%ld%%)",
                     done, total, done * 100L / total);
        else
            wsprintfA(stat, "%ld bytes received", done);
        SetWindowText(g_hwnd_stat, stat);
        return 0;
    }

    case WM_WGET_DONE:
        if (wp) {
            char msg[256];
            wsprintfA(msg, "Done: %ld bytes", (long)lp);
            SetWindowText(g_hwnd_stat, msg);
        } else {
            SetWindowText(g_hwnd_stat, g_stopped ? "Stopped." : "Error.");
        }
        EnableWindow(g_hwnd_stop, FALSE);
        SetWindowText(g_hwnd_stop, "Close");
        EnableWindow(g_hwnd_stop, TRUE);
        /* re-wire Stop button to close */
        SetWindowLong(g_hwnd_stop, GWL_ID, IDOK);
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static void pump_messages(void)
{
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

/* ------------------------------------------------------------------ */
/* Win32 raw TCP HTTP fallback (no WinInet)                             */
/* ------------------------------------------------------------------ */

static int raw_http_get(const ParsedURL *url, FILE *outf)
{
    WSADATA wd;
    SOCKET  sock;
    struct sockaddr_in sa;
    struct hostent *he;
    char req[1600], buf[4096];
    int  n, in_body = 0;
    char hdr[8192];
    int  hdr_len = 0;

    if (WSAStartup(MAKEWORD(1, 1), &wd) != 0) return 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) { WSACleanup(); return 0; }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)url->port);

    he = gethostbyname(url->host);
    if (he)
        memcpy(&sa.sin_addr, he->h_addr, 4);
    else {
        unsigned long a = inet_addr(url->host);
        if (a == INADDR_NONE) { closesocket(sock); WSACleanup(); return 0; }
        sa.sin_addr.s_addr = a;
    }

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        closesocket(sock); WSACleanup(); return 0;
    }

    wsprintfA(req,
        "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: wget/win32s\r\n"
        "Connection: close\r\n\r\n",
        url->path, url->host);
    send(sock, req, lstrlenA(req), 0);

    while (!in_body) {
        n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        if (hdr_len + n < (int)sizeof(hdr) - 1) {
            memcpy(hdr + hdr_len, buf, n);
            hdr_len += n;
            hdr[hdr_len] = '\0';
        }
        {
            char *p = strstr(hdr, "\r\n\r\n");
            if (p) {
                char *cl = strstr(hdr, "Content-Length:");
                if (!cl) cl = strstr(hdr, "content-length:");
                if (cl) g_total = atol(cl + 15);
                p += 4;
                n = hdr_len - (int)(p - hdr);
                if (n > 0) { fwrite(p, 1, n, outf); g_done += n; }
                in_body = 1;
            }
        }
    }
    while (in_body) {
        n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        fwrite(buf, 1, n, outf);
        g_done += n;
        if (g_hwnd_prog)
            SendMessage(g_hwnd_prog, WM_WGET_PROGRESS, (WPARAM)g_done, (LPARAM)g_total);
        pump_messages();
        if (g_stopped) { in_body = 0; break; }
    }
    closesocket(sock);
    WSACleanup();
    return 1;
}

/* ------------------------------------------------------------------ */
/* Win32 WinInet HTTP/HTTPS                                             */
/* ------------------------------------------------------------------ */

static int wininet_http_get(const ParsedURL *url, FILE *outf)
{
    HANDLE hInet, hConn, hReq;
    DWORD  flags, dwRead, dwLen, dwStatus, dwIndex;
    char   buf[8192];
    char   szLen[64];
    int    ok = 0;

    hInet = pfnInternetOpen("wget/win32", INTERNET_OPEN_TYPE_PRECONFIG,
                            NULL, NULL, 0);
    if (!hInet) return 0;

    hConn = pfnInternetConnect(hInet, url->host,
                               (INTERNET_PORT)url->port,
                               NULL, NULL,
                               INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) { pfnInternetCloseHandle(hInet); return 0; }

    flags = INTERNET_FLAG_RELOAD |
            INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
            INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    if (url->scheme == SCHEME_HTTPS)
        flags |= INTERNET_FLAG_SECURE;

    hReq = pfnHttpOpenRequest(hConn, "GET", url->path,
                              "HTTP/1.0", NULL, NULL, flags, 0);
    if (!hReq) {
        pfnInternetCloseHandle(hConn);
        pfnInternetCloseHandle(hInet);
        return 0;
    }

    if (!pfnHttpSendRequest(hReq, NULL, 0, NULL, 0)) {
        pfnInternetCloseHandle(hReq);
        pfnInternetCloseHandle(hConn);
        pfnInternetCloseHandle(hInet);
        return 0;
    }

    /* check HTTP status */
    dwLen = sizeof(szLen) - 1;
    dwIndex = 0;
    dwStatus = 0;
    if (pfnHttpQueryInfo) {
        DWORD dwStat = 0, dwSLen = sizeof(dwStat);
        pfnHttpQueryInfo(hReq, HTTP_QUERY_STATUS_CODE | 0x20000000,
                         &dwStat, &dwSLen, &dwIndex);
        dwStatus = dwStat;
    }

    /* get content-length */
    dwLen = sizeof(szLen) - 1;
    dwIndex = 0;
    if (pfnHttpQueryInfo(hReq, HTTP_QUERY_CONTENT_LENGTH,
                         szLen, &dwLen, &dwIndex))
        g_total = atol(szLen);

    ok = 1;
    while (!g_stopped) {
        if (!pfnInternetReadFile(hReq, buf, sizeof(buf), &dwRead)) {
            ok = 0; break;
        }
        if (dwRead == 0) break;
        fwrite(buf, 1, dwRead, outf);
        g_done += dwRead;
        if (g_hwnd_prog)
            SendMessage(g_hwnd_prog, WM_WGET_PROGRESS,
                       (WPARAM)g_done, (LPARAM)g_total);
        pump_messages();
    }

    pfnInternetCloseHandle(hReq);
    pfnInternetCloseHandle(hConn);
    pfnInternetCloseHandle(hInet);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Win32 WinInet FTP                                                    */
/* ------------------------------------------------------------------ */

static int wininet_ftp_get(const ParsedURL *url, FILE *outf)
{
    HANDLE hInet, hConn, hFile;
    DWORD  dwRead, flags;
    char   buf[8192];
    int    ok = 0;
    const char *path;

    hInet = pfnInternetOpen("wget/win32", INTERNET_OPEN_TYPE_PRECONFIG,
                            NULL, NULL, 0);
    if (!hInet) return 0;

    flags = INTERNET_FLAG_PASSIVE | INTERNET_FLAG_RELOAD;
    hConn = pfnInternetConnect(hInet, url->host,
                               (INTERNET_PORT)url->port,
                               "anonymous", "wget@",
                               INTERNET_SERVICE_FTP, flags, 0);
    if (!hConn) { pfnInternetCloseHandle(hInet); return 0; }

    path = url->path;
    if (*path == '/') path++;

    hFile = pfnFtpOpenFile(hConn, path, GENERIC_READ,
                           INTERNET_FLAG_TRANSFER_BINARY |
                           FTP_TRANSFER_TYPE_BINARY, 0);
    if (!hFile) {
        pfnInternetCloseHandle(hConn);
        pfnInternetCloseHandle(hInet);
        return 0;
    }

    ok = 1;
    while (!g_stopped) {
        if (!pfnInternetReadFile(hFile, buf, sizeof(buf), &dwRead)) {
            ok = 0; break;
        }
        if (dwRead == 0) break;
        fwrite(buf, 1, dwRead, outf);
        g_done += dwRead;
        if (g_hwnd_prog)
            SendMessage(g_hwnd_prog, WM_WGET_PROGRESS,
                       (WPARAM)g_done, (LPARAM)g_total);
        pump_messages();
    }

    pfnInternetCloseHandle(hFile);
    pfnInternetCloseHandle(hConn);
    pfnInternetCloseHandle(hInet);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Win32 console detection + stdout progress                            */
/* ------------------------------------------------------------------ */

static int g_console_out = 0;

static void detect_console(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode;
    if (h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        g_console_out = 1;
}

static void console_progress(const char *fname)
{
    if (!g_console_out || g_quiet) return;
    if (g_total > 0)
        fprintf(stderr, "\r%-40s %ld%%", fname,
                g_done * 100L / g_total);
    else
        fprintf(stderr, "\r%-40s %ld bytes", fname, g_done);
}

/* ------------------------------------------------------------------ */
/* Win32 WinMain                                                        */
/* ------------------------------------------------------------------ */

static int  g_argc = 0;
static char *g_argv[32];
static char  g_cmdcopy[2048];

static void parse_cmdline(LPSTR lp)
{
    char *tok;
    lstrcpynA(g_cmdcopy, lp, sizeof(g_cmdcopy) - 1);
    tok = strtok(g_cmdcopy, " \t");
    while (tok && g_argc < 30) {
        g_argv[g_argc++] = tok;
        tok = strtok(NULL, " \t");
    }
    g_argv[g_argc] = NULL;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nShow)
{
    char       url_arg[1024] = "";
    char       out_arg[256]  = "";
    char       fname[256]    = "";
    int        i, use_wininet, ok;
    ParsedURL  pu;
    FILE      *outf;
    MSG        msg;

    (void)hPrev; (void)nShow;
    g_hinst = hInst;

    detect_console();
    parse_cmdline(lpCmd);

    for (i = 0; i < g_argc; i++) {
        if (lstrcmpA(g_argv[i], "-O") == 0 && i + 1 < g_argc)
            lstrcpynA(out_arg, g_argv[++i], sizeof(out_arg) - 1);
        else if (lstrcmpA(g_argv[i], "-q") == 0)
            g_quiet = 1;
        else if (url_arg[0] == '\0')
            lstrcpynA(url_arg, g_argv[i], sizeof(url_arg) - 1);
    }

    if (url_arg[0] == '\0') {
        if (g_console_out) {
            fprintf(stderr,
                "Usage: wget <URL> [-O filename] [-q]\n"
                "Schemes: http, https (WinInet), ftp (WinInet)\n");
        } else {
            MessageBoxA(NULL,
                "Usage: wget <URL> [-O filename] [-q]\n"
                "Schemes: http, https (WinInet), ftp (WinInet)",
                "wget", MB_OK | MB_ICONINFORMATION);
        }
        return 1;
    }

    parse_url(url_arg, &pu);

    if (out_arg[0] != '\0')
        lstrcpynA(fname, out_arg, sizeof(fname) - 1);
    else
        url_to_filename(pu.path, fname, sizeof(fname));

    use_wininet = wininet_load();

    if (!use_wininet && pu.scheme != SCHEME_HTTP) {
        if (g_console_out)
            fprintf(stderr, "wget: WININET.DLL not found; only HTTP supported\n");
        else
            MessageBoxA(NULL,
                "WININET.DLL not found.\nOnly plain HTTP is supported without it.",
                "wget", MB_OK | MB_ICONEXCLAMATION);
        return 1;
    }

    outf = fopen(fname, "wb");
    if (!outf) {
        char errmsg[512];
        wsprintfA(errmsg, "Cannot open '%s' for writing", fname);
        if (g_console_out)
            fprintf(stderr, "wget: %s\n", errmsg);
        else
            MessageBoxA(NULL, errmsg, "wget", MB_OK | MB_ICONEXCLAMATION);
        return 1;
    }

    /* GUI progress window when not running in console */
    if (!g_console_out && !g_quiet) {
        WNDCLASS wc;
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = ProgWndProc;
        wc.hInstance     = hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = "WgetProgress";
        wc.hIcon         = LoadIcon(hInst, MAKEINTRESOURCE(1));
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        RegisterClass(&wc);

        g_hwnd_prog = CreateWindow("WgetProgress",
            "wget \x97 Downloading",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 412, 148,
            NULL, NULL, hInst, NULL);

        if (g_hwnd_prog) {
            SetWindowText(g_hwnd_url,  url_arg);
            SetWindowText(g_hwnd_file, fname);
            UpdateWindow(g_hwnd_prog);
        }
    }

    if (!g_console_out && !g_quiet)
        fprintf(stderr, "Saving '%s' <- %s\n", fname, url_arg);

    if (use_wininet) {
        if (pu.scheme == SCHEME_FTP)
            ok = wininet_ftp_get(&pu, outf);
        else
            ok = wininet_http_get(&pu, outf);
    } else {
        ok = raw_http_get(&pu, outf);
    }

    fclose(outf);

    if (g_console_out && !g_quiet)
        console_progress(fname);

    if (g_hwnd_prog) {
        SendMessage(g_hwnd_prog, WM_WGET_DONE, (WPARAM)ok, (LPARAM)g_done);
        while (GetMessage(&msg, NULL, 0, 0)) {
            if (msg.message == WM_COMMAND &&
                LOWORD(msg.wParam) == IDOK &&
                msg.hwnd == g_hwnd_stop) break;
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    if (g_wininet) FreeLibrary(g_wininet);
    return ok ? 0 : 1;
}

#endif /* WGET_WIN16 */
