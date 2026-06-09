/*
 * ncwfw.c  -  MDI Netcat for Windows
 *
 * Multiple concurrent TCP/TLS sessions in a Win32 MDI window.
 * Plain TCP works on Win32s / Windows 3.1.
 * TLS uses Windows Schannel (secur32.dll, NT 4.0 SP3+ / Win95 OSR2+),
 * loaded dynamically so the binary runs anywhere; the TLS checkbox is
 * greyed out when secur32.dll is unavailable.
 *
 * NOTE: PuTTY has no standalone TLS client backend -- all its encryption
 * lives inside the SSH layer.  Schannel is the correct Windows-native
 * substitute and gives real TLS 1.2/1.3 interoperability.
 *
 * Build:
 *   wmake -f Makefile.wc ncwfw
 * Links: wsock32.lib  (secur32.dll is loaded at runtime, not link-time)
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aeldre_theme.h"

static int    g_theme_idx = 0;
static HBRUSH g_bg_brush  = NULL;

/* ================================================================
 * Schannel / SSPI types -- defined inline so we compile without
 * needing security.h / schannel.h in every SDK / OpenWatcom rev.
 * ================================================================ */

typedef LONG SECURITY_STATUS;

typedef struct { ULONG_PTR dwLower; ULONG_PTR dwUpper; } NC_SecHandle;
typedef NC_SecHandle CredHandle;
typedef NC_SecHandle CtxtHandle;

typedef struct { DWORD LowPart; LONG HighPart; } NC_TimeStamp;

typedef struct {
    ULONG cbBuffer;
    ULONG BufferType;
    PVOID pvBuffer;
} SecBuffer;

typedef struct {
    ULONG     ulVersion;
    ULONG     cBuffers;
    SecBuffer *pBuffers;
} SecBufferDesc;

typedef struct {
    ULONG cbHeader;
    ULONG cbTrailer;
    ULONG cbMaximumMessage;
    ULONG cBuffers;
    ULONG cbBlockSize;
} SecPkgContext_StreamSizes;

typedef struct {
    DWORD dwVersion;        /* SCHANNEL_CRED_VERSION = 4 */
    DWORD cCreds;
    void  **paCred;
    HANDLE hRootStore;
    DWORD cMappers;
    void  **aphMappers;
    DWORD cSupportedAlgs;
    DWORD *palgSupportedAlgs;
    DWORD grbitEnabledProtocols;
    DWORD dwMinimumCipherStrength;
    DWORD dwMaximumCipherStrength;
    DWORD dwSessionLifespan;
    DWORD dwFlags;
    DWORD dwCredFormat;
} NC_SchannelCred;

/* SSPI constants */
#define NC_SECBUF_VERSION           0
#define NC_SECBUFFER_EMPTY          0
#define NC_SECBUFFER_DATA           1
#define NC_SECBUFFER_TOKEN          2
#define NC_SECBUFFER_EXTRA          5
#define NC_SECBUFFER_STREAM_TRAILER 6
#define NC_SECBUFFER_STREAM_HEADER  7

#define NC_SEC_E_OK                 ((SECURITY_STATUS)0x00000000L)
#define NC_SEC_I_CONTINUE_NEEDED    ((SECURITY_STATUS)0x00090312L)
#define NC_SEC_E_INCOMPLETE_MESSAGE ((SECURITY_STATUS)0x80090318L)
#define NC_SECPKG_ATTR_STREAM_SIZES 4
#define NC_SECPKG_CRED_OUTBOUND     2
#define NC_SCHANNEL_CRED_VERSION    4

#define NC_SP_PROT_TLS1_2_CLIENT    0x00000200
#define NC_SP_PROT_TLS1_3_CLIENT    0x00002000
#define NC_SCH_CRED_NO_DEFAULT_CREDS           0x00000010
#define NC_SCH_CRED_MANUAL_CRED_VALIDATION     0x00000008

#define NC_ISC_REQ_REPLAY_DETECT    0x00000004
#define NC_ISC_REQ_SEQUENCE_DETECT  0x00000008
#define NC_ISC_REQ_CONFIDENTIALITY  0x00000010
#define NC_ISC_REQ_ALLOCATE_MEMORY  0x00000100
#define NC_ISC_REQ_STREAM           0x00008000
#define NC_ISC_REQ_MANUAL_CRED_VAL  0x00080000

#define NC_UNISP_NAME "Microsoft Unified Security Protocol Provider"

typedef SECURITY_STATUS (WINAPI *pfAcqCred)(
    char *, char *, ULONG, void *, void *, void *, void *,
    CredHandle *, NC_TimeStamp *);
typedef SECURITY_STATUS (WINAPI *pfInitSecCtx)(
    CredHandle *, CtxtHandle *, char *, ULONG, ULONG, ULONG,
    SecBufferDesc *, ULONG, CtxtHandle *, SecBufferDesc *,
    PULONG, NC_TimeStamp *);
typedef SECURITY_STATUS (WINAPI *pfFreeCredH)(CredHandle *);
typedef SECURITY_STATUS (WINAPI *pfDelSecCtx)(CtxtHandle *);
typedef SECURITY_STATUS (WINAPI *pfEncMsg)(CtxtHandle *, ULONG, SecBufferDesc *, ULONG);
typedef SECURITY_STATUS (WINAPI *pfDecMsg)(CtxtHandle *, SecBufferDesc *, ULONG, PULONG);
typedef SECURITY_STATUS (WINAPI *pfFreeCtxBuf)(void *);
typedef SECURITY_STATUS (WINAPI *pfQryCtxAttr)(CtxtHandle *, ULONG, void *);

static HMODULE       g_secur32       = NULL;
static pfAcqCred     p_AcqCred       = NULL;
static pfInitSecCtx  p_InitSecCtx    = NULL;
static pfFreeCredH   p_FreeCred      = NULL;
static pfDelSecCtx   p_DelSecCtx     = NULL;
static pfEncMsg      p_EncMsg        = NULL;
static pfDecMsg      p_DecMsg        = NULL;
static pfFreeCtxBuf  p_FreeCtxBuf    = NULL;
static pfQryCtxAttr  p_QryCtxAttr    = NULL;
static int           g_tls_avail     = 0;

/* ================================================================
 * Control IDs and menu IDs
 * ================================================================ */
#define IDC_OUT      1000
#define IDC_IN       1001
#define IDC_SEND     1002

#define IDM_FILE_NEW        2000
#define IDM_FILE_DISCONNECT 2001
#define IDM_FILE_EXIT       2002
#define IDM_WIN_TILE_H      2010
#define IDM_WIN_TILE_V      2011
#define IDM_WIN_CASCADE     2012
#define IDM_WIN_CLOSEALL    2013
#define IDM_HELP_ABOUT      2020

#define IDC_DLG_HOST    3000
#define IDC_DLG_PORT    3001
#define IDC_DLG_TLS     3002
#define IDC_DLG_LISTEN  3003
#define IDC_DLG_OK      3004
#define IDC_DLG_CANCEL  3005

#define WM_NC_SOCKET (WM_APP + 1)   /* wParam=sock,   lParam=WSA event/error */
#define WM_NC_DNS    (WM_APP + 2)   /* wParam=handle, lParam=WSA error/len   */

#ifndef MAXGETHOSTSTRUCT
#define MAXGETHOSTSTRUCT 1024
#endif

#define INPUT_H  26
#define BTN_W    60

/* ================================================================
 * Session state
 * ================================================================ */
#define NS_IDLE       0
#define NS_RESOLVING  1   /* async DNS in flight */
#define NS_CONNECTING 2
#define NS_TLS_SHAKE  3
#define NS_CONNECTED  4
#define NS_LISTENING  5

#define NC_IBUF (32*1024)

typedef struct {
    HWND   hwnd;
    SOCKET sock;
    SOCKET listen_sock;
    int    state;
    int    tls;
    char   host[256];
    int    port;
    /* Schannel */
    CredHandle tls_cred;
    CtxtHandle tls_ctx;
    int        tls_cred_valid;
    int        tls_ctx_valid;
    char       tls_ibuf[NC_IBUF];
    int        tls_ibuf_len;
    SecPkgContext_StreamSizes tls_sizes;
    int        tls_sizes_valid;
    /* Async DNS */
    HANDLE     dns_task;
    char       dns_buf[MAXGETHOSTSTRUCT];
} NcSession;

#define MAX_SESSIONS 16
static NcSession *g_sess[MAX_SESSIONS];
static int        g_nsess  = 0;
static HWND       g_frame  = NULL;
static HWND       g_mdi    = NULL;
static HINSTANCE  g_hinst  = NULL;
static WNDPROC    g_in_orig = NULL;

/* ================================================================
 * New-connection dialog globals
 * ================================================================ */
static HWND g_dlg           = NULL;
static HWND g_dlg_hedit     = NULL;
static HWND g_dlg_pedit     = NULL;
static HWND g_dlg_tlschk    = NULL;
static HWND g_dlg_listenchk = NULL;
static char g_dlg_host_buf[256];
static char g_dlg_port_buf[16];
static int  g_dlg_tls_val    = 0;
static int  g_dlg_listen_val = 0;
static int  g_dlg_ok         = 0;

/* ================================================================
 * Forward declarations
 * ================================================================ */
static void session_append(NcSession *s, const char *text);
static void session_close(NcSession *s);
static int  tls_client_begin(NcSession *s);
static void tls_handshake_feed(NcSession *s);
static void tls_decrypt_recv(NcSession *s, const char *buf, int len);
static int  tls_encrypt_send(NcSession *s, const char *buf, int len);
static LRESULT CALLBACK FrameProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK ChildProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK DlgProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK InputSubclass(HWND, UINT, WPARAM, LPARAM);

/* ================================================================
 * Schannel init
 * ================================================================ */
static void tls_load(void)
{
    g_secur32 = LoadLibrary("secur32.dll");
    if (!g_secur32) return;
#define GF(v,n) v = (void*)GetProcAddress(g_secur32, n); if (!v) { FreeLibrary(g_secur32); g_secur32=NULL; return; }
    GF(p_AcqCred,    "AcquireCredentialsHandleA")
    GF(p_InitSecCtx, "InitializeSecurityContextA")
    GF(p_FreeCred,   "FreeCredentialsHandle")
    GF(p_DelSecCtx,  "DeleteSecurityContext")
    GF(p_EncMsg,     "EncryptMessage")
    GF(p_DecMsg,     "DecryptMessage")
    GF(p_FreeCtxBuf, "FreeContextBuffer")
    GF(p_QryCtxAttr, "QueryContextAttributesA")
#undef GF
    g_tls_avail = 1;
}

/* ================================================================
 * Session helpers
 * ================================================================ */
static NcSession *session_by_sock(SOCKET s)
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++)
        if (g_sess[i] &&
            (g_sess[i]->sock == s || g_sess[i]->listen_sock == s))
            return g_sess[i];
    return NULL;
}

static NcSession *session_by_dnstask(HANDLE task)
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++)
        if (g_sess[i] && g_sess[i]->dns_task == task)
            return g_sess[i];
    return NULL;
}

static void session_append(NcSession *s, const char *text)
{
    HWND out;
    int  len;
    if (!s || !s->hwnd) return;
    out = GetDlgItem(s->hwnd, IDC_OUT);
    if (!out) return;
    len = GetWindowTextLength(out);
    SendMessage(out, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessage(out, EM_REPLACESEL, 0, (LPARAM)text);
}

static void session_set_title(NcSession *s)
{
    char title[320];
    const char *state_str = "";
    if (!s) return;
    switch (s->state) {
    case NS_RESOLVING:  state_str = " [resolving]"; break;
    case NS_CONNECTING: state_str = " [connecting]"; break;
    case NS_TLS_SHAKE:  state_str = " [TLS handshake]"; break;
    case NS_CONNECTED:  state_str = s->tls ? " [TLS]" : ""; break;
    case NS_LISTENING:  state_str = " [listening]"; break;
    default:            state_str = " [idle]"; break;
    }
    if (s->listen_sock != INVALID_SOCKET && s->state == NS_LISTENING)
        sprintf(title, "nc :%-5d%s", s->port, state_str);
    else
        sprintf(title, "nc %s:%d%s", s->host, s->port, state_str);
    SetWindowText(s->hwnd, title);
}

static void session_close(NcSession *s)
{
    if (!s) return;
    if (s->dns_task) {
        WSACancelAsyncRequest(s->dns_task);
        s->dns_task = NULL;
    }
    if (s->sock != INVALID_SOCKET) {
        WSAAsyncSelect(s->sock, g_frame, 0, 0);
        closesocket(s->sock);
        s->sock = INVALID_SOCKET;
    }
    if (s->listen_sock != INVALID_SOCKET) {
        WSAAsyncSelect(s->listen_sock, g_frame, 0, 0);
        closesocket(s->listen_sock);
        s->listen_sock = INVALID_SOCKET;
    }
    if (s->tls_ctx_valid)  { p_DelSecCtx(&s->tls_ctx);  s->tls_ctx_valid  = 0; }
    if (s->tls_cred_valid) { p_FreeCred(&s->tls_cred);  s->tls_cred_valid = 0; }
    s->tls_ibuf_len    = 0;
    s->tls_sizes_valid = 0;
    s->state = NS_IDLE;
    session_set_title(s);
}

/* ================================================================
 * TLS helpers (Schannel)
 * ================================================================ */
static int tls_client_begin(NcSession *s)
{
    NC_SchannelCred cred;
    NC_TimeStamp    ts;
    ULONG           attrs;
    SecBuffer       out_buf;
    SecBufferDesc   out_desc;
    SECURITY_STATUS ss;

    memset(&cred, 0, sizeof(cred));
    cred.dwVersion             = NC_SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = NC_SP_PROT_TLS1_2_CLIENT | NC_SP_PROT_TLS1_3_CLIENT;
    cred.dwFlags               = NC_SCH_CRED_NO_DEFAULT_CREDS |
                                 NC_SCH_CRED_MANUAL_CRED_VALIDATION;

    ss = p_AcqCred(NULL, NC_UNISP_NAME, NC_SECPKG_CRED_OUTBOUND,
                   NULL, &cred, NULL, NULL, &s->tls_cred, &ts);
    if (ss != NC_SEC_E_OK) {
        char msg[64];
        sprintf(msg, "[TLS: AcquireCredentials failed %08lx]\r\n", (unsigned long)ss);
        session_append(s, msg);
        return 0;
    }
    s->tls_cred_valid = 1;

    out_buf.cbBuffer   = 0;
    out_buf.BufferType = NC_SECBUFFER_TOKEN;
    out_buf.pvBuffer   = NULL;
    out_desc.ulVersion = NC_SECBUF_VERSION;
    out_desc.cBuffers  = 1;
    out_desc.pBuffers  = &out_buf;

    attrs = NC_ISC_REQ_REPLAY_DETECT   | NC_ISC_REQ_SEQUENCE_DETECT |
            NC_ISC_REQ_CONFIDENTIALITY | NC_ISC_REQ_ALLOCATE_MEMORY |
            NC_ISC_REQ_STREAM          | NC_ISC_REQ_MANUAL_CRED_VAL;

    ss = p_InitSecCtx(&s->tls_cred, NULL, s->host,
                      attrs, 0, 0, NULL, 0,
                      &s->tls_ctx, &out_desc, &attrs, &ts);
    s->tls_ctx_valid = 1;

    if (out_buf.pvBuffer && out_buf.cbBuffer > 0) {
        send(s->sock, (char *)out_buf.pvBuffer, (int)out_buf.cbBuffer, 0);
        p_FreeCtxBuf(out_buf.pvBuffer);
    }

    if (ss == NC_SEC_E_OK || ss == NC_SEC_I_CONTINUE_NEEDED) {
        s->state = NS_TLS_SHAKE;
        session_set_title(s);
        return 1;
    }
    {
        char msg[64];
        sprintf(msg, "[TLS init failed %08lx]\r\n", (unsigned long)ss);
        session_append(s, msg);
        session_close(s);
        return 0;
    }
}

static void tls_handshake_feed(NcSession *s)
{
    SecBuffer     in_bufs[2], out_buf;
    SecBufferDesc in_desc,    out_desc;
    NC_TimeStamp  ts;
    ULONG         attrs;
    SECURITY_STATUS ss;
    int i;

    in_bufs[0].cbBuffer   = (ULONG)s->tls_ibuf_len;
    in_bufs[0].BufferType = NC_SECBUFFER_TOKEN;
    in_bufs[0].pvBuffer   = s->tls_ibuf;
    in_bufs[1].cbBuffer   = 0;
    in_bufs[1].BufferType = NC_SECBUFFER_EMPTY;
    in_bufs[1].pvBuffer   = NULL;
    in_desc.ulVersion = NC_SECBUF_VERSION;
    in_desc.cBuffers  = 2;
    in_desc.pBuffers  = in_bufs;

    out_buf.cbBuffer   = 0;
    out_buf.BufferType = NC_SECBUFFER_TOKEN;
    out_buf.pvBuffer   = NULL;
    out_desc.ulVersion = NC_SECBUF_VERSION;
    out_desc.cBuffers  = 1;
    out_desc.pBuffers  = &out_buf;

    attrs = NC_ISC_REQ_REPLAY_DETECT   | NC_ISC_REQ_SEQUENCE_DETECT |
            NC_ISC_REQ_CONFIDENTIALITY | NC_ISC_REQ_ALLOCATE_MEMORY |
            NC_ISC_REQ_STREAM          | NC_ISC_REQ_MANUAL_CRED_VAL;

    ss = p_InitSecCtx(&s->tls_cred, &s->tls_ctx, s->host,
                      attrs, 0, 0, &in_desc, 0,
                      &s->tls_ctx, &out_desc, &attrs, &ts);

    if (out_buf.pvBuffer && out_buf.cbBuffer > 0) {
        send(s->sock, (char *)out_buf.pvBuffer, (int)out_buf.cbBuffer, 0);
        p_FreeCtxBuf(out_buf.pvBuffer);
    }

    /* Handle leftover (SECBUFFER_EXTRA) in the input */
    s->tls_ibuf_len = 0;
    for (i = 0; i < 2; i++) {
        if (in_bufs[i].BufferType == NC_SECBUFFER_EXTRA &&
            in_bufs[i].cbBuffer > 0) {
            int extra = (int)in_bufs[i].cbBuffer;
            memmove(s->tls_ibuf,
                    s->tls_ibuf + (s->tls_ibuf_len - extra), extra);
            s->tls_ibuf_len = extra;
            break;
        }
    }

    if (ss == NC_SEC_E_OK) {
        p_QryCtxAttr(&s->tls_ctx, NC_SECPKG_ATTR_STREAM_SIZES, &s->tls_sizes);
        s->tls_sizes_valid = 1;
        s->state = NS_CONNECTED;
        session_set_title(s);
        session_append(s, "[TLS connected]\r\n");
        if (s->tls_ibuf_len > 0)
            tls_decrypt_recv(s, s->tls_ibuf, s->tls_ibuf_len);
    } else if (ss == NC_SEC_E_INCOMPLETE_MESSAGE) {
        s->tls_ibuf_len = (int)in_bufs[0].cbBuffer;
    } else if (ss != NC_SEC_I_CONTINUE_NEEDED) {
        char msg[64];
        sprintf(msg, "[TLS handshake error %08lx]\r\n", (unsigned long)ss);
        session_append(s, msg);
        session_close(s);
    }
}

static void tls_decrypt_recv(NcSession *s, const char *buf, int len)
{
    char   tmp[64];
    char   plain[NC_IBUF];
    int    plain_len;
    int    i;

    if (buf != s->tls_ibuf) {
        if (s->tls_ibuf_len + len > NC_IBUF) len = NC_IBUF - s->tls_ibuf_len;
        memcpy(s->tls_ibuf + s->tls_ibuf_len, buf, len);
        s->tls_ibuf_len += len;
    }

    while (s->tls_ibuf_len > 0) {
        SecBuffer bufs[4];
        SecBufferDesc desc;
        ULONG qop = 0;
        SECURITY_STATUS ss;

        bufs[0].cbBuffer   = (ULONG)s->tls_ibuf_len;
        bufs[0].BufferType = NC_SECBUFFER_DATA;
        bufs[0].pvBuffer   = s->tls_ibuf;
        bufs[1].cbBuffer = 0; bufs[1].BufferType = NC_SECBUFFER_EMPTY; bufs[1].pvBuffer = NULL;
        bufs[2].cbBuffer = 0; bufs[2].BufferType = NC_SECBUFFER_EMPTY; bufs[2].pvBuffer = NULL;
        bufs[3].cbBuffer = 0; bufs[3].BufferType = NC_SECBUFFER_EMPTY; bufs[3].pvBuffer = NULL;
        desc.ulVersion = NC_SECBUF_VERSION;
        desc.cBuffers  = 4;
        desc.pBuffers  = bufs;

        ss = p_DecMsg(&s->tls_ctx, &desc, 0, &qop);

        if (ss == NC_SEC_E_INCOMPLETE_MESSAGE) break;

        if (ss != NC_SEC_E_OK) {
            sprintf(tmp, "[TLS recv error %08lx]\r\n", (unsigned long)ss);
            session_append(s, tmp);
            session_close(s);
            return;
        }

        plain_len = 0;
        for (i = 0; i < 4; i++) {
            if (bufs[i].BufferType == NC_SECBUFFER_DATA &&
                bufs[i].cbBuffer > 0 &&
                plain_len + (int)bufs[i].cbBuffer < NC_IBUF) {
                memcpy(plain + plain_len, bufs[i].pvBuffer, bufs[i].cbBuffer);
                plain_len += (int)bufs[i].cbBuffer;
            }
        }
        if (plain_len > 0) {
            if (plain_len < NC_IBUF) plain[plain_len] = '\0';
            session_append(s, plain);
        }

        s->tls_ibuf_len = 0;
        for (i = 0; i < 4; i++) {
            if (bufs[i].BufferType == NC_SECBUFFER_EXTRA &&
                bufs[i].cbBuffer > 0) {
                int extra = (int)bufs[i].cbBuffer;
                memmove(s->tls_ibuf, bufs[i].pvBuffer, extra);
                s->tls_ibuf_len = extra;
                break;
            }
        }
        if (s->tls_ibuf_len == 0) break;
    }
}

static int tls_encrypt_send(NcSession *s, const char *data, int data_len)
{
    char *buf;
    int   total, sent;
    SecBuffer     bufs[4];
    SecBufferDesc desc;
    SECURITY_STATUS ss;

    if (!s->tls_sizes_valid) return -1;
    total = (int)(s->tls_sizes.cbHeader + (ULONG)data_len + s->tls_sizes.cbTrailer);
    buf   = (char *)malloc(total);
    if (!buf) return -1;

    memcpy(buf + s->tls_sizes.cbHeader, data, data_len);

    bufs[0].cbBuffer   = s->tls_sizes.cbHeader;
    bufs[0].BufferType = NC_SECBUFFER_STREAM_HEADER;
    bufs[0].pvBuffer   = buf;
    bufs[1].cbBuffer   = (ULONG)data_len;
    bufs[1].BufferType = NC_SECBUFFER_DATA;
    bufs[1].pvBuffer   = buf + s->tls_sizes.cbHeader;
    bufs[2].cbBuffer   = s->tls_sizes.cbTrailer;
    bufs[2].BufferType = NC_SECBUFFER_STREAM_TRAILER;
    bufs[2].pvBuffer   = buf + s->tls_sizes.cbHeader + data_len;
    bufs[3].cbBuffer   = 0;
    bufs[3].BufferType = NC_SECBUFFER_EMPTY;
    bufs[3].pvBuffer   = NULL;
    desc.ulVersion = NC_SECBUF_VERSION;
    desc.cBuffers  = 4;
    desc.pBuffers  = bufs;

    ss = p_EncMsg(&s->tls_ctx, 0, &desc, 0);
    sent = (ss == NC_SEC_E_OK) ? send(s->sock, buf, total, 0) : -1;

    free(buf);
    return sent;
}

/* ================================================================
 * Socket event handler
 * ================================================================ */
static void handle_socket_event(SOCKET sock, int event, int err)
{
    NcSession *s = session_by_sock(sock);
    char  buf[4096];
    int   n;
    char  msg[80];

    if (!s) return;

    if (err) {
        sprintf(msg, "[error %d]\r\n", err);
        session_append(s, msg);
        session_close(s);
        return;
    }

    switch (event) {
    case FD_CONNECT:
        if (s->tls && g_tls_avail) {
            tls_client_begin(s);
        } else {
            s->state = NS_CONNECTED;
            session_set_title(s);
            session_append(s, "[connected]\r\n");
        }
        break;

    case FD_READ:
        n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';

        if (s->state == NS_TLS_SHAKE) {
            int room = NC_IBUF - s->tls_ibuf_len;
            if (n > room) n = room;
            memcpy(s->tls_ibuf + s->tls_ibuf_len, buf, n);
            s->tls_ibuf_len += n;
            tls_handshake_feed(s);
        } else if (s->state == NS_CONNECTED && s->tls) {
            tls_decrypt_recv(s, buf, n);
        } else if (s->state == NS_CONNECTED) {
            session_append(s, buf);
        }
        break;

    case FD_ACCEPT: {
        struct sockaddr_in peer;
        int peer_len = sizeof(peer);
        SOCKET new_sock;
        memset(&peer, 0, sizeof(peer));
        new_sock = accept(s->listen_sock, (struct sockaddr *)&peer, &peer_len);
        if (new_sock == INVALID_SOCKET) break;
        WSAAsyncSelect(s->listen_sock, g_frame, 0, 0);
        closesocket(s->listen_sock);
        s->listen_sock = INVALID_SOCKET;
        s->sock = new_sock;
        WSAAsyncSelect(s->sock, g_frame, WM_NC_SOCKET,
                       FD_READ | FD_WRITE | FD_CLOSE);
        s->state = NS_CONNECTED;
        session_set_title(s);
        sprintf(msg, "[connection from %s:%d]\r\n",
                inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
        session_append(s, msg);
        break;
    }

    case FD_CLOSE:
        session_append(s, "[connection closed]\r\n");
        session_close(s);
        break;
    }
}

/* ================================================================
 * Send from the input EDIT
 * ================================================================ */
static void session_send(NcSession *s)
{
    HWND  in_wnd;
    char  buf[2048];
    int   len;

    if (!s || s->state != NS_CONNECTED) return;
    in_wnd = GetDlgItem(s->hwnd, IDC_IN);
    if (!in_wnd) return;
    len = GetWindowText(in_wnd, buf, (int)sizeof(buf) - 3);
    if (len <= 0) return;

    buf[len]     = '\r';
    buf[len + 1] = '\n';
    buf[len + 2] = '\0';

    if (s->tls && g_tls_avail)
        tls_encrypt_send(s, buf, len + 2);
    else
        send(s->sock, buf, len + 2, 0);

    session_append(s, "> ");
    session_append(s, buf);
    SetWindowText(in_wnd, "");
}

/* ================================================================
 * New-connection dialog
 * ================================================================ */
static void dlg_update_listen(void)
{
    int listen = (g_dlg_listenchk &&
                  SendMessage(g_dlg_listenchk, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (g_dlg_hedit) EnableWindow(g_dlg_hedit, !listen);
    if (g_dlg_tlschk && !g_tls_avail)
        EnableWindow(g_dlg_tlschk, FALSE);
}

static LRESULT CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND  hw;
        int   y = 10;

        hw = CreateWindow("STATIC", "Host:", WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8, y+3, 44, 18, hwnd, NULL, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        g_dlg_hedit = CreateWindow("EDIT", "",
                          WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                          56, y, 276, 22, hwnd, (HMENU)IDC_DLG_HOST, g_hinst, NULL);
        SendMessage(g_dlg_hedit, WM_SETFONT, (WPARAM)hf, FALSE);

        y = 40;
        hw = CreateWindow("STATIC", "Port:", WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8, y+3, 44, 18, hwnd, NULL, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        g_dlg_pedit = CreateWindow("EDIT", "4444",
                          WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_NUMBER,
                          56, y, 60, 22, hwnd, (HMENU)IDC_DLG_PORT, g_hinst, NULL);
        SendMessage(g_dlg_pedit, WM_SETFONT, (WPARAM)hf, FALSE);

        g_dlg_tlschk = CreateWindow("BUTTON", "TLS",
                          WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
                          130, y+2, 60, 18, hwnd, (HMENU)IDC_DLG_TLS, g_hinst, NULL);
        SendMessage(g_dlg_tlschk, WM_SETFONT, (WPARAM)hf, FALSE);

        g_dlg_listenchk = CreateWindow("BUTTON", "Listen mode",
                          WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
                          200, y+2, 120, 18, hwnd, (HMENU)IDC_DLG_LISTEN, g_hinst, NULL);
        SendMessage(g_dlg_listenchk, WM_SETFONT, (WPARAM)hf, FALSE);

        y = 76;
        hw = CreateWindow("BUTTON", "Connect",
                          WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                          56, y, 90, 26, hwnd, (HMENU)IDC_DLG_OK, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("BUTTON", "Cancel",
                          WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                          158, y, 90, 26, hwnd, (HMENU)IDC_DLG_CANCEL, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);

        dlg_update_listen();
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_DLG_LISTEN) { dlg_update_listen(); return 0; }
        if (LOWORD(wp) == IDC_DLG_CANCEL || LOWORD(wp) == IDCANCEL) {
            g_dlg_ok = 0; DestroyWindow(hwnd); return 0;
        }
        if (LOWORD(wp) == IDC_DLG_OK) {
            GetWindowText(g_dlg_hedit, g_dlg_host_buf, sizeof(g_dlg_host_buf));
            GetWindowText(g_dlg_pedit, g_dlg_port_buf, sizeof(g_dlg_port_buf));
            g_dlg_tls_val    = (SendMessage(g_dlg_tlschk,    BM_GETCHECK, 0, 0) == BST_CHECKED);
            g_dlg_listen_val = (SendMessage(g_dlg_listenchk, BM_GETCHECK, 0, 0) == BST_CHECKED);
            g_dlg_ok = 1;
            DestroyWindow(hwnd);
            return 0;
        }
        return 0;
    case WM_CLOSE:
        g_dlg_ok = 0; DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        g_dlg           = NULL;
        g_dlg_hedit     = NULL;
        g_dlg_pedit     = NULL;
        g_dlg_tlschk    = NULL;
        g_dlg_listenchk = NULL;
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static int show_new_conn_dialog(void)
{
    RECT wr, dr; int dw, dh;
    MSG  msg;

    g_dlg_ok = 0;
    g_dlg_host_buf[0] = '\0';
    strcpy(g_dlg_port_buf, "4444");
    g_dlg_tls_val    = 0;
    g_dlg_listen_val = 0;

    g_dlg = CreateWindowEx(WS_EX_DLGMODALFRAME, "NcWfwDlg", "New Connection",
                WS_POPUP | WS_CAPTION | WS_SYSMENU,
                0, 0, 350, 120, g_frame, NULL, g_hinst, NULL);
    if (!g_dlg) return 0;

    GetWindowRect(g_frame, &wr);
    GetWindowRect(g_dlg,   &dr);
    dw = dr.right - dr.left; dh = dr.bottom - dr.top;
    SetWindowPos(g_dlg, HWND_TOP,
                 wr.left + (wr.right  - wr.left - dw) / 2,
                 wr.top  + (wr.bottom - wr.top  - dh) / 2,
                 0, 0, SWP_NOSIZE);
    ShowWindow(g_dlg, SW_SHOW);
    SetFocus(g_dlg_hedit);

    while (g_dlg) {
        if (!GetMessage(&msg, NULL, 0, 0)) break;
        if (!IsDialogMessage(g_dlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return g_dlg_ok;
}

/* ================================================================
 * Create a new session (connect or listen)
 * ================================================================ */
static void new_session(const char *host, int port, int tls_flag, int listen_mode)
{
    NcSession  *s;
    MDICREATESTRUCT mcs;
    int i;

    if (g_nsess >= MAX_SESSIONS) {
        MessageBox(g_frame, "Too many sessions open.", "ncwfw",
                   MB_OK | MB_ICONWARNING);
        return;
    }
    s = (NcSession *)calloc(1, sizeof(NcSession));
    if (!s) return;

    s->sock        = INVALID_SOCKET;
    s->listen_sock = INVALID_SOCKET;
    s->tls         = tls_flag && g_tls_avail;
    s->port        = port;
    strncpy(s->host, host ? host : "", 255);

    for (i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sess[i]) { g_sess[i] = s; break; }
    }
    if (i == MAX_SESSIONS) { free(s); return; }
    g_nsess++;

    memset(&mcs, 0, sizeof(mcs));
    mcs.szClass = "NcWfwChild";
    mcs.szTitle = "nc ...";
    mcs.hOwner  = g_hinst;
    mcs.x = mcs.y = mcs.cx = mcs.cy = CW_USEDEFAULT;
    mcs.style   = WS_VISIBLE;
    mcs.lParam  = (LPARAM)s;
    s->hwnd = (HWND)SendMessage(g_mdi, WM_MDICREATE, 0, (LPARAM)&mcs);

    if (listen_mode) {
        struct sockaddr_in addr;
        s->listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s->listen_sock == INVALID_SOCKET) goto fail;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons((unsigned short)port);
        if (bind(s->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
            listen(s->listen_sock, 1) != 0) {
            char msg[80];
            sprintf(msg, "[bind/listen on port %d failed]\r\n", port);
            session_append(s, msg);
            goto fail;
        }
        WSAAsyncSelect(s->listen_sock, g_frame, WM_NC_SOCKET, FD_ACCEPT);
        s->state = NS_LISTENING;
        session_set_title(s);
        {
            char msg[64];
            sprintf(msg, "[listening on port %d]\r\n", port);
            session_append(s, msg);
        }
    } else {
        /* Create the socket now; WSAAsyncSelect waits until DNS resolves. */
        s->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s->sock == INVALID_SOCKET) goto fail;

        s->dns_task = WSAAsyncGetHostByName(g_frame, WM_NC_DNS,
                                            host, s->dns_buf,
                                            sizeof(s->dns_buf));
        if (!s->dns_task) {
            char msg[120];
            sprintf(msg, "[WSAAsyncGetHostByName failed: %d]\r\n",
                    WSAGetLastError());
            session_append(s, msg);
            goto fail;
        }
        s->state = NS_RESOLVING;
        session_set_title(s);
        {
            char msg[288];
            sprintf(msg, "[resolving %s...]\r\n", host);
            session_append(s, msg);
        }
    }
    return;

fail:
    session_close(s);
}

/* ================================================================
 * MDI child (session) window proc
 * ================================================================ */
static LRESULT CALLBACK InputSubclass(HWND hwnd, UINT msg,
                                       WPARAM wp, LPARAM lp)
{
    if (msg == WM_KEYDOWN && wp == VK_RETURN) {
        HWND      child = GetParent(hwnd);
        NcSession *s    = (NcSession *)GetWindowLong(child, GWL_USERDATA);
        session_send(s);
        return 0;
    }
    return CallWindowProc(g_in_orig, hwnd, msg, wp, lp);
}

static LRESULT CALLBACK ChildProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    NcSession *s = (NcSession *)GetWindowLong(hwnd, GWL_USERDATA);

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT   *cs = (CREATESTRUCT *)lp;
        MDICREATESTRUCT *mc = (MDICREATESTRUCT *)cs->lpCreateParams;
        HFONT hf = (HFONT)GetStockObject(SYSTEM_FIXED_FONT);
        HWND  out, in, btn;

        s = (NcSession *)mc->lParam;
        SetWindowLong(hwnd, GWL_USERDATA, (LONG)s);

        out = CreateWindow("EDIT", "",
                  WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|
                  ES_AUTOVSCROLL|ES_READONLY,
                  0, 0, 100, 100, hwnd, (HMENU)IDC_OUT, g_hinst, NULL);
        SendMessage(out, WM_SETFONT, (WPARAM)hf, FALSE);

        in = CreateWindow("EDIT", "",
                  WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                  0, 0, 100, INPUT_H, hwnd, (HMENU)IDC_IN, g_hinst, NULL);
        SendMessage(in, WM_SETFONT, (WPARAM)hf, FALSE);
        if (!g_in_orig)
            g_in_orig = (WNDPROC)SetWindowLong(in, GWL_WNDPROC, (LONG)InputSubclass);
        else
            SetWindowLong(in, GWL_WNDPROC, (LONG)InputSubclass);

        btn = CreateWindow("BUTTON", "Send",
                  WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                  0, 0, BTN_W, INPUT_H, hwnd, (HMENU)IDC_SEND, g_hinst, NULL);
        SendMessage(btn, WM_SETFONT, (WPARAM)hf, FALSE);
        return 0;
    }

    case WM_SIZE: {
        int w = LOWORD(lp), h = HIWORD(lp);
        int iw = w - BTN_W - 2;
        MoveWindow(GetDlgItem(hwnd, IDC_OUT), 0, 0,
                   w, h - INPUT_H - 2, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_IN),  0, h - INPUT_H,
                   iw > 0 ? iw : 0, INPUT_H, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_SEND), iw > 0 ? iw : 0, h - INPUT_H,
                   BTN_W, INPUT_H, TRUE);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wp) == IDC_SEND) { session_send(s); return 0; }
        break;

    case WM_CLOSE:
        session_close(s);
        break;

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        const AeldreTheme *t = &g_aeldre_themes[g_theme_idx];
        SetTextColor(hdc, t->body);
        SetBkColor(hdc, t->bg);
        return (LRESULT)g_bg_brush;
    }

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wp; RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_bg_brush);
        return 1;
    }

    case WM_DESTROY: {
        int i;
        for (i = 0; i < MAX_SESSIONS; i++) {
            if (g_sess[i] == s) { g_sess[i] = NULL; g_nsess--; break; }
        }
        free(s);
        break;
    }
    }
    return DefMDIChildProc(hwnd, msg, wp, lp);
}

/* ================================================================
 * Frame window proc
 * ================================================================ */
static HMENU build_menu(void)
{
    HMENU bar  = CreateMenu();
    HMENU file = CreatePopupMenu();
    HMENU win  = CreatePopupMenu();
    HMENU help = CreatePopupMenu();

    AppendMenu(file, MF_STRING,    IDM_FILE_NEW,        "&New Connection\tCtrl+N");
    AppendMenu(file, MF_STRING,    IDM_FILE_DISCONNECT, "&Disconnect");
    AppendMenu(file, MF_SEPARATOR, 0, NULL);
    AppendMenu(file, MF_STRING,    IDM_FILE_EXIT,       "E&xit");

    AppendMenu(win,  MF_STRING,    IDM_WIN_TILE_H,   "Tile &Horizontal");
    AppendMenu(win,  MF_STRING,    IDM_WIN_TILE_V,   "Tile &Vertical");
    AppendMenu(win,  MF_STRING,    IDM_WIN_CASCADE,  "&Cascade");
    AppendMenu(win,  MF_SEPARATOR, 0, NULL);
    AppendMenu(win,  MF_STRING,    IDM_WIN_CLOSEALL, "Close &All");

    AppendMenu(help, MF_STRING,    IDM_HELP_ABOUT,   "&About");

    AppendMenu(bar, MF_POPUP, (UINT)file, "&File");
    AppendMenu(bar, MF_POPUP, (UINT)win,  "&Window");
    AppendMenu(bar, MF_POPUP, (UINT)help, "&Help");
    return bar;
}

static LRESULT CALLBACK FrameProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        CLIENTCREATESTRUCT ccs;
        g_theme_idx = aeldre_theme_load();
        g_bg_brush  = CreateSolidBrush(g_aeldre_themes[g_theme_idx].bg);
        ccs.hWindowMenu  = GetSubMenu(GetMenu(hwnd), 1);
        ccs.idFirstChild = 30000;
        g_mdi = CreateWindow("MDICLIENT", NULL,
                    WS_CHILD | WS_CLIPCHILDREN | WS_VISIBLE,
                    0, 0, 0, 0, hwnd, (HMENU)1, g_hinst, &ccs);
        return 0;
    }

    case WM_SIZE:
        MoveWindow(g_mdi, 0, 0, LOWORD(lp), HIWORD(lp), TRUE);
        return 0;

    case WM_NC_SOCKET:
        handle_socket_event((SOCKET)wp,
                            (int)WSAGETSELECTEVENT(lp),
                            (int)WSAGETSELECTERROR(lp));
        return 0;

    case WM_NC_DNS: {
        struct hostent    *he;
        struct sockaddr_in addr;
        NcSession *s = session_by_dnstask((HANDLE)wp);
        int dns_err  = WSAGETASYNCERROR(lp);
        char msg[288];
        if (!s) return 0;
        s->dns_task = NULL;
        if (dns_err) {
            sprintf(msg, "[DNS failed for '%s': error %d]\r\n",
                    s->host, dns_err);
            session_append(s, msg);
            session_close(s);
            return 0;
        }
        he = (struct hostent *)s->dns_buf;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);
        addr.sin_port = htons((unsigned short)s->port);
        WSAAsyncSelect(s->sock, g_frame, WM_NC_SOCKET,
                       FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE);
        connect(s->sock, (struct sockaddr *)&addr, sizeof(addr));
        s->state = NS_CONNECTING;
        session_set_title(s);
        sprintf(msg, "[connecting to %s:%d%s]\r\n",
                s->host, s->port, s->tls ? " (TLS)" : "");
        session_append(s, msg);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDM_FILE_NEW:
            if (show_new_conn_dialog() && g_dlg_ok) {
                int port = atoi(g_dlg_port_buf);
                if (port > 0 && port <= 65535)
                    new_session(g_dlg_host_buf, port,
                                g_dlg_tls_val, g_dlg_listen_val);
            }
            return 0;

        case IDM_FILE_DISCONNECT: {
            HWND active = (HWND)SendMessage(g_mdi, WM_MDIGETACTIVE, 0, NULL);
            if (active) {
                NcSession *s = (NcSession *)GetWindowLong(active, GWL_USERDATA);
                session_close(s);
            }
            return 0;
        }

        case IDM_FILE_EXIT:
            DestroyWindow(hwnd);
            return 0;

        case IDM_WIN_TILE_H:
            SendMessage(g_mdi, WM_MDITILE, MDITILE_HORIZONTAL, 0);
            return 0;
        case IDM_WIN_TILE_V:
            SendMessage(g_mdi, WM_MDITILE, MDITILE_VERTICAL, 0);
            return 0;
        case IDM_WIN_CASCADE:
            SendMessage(g_mdi, WM_MDICASCADE, 0, 0);
            return 0;
        case IDM_WIN_CLOSEALL: {
            int i;
            for (i = 0; i < MAX_SESSIONS; i++)
                if (g_sess[i]) session_close(g_sess[i]);
            return 0;
        }

        case IDM_HELP_ABOUT:
            MessageBox(hwnd,
                "ncwfw  -  MDI Netcat for Windows\r\n"
                "Plain TCP and TLS (Windows Schannel) sessions.\r\n\r\n"
                "Part of the putty-win32s project.",
                "About ncwfw", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        break;

    case WM_DESTROY:
        if (g_bg_brush) { DeleteObject(g_bg_brush); g_bg_brush = NULL; }
        PostQuitMessage(0);
        return 0;
    }
    return DefFrameProc(hwnd, g_mdi, msg, wp, lp);
}

/* ================================================================
 * WinMain
 * ================================================================ */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASS wc;
    MSG      msg;
    WSADATA  wsd;

    g_hinst = hInst;

    if (WSAStartup(MAKEWORD(1, 1), &wsd) != 0) {
        MessageBox(NULL, "WSAStartup failed.", "ncwfw", MB_OK | MB_ICONSTOP);
        return 1;
    }

    tls_load();

    if (!hPrev) {
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = DlgProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = "NcWfwDlg";
        RegisterClass(&wc);

        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = ChildProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = "NcWfwChild";
        RegisterClass(&wc);

        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = FrameProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_APPWORKSPACE + 1);
        wc.lpszClassName = "NcWfwFrame";
        RegisterClass(&wc);
    }

    g_frame = CreateWindow("NcWfwFrame", "ncwfw",
                  WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                  CW_USEDEFAULT, CW_USEDEFAULT,
                  800, 500, NULL, build_menu(), hInst, NULL);
    if (!g_frame) return 1;

    ShowWindow(g_frame, nCmdShow);
    UpdateWindow(g_frame);

    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!TranslateMDISysAccel(g_mdi, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    if (!hPrev) {
        UnregisterClass("NcWfwFrame", hInst);
        UnregisterClass("NcWfwChild", hInst);
        UnregisterClass("NcWfwDlg",   hInst);
    }
    if (g_secur32) FreeLibrary(g_secur32);
    WSACleanup();
    return (int)msg.wParam;
}
