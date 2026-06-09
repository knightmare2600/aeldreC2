/*
 * dumont.c  --  AeldreC2  --  Network Mapper
 *
 * Named after Dumont, the I/O Tower Guardian in Tron.
 * He guards the towers.  Dumont guards your network map.
 *
 * In fond memory of Hughes — the Bear — whose enthusiasm for network
 * diagrams sketched on whiteboards at unreasonable hours was an
 * inspiration to those who worked alongside him.  He would have
 * appreciated a tool like this, and probably have had opinions about
 * the colour scheme.
 *
 * Reads the tab-delimited output produced by grid.exe and renders a
 * scrollable node map: each discovered host appears as a labelled box
 * with its open ports and service names listed inside.  Hosts are
 * arranged in a grid, sorted by IP address, grouped by /24 subnet.
 *
 * Input format (grid -q output, one line per open port):
 *   HOST <TAB> PORT/tcp <TAB> open <TAB> SERVICE <TAB> BANNER
 *
 * Usage:
 *   dumont.exe [scanfile.tsv]
 *   grid 10.0.0.0/24 -p 1-1024 -q | dumont.exe   (stdin)
 *   dumont.exe                                     (File > Open)
 *
 * Build:
 *   wcl386 -za99 -bt=nt -l=nt_win -ox dumont.c comdlg32.lib
 *   wrc dumont.res dumont.exe
 *
 * Targets: Win32s / NT 3.1+ / Windows 95+
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include "aeldre_theme.h"

static int g_theme_idx = 0;
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Layout constants                                                    */
/* ------------------------------------------------------------------ */

#define NODE_W      210    /* width of each host box, pixels          */
#define NODE_H       88    /* height of each host box, pixels         */
#define NODE_GAP_X   18    /* horizontal gap between boxes            */
#define NODE_GAP_Y   18    /* vertical gap between boxes              */
#define NODE_COLS     4    /* boxes per row                           */
#define CANVAS_PAD   16    /* margin around the whole map             */

/* ------------------------------------------------------------------ */
/* Data model                                                          */
/* ------------------------------------------------------------------ */

#define MAX_HOSTS   512
#define MAX_PORTS   128

typedef struct {
    char host[256];
    char subnet[64];      /* first three octets, e.g. "10.0.0"        */
    int  ports[MAX_PORTS];
    char svcs [MAX_PORTS][24];
    int  nports;
} DHost;

static DHost  g_hosts[MAX_HOSTS];
static int    g_nhosts = 0;

/* ------------------------------------------------------------------ */
/* IDs                                                                 */
/* ------------------------------------------------------------------ */

#define IDM_FILE_OPEN      101
#define IDM_FILE_RELOAD    102
#define IDM_FILE_EXPORT    103
#define IDM_FILE_EXIT      104
#define IDM_VIEW_LABELS    110
#define IDM_VIEW_SUBNETS   111
#define IDM_VIEW_ZOOMIN    112
#define IDM_VIEW_ZOOMOUT   113
#define IDM_HELP_ABOUT     120

#define IDC_STATUS         201

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hinst    = NULL;
static HWND      g_hwnd     = NULL;
static HWND      g_status   = NULL;

static char g_path[MAX_PATH] = "";

static int g_show_labels  = 1;   /* show service names inside boxes  */
static int g_show_subnets = 1;   /* draw subnet group borders        */
static int g_zoom         = 100; /* zoom percent: 50 / 75 / 100 / 125 / 150 */

static int g_scroll_x = 0;
static int g_scroll_y = 0;

static const int STATUS_H = 22;

/* ------------------------------------------------------------------ */
/* IP sort helper — sort hosts numerically by dotted-quad address     */
/* ------------------------------------------------------------------ */
static int ip_key(const char *h)
{
    int a=0,b=0,c=0,d=0;
    sscanf(h, "%d.%d.%d.%d", &a,&b,&c,&d);
    return (a<<24)|(b<<16)|(c<<8)|d;
}

static int cmp_host(const void *pa, const void *pb)
{
    return ip_key(((DHost*)pa)->host) - ip_key(((DHost*)pb)->host);
}

/* ------------------------------------------------------------------ */
/* Find or create a host entry                                         */
/* ------------------------------------------------------------------ */
static DHost *get_host(const char *name)
{
    int i;
    for (i = 0; i < g_nhosts; i++)
        if (lstrcmpi(g_hosts[i].host, name) == 0) return &g_hosts[i];
    if (g_nhosts >= MAX_HOSTS) return NULL;
    memset(&g_hosts[g_nhosts], 0, sizeof(DHost));
    lstrcpyn(g_hosts[g_nhosts].host, name, 255);
    /* Derive /24 subnet from the first three octets                   */
    { int a=0,b=0,c=0,d=0; char *p;
      sscanf(name,"%d.%d.%d.%d",&a,&b,&c,&d);
      wsprintf(g_hosts[g_nhosts].subnet,"%d.%d.%d",a,b,c);
      (void)d; (void)p; }
    return &g_hosts[g_nhosts++];
}

/* ------------------------------------------------------------------ */
/* Parse grid TSV output                                               */
/* HOST <TAB> PORT/tcp <TAB> open <TAB> SERVICE <TAB> BANNER          */
/* ------------------------------------------------------------------ */
static int parse_tsv(const char *buf, long len)
{
    const char *p   = buf;
    const char *end = buf + len;
    int         added = 0;

    g_nhosts = 0;

    while (p < end) {
        const char *nl  = memchr(p, '\n', (size_t)(end - p));
        const char *eol = nl ? nl : end;
        char line[1024], host[256], portstr[32], svc[64];
        int  llen = (int)(eol - p);
        int  port;
        DHost *h;

        if (llen <= 0 || llen >= (int)sizeof(line)) { p = eol+1; continue; }
        memcpy(line, p, (size_t)llen);
        line[llen] = '\0';
        /* Strip \r                                                    */
        if (llen > 0 && line[llen-1] == '\r') line[--llen] = '\0';
        p = eol + 1;

        /* Skip comment / header lines                                 */
        if (line[0] == '#' || line[0] == '\0') continue;

        host[0] = portstr[0] = svc[0] = '\0';
        { /* Tokenise on TAB */
            char *t = line, *f;
            /* field 0: host */
            f = strchr(t,'\t'); if(!f) continue;
            *f='\0'; lstrcpyn(host,t,255); t=f+1;
            /* field 1: PORT/tcp */
            f = strchr(t,'\t'); if(!f) f = t + lstrlen(t);
            else *f='\0'; lstrcpyn(portstr,t,31); t=f+1;
            /* field 2: open (skip) */
            f = strchr(t,'\t'); if(f){*f='\0';t=f+1;}
            /* field 3: service */
            f = strchr(t,'\t'); if(f) *f='\0';
            lstrcpyn(svc,t,63);
        }

        port = atoi(portstr);
        if (port <= 0 || port > 65535) continue;
        if (!host[0]) continue;

        h = get_host(host);
        if (!h) continue;
        if (h->nports < MAX_PORTS) {
            h->ports[h->nports] = port;
            lstrcpyn(h->svcs[h->nports], svc[0] ? svc : portstr, 23);
            h->nports++;
            added++;
        }
    }

    /* Sort by IP so subnets group naturally                           */
    qsort(g_hosts, (size_t)g_nhosts, sizeof(DHost), cmp_host);
    return added;
}

/* ------------------------------------------------------------------ */
/* Load from file                                                      */
/* ------------------------------------------------------------------ */
static int load_file(const char *path)
{
    FILE *f;
    long  sz;
    char *buf;
    int   r;

    f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END); sz = ftell(f); rewind(f);
    if (sz <= 0) { fclose(f); return 0; }
    buf = (char *)malloc((size_t)sz + 2);
    if (!buf) { fclose(f); return 0; }
    sz = (long)fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[sz] = '\0';
    r = parse_tsv(buf, sz);
    free(buf);
    return r;
}

/* ------------------------------------------------------------------ */
/* Scaled node dimensions                                              */
/* ------------------------------------------------------------------ */
static int scaled(int v) { return v * g_zoom / 100; }

/* ------------------------------------------------------------------ */
/* Compute the full canvas size                                        */
/* ------------------------------------------------------------------ */
static void canvas_size(int *w, int *h)
{
    int rows = g_nhosts > 0 ? (g_nhosts + NODE_COLS - 1) / NODE_COLS : 1;
    *w = CANVAS_PAD*2 + NODE_COLS * scaled(NODE_W) + (NODE_COLS-1) * scaled(NODE_GAP_X);
    *h = CANVAS_PAD*2 + rows     * scaled(NODE_H)  + (rows -1)     * scaled(NODE_GAP_Y);
}

/* ------------------------------------------------------------------ */
/* Update scrollbars to match canvas vs client area                   */
/* ------------------------------------------------------------------ */
static void update_scrollbars(HWND hwnd)
{
    RECT    rc;
    SCROLLINFO si;
    int cw, ch;
    canvas_size(&cw, &ch);
    GetClientRect(hwnd, &rc);
    rc.bottom -= STATUS_H;

    si.cbSize = sizeof(si); si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;

    si.nMin  = 0; si.nMax  = cw; si.nPage = (UINT)rc.right;  si.nPos = g_scroll_x;
    SetScrollInfo(hwnd, SB_HORZ, &si, TRUE);

    si.nMin  = 0; si.nMax  = ch; si.nPage = (UINT)rc.bottom; si.nPos = g_scroll_y;
    SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
}

/* ------------------------------------------------------------------ */
/* Repaint — draw the node map into a memory DC then blit             */
/* ------------------------------------------------------------------ */
static void paint_map(HWND hwnd, HDC hdc, RECT *clip)
{
    RECT     cr;
    HDC      mdc;
    HBITMAP  bmp, old_bmp;
    HFONT    hf_host, hf_port, hf_old;
    HPEN     pen_box, pen_sub, pen_old;
    HBRUSH   br_bg, br_node, br_old;
    int      i, cw, ch;
    (void)clip;

    GetClientRect(hwnd, &cr);
    cr.bottom -= STATUS_H;

    /* Off-screen buffer                                               */
    mdc     = CreateCompatibleDC(hdc);
    bmp     = CreateCompatibleBitmap(hdc, cr.right, cr.bottom);
    old_bmp = (HBITMAP)SelectObject(mdc, bmp);

    /* Background                                                      */
    br_bg = CreateSolidBrush(g_aeldre_themes[g_theme_idx].bg);
    { RECT all; SetRect(&all,0,0,cr.right,cr.bottom); FillRect(mdc,&all,br_bg); }
    DeleteObject(br_bg);

    if (g_nhosts == 0) {
        SetBkMode(mdc, TRANSPARENT);
        SetTextColor(mdc, RGB(120,120,120));
        SelectObject(mdc, GetStockObject(DEFAULT_GUI_FONT));
        { RECT tr = cr;
          DrawText(mdc,
              "No hosts loaded.\r\n\r\n"
              "Use File > Open to load grid scan output,\r\n"
              "or run:  grid <target> -p <ports> -q > scan.tsv",
              -1, &tr, DT_CENTER | DT_VCENTER | DT_NOPREFIX); }
        goto blit;
    }

    canvas_size(&cw, &ch);

    hf_host = CreateFont(-MulDiv(8, GetDeviceCaps(mdc,LOGPIXELSY),72),
                         0,0,0,FW_BOLD,0,0,0,ANSI_CHARSET,
                         OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
                         DEFAULT_QUALITY,DEFAULT_PITCH|FF_DONTCARE,"Arial");
    hf_port = CreateFont(-MulDiv(7, GetDeviceCaps(mdc,LOGPIXELSY),72),
                         0,0,0,FW_NORMAL,0,0,0,ANSI_CHARSET,
                         OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
                         DEFAULT_QUALITY,DEFAULT_PITCH|FF_DONTCARE,"Arial");

    pen_box = CreatePen(PS_SOLID, 1, RGB(85, 153, 204));
    pen_sub = CreatePen(PS_DOT,   1, RGB(60,  90, 120));
    br_node = CreateSolidBrush(RGB(42, 58, 74));

    SetBkMode(mdc, TRANSPARENT);

    /* If subnet grouping is on, draw a faint border around each /24  */
    if (g_show_subnets) {
        char cur_sub[64] = "";
        int  grp_start = 0;
        pen_old = (HPEN)SelectObject(mdc, pen_sub);
        br_old  = (HBRUSH)SelectObject(mdc, GetStockObject(NULL_BRUSH));
        for (i = 0; i <= g_nhosts; i++) {
            const char *sub = (i < g_nhosts) ? g_hosts[i].subnet : "";
            if (lstrcmp(sub, cur_sub) != 0 || i == g_nhosts) {
                if (cur_sub[0] && i > grp_start) {
                    /* Draw a box around grp_start..i-1               */
                    int r0 = grp_start / NODE_COLS;
                    int r1 = (i-1)     / NODE_COLS;
                    int c0 = grp_start % NODE_COLS;
                    int c1 = (i-1)     % NODE_COLS;
                    int x0 = CANVAS_PAD + c0 * (scaled(NODE_W) + scaled(NODE_GAP_X)) - g_scroll_x - 4;
                    int y0 = CANVAS_PAD + r0 * (scaled(NODE_H) + scaled(NODE_GAP_Y)) - g_scroll_y - 4;
                    int x1, y1;
                    /* Multi-row groups span full width                */
                    if (r1 > r0) {
                        x0 = CANVAS_PAD - g_scroll_x - 4;
                        c1 = NODE_COLS - 1;
                    }
                    x1 = CANVAS_PAD + (c1+1) * scaled(NODE_W) + c1 * scaled(NODE_GAP_X) - g_scroll_x + 4;
                    y1 = CANVAS_PAD + (r1+1) * scaled(NODE_H) + r1 * scaled(NODE_GAP_Y) - g_scroll_y + 4;
                    Rectangle(mdc, x0, y0, x1, y1);
                    /* Label the subnet                                */
                    SetTextColor(mdc, RGB(60,90,120));
                    SelectObject(mdc, hf_port);
                    { RECT tr; tr.left=x0+4; tr.top=y0+2; tr.right=x1; tr.bottom=y0+14;
                      DrawText(mdc, cur_sub, -1, &tr, DT_LEFT|DT_NOPREFIX|DT_SINGLELINE); }
                }
                lstrcpyn(cur_sub, sub, 63);
                grp_start = i;
            }
        }
        SelectObject(mdc, pen_old);
        SelectObject(mdc, br_old);
    }

    /* Draw each host node                                             */
    hf_old  = (HFONT) SelectObject(mdc, hf_host);
    pen_old = (HPEN)  SelectObject(mdc, pen_box);
    br_old  = (HBRUSH)SelectObject(mdc, br_node);

    for (i = 0; i < g_nhosts; i++) {
        DHost *h   = &g_hosts[i];
        int    row = i / NODE_COLS;
        int    col = i % NODE_COLS;
        int    x   = CANVAS_PAD + col * (scaled(NODE_W) + scaled(NODE_GAP_X)) - g_scroll_x;
        int    y   = CANVAS_PAD + row * (scaled(NODE_H) + scaled(NODE_GAP_Y)) - g_scroll_y;
        RECT   nr;
        char   portbuf[256];
        int    j, used=0;

        nr.left = x; nr.top = y; nr.right = x+scaled(NODE_W); nr.bottom = y+scaled(NODE_H);

        /* Skip nodes entirely outside the clip region                 */
        if (nr.right < 0 || nr.bottom < 0 || nr.left > cr.right || nr.top > cr.bottom)
            continue;

        /* Box + hostname header bar                                   */
        Rectangle(mdc, nr.left, nr.top, nr.right, nr.bottom);
        { HBRUSH hb = CreateSolidBrush(g_aeldre_themes[g_theme_idx].strip);
          RECT hdr; SetRect(&hdr, nr.left+1, nr.top+1, nr.right-1, nr.top+scaled(18));
          FillRect(mdc, &hdr, hb);
          DeleteObject(hb); }

        /* Hostname                                                    */
        SetTextColor(mdc, g_aeldre_themes[g_theme_idx].title);
        SelectObject(mdc, hf_host);
        { RECT tr; SetRect(&tr, nr.left+5, nr.top+2, nr.right-3, nr.top+scaled(18));
          DrawText(mdc, h->host, -1, &tr, DT_LEFT|DT_NOPREFIX|DT_SINGLELINE|DT_END_ELLIPSIS); }

        /* Port / service list                                         */
        SelectObject(mdc, hf_port);
        SetTextColor(mdc, g_aeldre_themes[g_theme_idx].body);
        portbuf[0] = '\0';
        for (j = 0; j < h->nports && j < 6; j++) {
            char entry[48];
            if (g_show_labels && h->svcs[j][0])
                wsprintf(entry, "%d/%s  ", h->ports[j], h->svcs[j]);
            else
                wsprintf(entry, "%d  ", h->ports[j]);
            if (used + lstrlen(entry) < (int)sizeof(portbuf) - 4) {
                lstrcat(portbuf, entry);
                used += lstrlen(entry);
            }
        }
        if (h->nports > 6) lstrcat(portbuf, "...");
        { RECT tr; SetRect(&tr, nr.left+5, nr.top+scaled(22), nr.right-3, nr.bottom-3);
          DrawText(mdc, portbuf, -1, &tr, DT_LEFT|DT_NOPREFIX|DT_WORDBREAK); }
    }

    SelectObject(mdc, hf_old);
    SelectObject(mdc, pen_old);
    SelectObject(mdc, br_old);
    DeleteObject(hf_host);
    DeleteObject(hf_port);
    DeleteObject(pen_box);
    DeleteObject(pen_sub);
    DeleteObject(br_node);

blit:
    BitBlt(hdc, 0, 0, cr.right, cr.bottom, mdc, 0, 0, SRCCOPY);
    SelectObject(mdc, old_bmp);
    DeleteObject(bmp);
    DeleteDC(mdc);
}

/* ------------------------------------------------------------------ */
/* Update the status bar                                               */
/* ------------------------------------------------------------------ */
static void update_status(void)
{
    char buf[MAX_PATH + 64];
    const char *leaf = strrchr(g_path, '\\');
    if (leaf) leaf++; else if (g_path[0]) leaf = g_path; else leaf = "(no file)";
    wsprintf(buf, "  %s     %d host%s     Zoom: %d%%",
             leaf, g_nhosts, g_nhosts == 1 ? "" : "s", g_zoom);
    SetWindowText(g_status, buf);
}

/* ------------------------------------------------------------------ */
/* Export map as plain text to clipboard                               */
/* ------------------------------------------------------------------ */
static void export_clipboard(void)
{
    int    i, j;
    char  *buf;
    int    sz = g_nhosts * (256 + MAX_PORTS * 32) + 256;

    buf = (char *)malloc((size_t)sz);
    if (!buf) return;
    buf[0] = '\0';

    /* Header — Dumont would approve of a nice header                 */
    lstrcat(buf, "=== AeldreC2 Dumont  --  Network Map ===\r\n\r\n");
    for (i = 0; i < g_nhosts; i++) {
        DHost *h = &g_hosts[i];
        char row[256];
        wsprintf(row, "%-20s  ", h->host);
        lstrcat(buf, row);
        for (j = 0; j < h->nports; j++) {
            wsprintf(row, "%d", h->ports[j]);
            if (h->svcs[j][0]) { lstrcat(row, "/"); lstrcat(row, h->svcs[j]); }
            lstrcat(buf, row);
            if (j < h->nports - 1) lstrcat(buf, "  ");
        }
        lstrcat(buf, "\r\n");
    }

    if (OpenClipboard(g_hwnd)) {
        HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)lstrlen(buf) + 1);
        if (hg) {
            char *p = (char *)GlobalLock(hg);
            if (p) { lstrcpy(p, buf); GlobalUnlock(hg); }
            EmptyClipboard();
            SetClipboardData(CF_TEXT, hg);
        }
        CloseClipboard();
    }
    free(buf);
}

/* ------------------------------------------------------------------ */
/* Browse for a TSV file                                               */
/* ------------------------------------------------------------------ */
static int browse_open(void)
{
    OPENFILENAME ofn;
    char buf[MAX_PATH];
    lstrcpyn(buf, g_path, MAX_PATH);
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hwnd;
    ofn.lpstrFilter = "Scan files (*.tsv;*.txt)\0*.tsv;*.txt\0All files\0*.*\0\0";
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = "Open Grid Scan Output";
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileName(&ofn)) return 0;
    lstrcpyn(g_path, buf, MAX_PATH);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Window procedure                                                    */
/* ------------------------------------------------------------------ */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_CREATE: {
        RECT rc;
        g_theme_idx = aeldre_theme_load();
        GetClientRect(hwnd, &rc);
        g_status = CreateWindow("STATIC","  (no file)",
                       WS_CHILD|WS_VISIBLE|SS_LEFT,
                       0,rc.bottom-STATUS_H,rc.right,STATUS_H,
                       hwnd,(HMENU)IDC_STATUS,g_hinst,NULL);
        SendMessage(g_status,WM_SETFONT,(WPARAM)GetStockObject(DEFAULT_GUI_FONT),FALSE);
        return 0;
    }

    case WM_SIZE: {
        int w=(int)LOWORD(lp), h=(int)HIWORD(lp);
        if (g_status) MoveWindow(g_status,0,h-STATUS_H,w,STATUS_H,TRUE);
        update_scrollbars(hwnd);
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        paint_map(hwnd, dc, &ps.rcPaint);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_HSCROLL: {
        SCROLLINFO si; si.cbSize=sizeof(si); si.fMask=SIF_ALL;
        GetScrollInfo(hwnd,SB_HORZ,&si);
        switch(LOWORD(wp)){
        case SB_LINELEFT:  si.nPos-=scaled(NODE_W)/4; break;
        case SB_LINERIGHT: si.nPos+=scaled(NODE_W)/4; break;
        case SB_PAGELEFT:  si.nPos-=(int)si.nPage;    break;
        case SB_PAGERIGHT: si.nPos+=(int)si.nPage;    break;
        case SB_THUMBTRACK:si.nPos=si.nTrackPos;       break;
        }
        si.fMask=SIF_POS; SetScrollInfo(hwnd,SB_HORZ,&si,TRUE);
        GetScrollInfo(hwnd,SB_HORZ,&si); g_scroll_x=si.nPos;
        InvalidateRect(hwnd,NULL,FALSE); return 0;
    }

    case WM_VSCROLL: {
        SCROLLINFO si; si.cbSize=sizeof(si); si.fMask=SIF_ALL;
        GetScrollInfo(hwnd,SB_VERT,&si);
        switch(LOWORD(wp)){
        case SB_LINEUP:   si.nPos-=scaled(NODE_H)/4; break;
        case SB_LINEDOWN: si.nPos+=scaled(NODE_H)/4; break;
        case SB_PAGEUP:   si.nPos-=(int)si.nPage;    break;
        case SB_PAGEDOWN: si.nPos+=(int)si.nPage;    break;
        case SB_THUMBTRACK:si.nPos=si.nTrackPos;      break;
        }
        si.fMask=SIF_POS; SetScrollInfo(hwnd,SB_VERT,&si,TRUE);
        GetScrollInfo(hwnd,SB_VERT,&si); g_scroll_y=si.nPos;
        InvalidateRect(hwnd,NULL,FALSE); return 0;
    }

    case WM_MOUSEWHEEL: {
        int delta = (short)HIWORD(wp);
        g_scroll_y -= delta / 3;
        if (g_scroll_y < 0) g_scroll_y = 0;
        update_scrollbars(hwnd);
        InvalidateRect(hwnd,NULL,FALSE); return 0;
    }

    case WM_KEYDOWN:
        if (wp == VK_F5) PostMessage(hwnd,WM_COMMAND,IDM_FILE_RELOAD,0);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {

        case IDM_FILE_OPEN:
            if (browse_open()) {
                load_file(g_path);
                g_scroll_x = g_scroll_y = 0;
                update_scrollbars(hwnd);
                update_status();
                InvalidateRect(hwnd,NULL,FALSE);
            }
            return 0;

        case IDM_FILE_RELOAD:
            if (g_path[0]) {
                load_file(g_path);
                g_scroll_x = g_scroll_y = 0;
                update_scrollbars(hwnd);
                update_status();
                InvalidateRect(hwnd,NULL,FALSE);
            }
            return 0;

        case IDM_FILE_EXPORT:
            export_clipboard();
            MessageBox(hwnd,"Map copied to clipboard.","Dumont",MB_OK|MB_ICONINFORMATION);
            return 0;

        case IDM_FILE_EXIT:
            DestroyWindow(hwnd); return 0;

        case IDM_VIEW_LABELS:
            g_show_labels = !g_show_labels;
            CheckMenuItem(GetMenu(hwnd),IDM_VIEW_LABELS,MF_BYCOMMAND|
                          (g_show_labels?MF_CHECKED:MF_UNCHECKED));
            InvalidateRect(hwnd,NULL,FALSE); return 0;

        case IDM_VIEW_SUBNETS:
            g_show_subnets = !g_show_subnets;
            CheckMenuItem(GetMenu(hwnd),IDM_VIEW_SUBNETS,MF_BYCOMMAND|
                          (g_show_subnets?MF_CHECKED:MF_UNCHECKED));
            InvalidateRect(hwnd,NULL,FALSE); return 0;

        case IDM_VIEW_ZOOMIN:
            if (g_zoom < 150) g_zoom += 25;
            update_scrollbars(hwnd);
            update_status();
            InvalidateRect(hwnd,NULL,FALSE); return 0;

        case IDM_VIEW_ZOOMOUT:
            if (g_zoom > 50) g_zoom -= 25;
            update_scrollbars(hwnd);
            update_status();
            InvalidateRect(hwnd,NULL,FALSE); return 0;

        case IDM_HELP_ABOUT:
            MessageBox(hwnd,
                "Dumont  \x97  AeldreC2 Network Mapper\r\n\r\n"
                "Named after Dumont, the I/O Tower Guardian in Tron.\r\n"
                "He guards the towers.\r\n\r\n"
                "Reads grid scan output (tab-delimited).\r\n"
                "F5 to reload.  View > Zoom to adjust.\r\n"
                "File > Export copies the map as plain text.\r\n\r\n"
                "\xc6ldreC2  \x97  Retro C2 for the masses.",
                "About Dumont",MB_OK|MB_ICONINFORMATION);
            return 0;
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0); return 0;
    }
    return DefWindowProc(hwnd,msg,wp,lp);
}

/* ------------------------------------------------------------------ */
/* Menu                                                                */
/* ------------------------------------------------------------------ */
static HMENU build_menu(void)
{
    HMENU bar  = CreateMenu();
    HMENU file = CreatePopupMenu();
    HMENU view = CreatePopupMenu();
    HMENU help = CreatePopupMenu();

    AppendMenu(file,MF_STRING,    IDM_FILE_OPEN,   "&Open...\tCtrl+O");
    AppendMenu(file,MF_STRING,    IDM_FILE_RELOAD, "&Reload\tF5");
    AppendMenu(file,MF_SEPARATOR, 0,NULL);
    AppendMenu(file,MF_STRING,    IDM_FILE_EXPORT, "&Copy Map to Clipboard");
    AppendMenu(file,MF_SEPARATOR, 0,NULL);
    AppendMenu(file,MF_STRING,    IDM_FILE_EXIT,   "E&xit");

    AppendMenu(view,MF_STRING|MF_CHECKED, IDM_VIEW_LABELS,  "&Service Labels");
    AppendMenu(view,MF_STRING|MF_CHECKED, IDM_VIEW_SUBNETS, "S&ubnet Groups");
    AppendMenu(view,MF_SEPARATOR,0,NULL);
    AppendMenu(view,MF_STRING,IDM_VIEW_ZOOMIN,  "Zoom &In\t+");
    AppendMenu(view,MF_STRING,IDM_VIEW_ZOOMOUT, "Zoom &Out\t-");

    AppendMenu(help,MF_STRING,IDM_HELP_ABOUT,"&About");

    AppendMenu(bar,MF_POPUP,(UINT)file,"&File");
    AppendMenu(bar,MF_POPUP,(UINT)view,"&View");
    AppendMenu(bar,MF_POPUP,(UINT)help,"&Help");
    return bar;
}

/* ------------------------------------------------------------------ */
/* WinMain                                                             */
/* ------------------------------------------------------------------ */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASS wc;
    MSG      msg;

    g_hinst = hInst;

    /* Accept a scan file or piped stdin from command line             */
    if (lpCmdLine && lpCmdLine[0]) {
        char *p = lpCmdLine;
        if (*p == '"') { p++; lstrcpyn(g_path,p,MAX_PATH); { char *q=strchr(g_path,'"'); if(q)*q='\0'; } }
        else lstrcpyn(g_path,p,MAX_PATH);
    }

    /* Check for piped stdin — grid | dumont                          */
    if (!g_path[0]) {
        HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
        if (hin && hin != INVALID_HANDLE_VALUE &&
            GetFileType(hin) == FILE_TYPE_PIPE) {
            char  chunk[4096]; char *stdinbuf = NULL;
            DWORD got; long total = 0;
            /* Read all piped input                                    */
            while (ReadFile(hin,chunk,sizeof(chunk)-1,&got,NULL) && got > 0) {
                char *nb = (char*)realloc(stdinbuf,(size_t)(total+got+2));
                if (!nb) break;
                stdinbuf = nb;
                memcpy(stdinbuf+total,chunk,(size_t)got);
                total += got;
            }
            if (stdinbuf && total > 0) {
                stdinbuf[total] = '\0';
                parse_tsv(stdinbuf, total);
            }
            free(stdinbuf);
        }
    }

    if (!hPrev) {
        memset(&wc,0,sizeof(wc));
        wc.lpfnWndProc   = WndProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL,IDC_ARROW);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName = "DumontFrame";
        wc.hIcon         = LoadIcon(NULL,IDI_APPLICATION);
        wc.style         = CS_HREDRAW|CS_VREDRAW;
        RegisterClass(&wc);
    }

    g_hwnd = CreateWindow("DumontFrame",
                          "Dumont  \x97  AeldreC2 Network Mapper",
                          WS_OVERLAPPEDWINDOW|WS_HSCROLL|WS_VSCROLL,
                          CW_USEDEFAULT,CW_USEDEFAULT,960,680,
                          NULL,build_menu(),hInst,NULL);
    if (!g_hwnd) return 1;

    /* Load file if given on command line                              */
    if (g_path[0]) load_file(g_path);
    update_status();
    update_scrollbars(g_hwnd);

    ShowWindow(g_hwnd,nCmdShow);
    UpdateWindow(g_hwnd);

    while (GetMessage(&msg,NULL,0,0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
