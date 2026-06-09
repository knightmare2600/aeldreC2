/*
 * markuped.c  --  Win32s/Win32 Markdown editor (split-pane, live preview)
 *
 * Left pane:  multi-line EDIT control (raw Markdown source)
 * Right pane: custom preview window (rendered output)
 * Draggable splitter between the two panes
 *
 * Rendering: headers, bold/italic, inline code, fenced code blocks,
 * blockquotes, unordered/ordered lists, horizontal rules.
 *
 * Toolbar:  New | Open | Save | [B] [I] [H1] [H2] [H3] [``] [```] [>] [---] [-]
 * Menus:    File / Edit / Format / View / Help
 *
 * Build:
 *   wcl386 -bt=nt -l=nt_win -za99 -ox -D_WIN32 markuped.c comdlg32.lib
 */

#include <windows.h>
#include <commdlg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "aeldre_theme.h"

static int    g_theme_idx = 0;
static HBRUSH g_bg_brush  = NULL;

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define APP_NAME   "markuped"
#define APP_TITLE  "markuped \x97 Markdown Editor"
#define PREVIEW_CLS "MarkupedPreview"

#define TOOLBAR_H   30
#define SPLIT_W      4
#define DEF_SPLIT   400

#define IDC_EDITOR   100
#define IDM_NEW      1001
#define IDM_OPEN     1002
#define IDM_SAVE     1003
#define IDM_SAVEAS   1004
#define IDM_EXIT     1005
#define IDM_UNDO     1011
#define IDM_CUT      1012
#define IDM_COPY     1013
#define IDM_PASTE    1014
#define IDM_SELALL   1015
#define IDM_BOLD     1021
#define IDM_ITALIC   1022
#define IDM_CODE     1023
#define IDM_CODEBLK  1024
#define IDM_H1       1025
#define IDM_H2       1026
#define IDM_H3       1027
#define IDM_BQUOTE   1028
#define IDM_LIST     1029
#define IDM_HR       1030
#define IDM_LINK     1031
#define IDM_TOGPREV  1040
#define IDM_ABOUT    1050

/* toolbar button IDs — offset from 200 */
#define IDB_NEW      201
#define IDB_OPEN     202
#define IDB_SAVE     203
#define IDB_BOLD     210
#define IDB_ITALIC   211
#define IDB_H1       212
#define IDB_H2       213
#define IDB_H3       214
#define IDB_CODE     215
#define IDB_CODEBLK  216
#define IDB_BQUOTE   217
#define IDB_HR       218
#define IDB_LIST     219

#define PREVIEW_TIMER  1
#define PREVIEW_DELAY  500

/* ------------------------------------------------------------------ */
/* Inline run types for the preview renderer                            */
/* ------------------------------------------------------------------ */
#define RT_NORMAL  0
#define RT_BOLD    1
#define RT_ITALIC  2
#define RT_BITALIC 3
#define RT_CODE    4

typedef struct {
    int  type;
    char text[512];
} InlineRun;

/* ------------------------------------------------------------------ */
/* Globals                                                              */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hinst       = NULL;
static HWND      g_hwnd_frame  = NULL;
static HWND      g_hwnd_edit   = NULL;
static HWND      g_hwnd_prev   = NULL;
static HWND     *g_toolbar_btns = NULL;
static int       g_ntoolbtns   = 0;

static int       g_split_x     = DEF_SPLIT;
static int       g_dragging    = 0;
static int       g_show_prev   = 1;

static char      g_filepath[MAX_PATH] = "";
static BOOL      g_dirty       = FALSE;

/* fonts for preview */
static HFONT g_font_body  = NULL;
static HFONT g_font_h1    = NULL;
static HFONT g_font_h2    = NULL;
static HFONT g_font_h3    = NULL;
static HFONT g_font_h4    = NULL;
static HFONT g_font_code  = NULL;
static HFONT g_font_bi    = NULL;

/* preview rendered lines (simple string list) */
#define MAX_PLINES 4096
typedef struct {
    int   indent;
    int   line_h;
    int   is_rule;
    int   is_codeblk;
    int   is_task;     /* 1=unchecked [ ], 2=checked [x] */
    int   src_line;    /* 0-based source line index for checkbox toggle */
    int   nruns;
    InlineRun runs[16];
    HFONT font;
} PreviewLine;

static PreviewLine g_plines[MAX_PLINES];
static int         g_nplines = 0;

/* Forward declaration */
static void preview_refresh(int reset_scroll);

/* ------------------------------------------------------------------ */
/* Font helpers                                                         */
/* ------------------------------------------------------------------ */

static HFONT make_font(const char *face, int pts, int bold, int italic)
{
    HDC  dc  = GetDC(NULL);
    int  lh  = -MulDiv(pts, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(NULL, dc);
    return CreateFont(lh, 0, 0, 0,
                      bold ? FW_BOLD : FW_NORMAL,
                      italic, FALSE, FALSE,
                      ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                      CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                      DEFAULT_PITCH | FF_DONTCARE, face);
}

static void fonts_create(void)
{
    g_font_body = make_font("Times New Roman", 11, 0, 0);
    g_font_h1   = make_font("Times New Roman", 22, 1, 0);
    g_font_h2   = make_font("Times New Roman", 18, 1, 0);
    g_font_h3   = make_font("Times New Roman", 14, 1, 0);
    g_font_h4   = make_font("Times New Roman", 12, 1, 0);
    g_font_code = make_font("Courier New", 10, 0, 0);
    g_font_bi   = make_font("Times New Roman", 11, 1, 1);
}

static void fonts_destroy(void)
{
    if (g_font_body)  { DeleteObject(g_font_body);  g_font_body  = NULL; }
    if (g_font_h1)    { DeleteObject(g_font_h1);    g_font_h1    = NULL; }
    if (g_font_h2)    { DeleteObject(g_font_h2);    g_font_h2    = NULL; }
    if (g_font_h3)    { DeleteObject(g_font_h3);    g_font_h3    = NULL; }
    if (g_font_h4)    { DeleteObject(g_font_h4);    g_font_h4    = NULL; }
    if (g_font_code)  { DeleteObject(g_font_code);  g_font_code  = NULL; }
    if (g_font_bi)    { DeleteObject(g_font_bi);    g_font_bi    = NULL; }
}

/* ------------------------------------------------------------------ */
/* Inline run tokenizer                                                 */
/* ------------------------------------------------------------------ */

static int parse_inline(const char *src, InlineRun *runs, int maxruns)
{
    int  n = 0;
    const char *p = src;
    char tmp[512];
    int  tlen;

    while (*p && n < maxruns - 1) {
        InlineRun *r = &runs[n];
        const char *start = p;
        int type = RT_NORMAL;

        if (p[0] == '`') {
            /* inline code */
            const char *end = strchr(p + 1, '`');
            if (end) {
                type = RT_CODE;
                tlen = (int)(end - p - 1);
                if (tlen >= (int)sizeof(tmp)) tlen = sizeof(tmp) - 1;
                memcpy(tmp, p + 1, tlen);
                tmp[tlen] = '\0';
                r->type = type;
                lstrcpynA(r->text, tmp, sizeof(r->text) - 1);
                n++;
                p = end + 1;
                continue;
            }
        } else if (p[0] == '*' && p[1] == '*' && p[2] == '*') {
            const char *end = strstr(p + 3, "***");
            if (end) {
                type = RT_BITALIC;
                tlen = (int)(end - p - 3);
                if (tlen >= (int)sizeof(tmp)) tlen = sizeof(tmp) - 1;
                memcpy(tmp, p + 3, tlen);
                tmp[tlen] = '\0';
                r->type = type;
                lstrcpynA(r->text, tmp, sizeof(r->text) - 1);
                n++;
                p = end + 3;
                continue;
            }
        } else if (p[0] == '*' && p[1] == '*') {
            const char *end = strstr(p + 2, "**");
            if (end) {
                type = RT_BOLD;
                tlen = (int)(end - p - 2);
                if (tlen >= (int)sizeof(tmp)) tlen = sizeof(tmp) - 1;
                memcpy(tmp, p + 2, tlen);
                tmp[tlen] = '\0';
                r->type = type;
                lstrcpynA(r->text, tmp, sizeof(r->text) - 1);
                n++;
                p = end + 2;
                continue;
            }
        } else if (p[0] == '_' && p[1] == '_') {
            const char *end = strstr(p + 2, "__");
            if (end) {
                type = RT_BOLD;
                tlen = (int)(end - p - 2);
                if (tlen >= (int)sizeof(tmp)) tlen = sizeof(tmp) - 1;
                memcpy(tmp, p + 2, tlen);
                tmp[tlen] = '\0';
                r->type = type;
                lstrcpynA(r->text, tmp, sizeof(r->text) - 1);
                n++;
                p = end + 2;
                continue;
            }
        } else if (p[0] == '*' || p[0] == '_') {
            char delim = p[0];
            const char *end = strchr(p + 1, delim);
            if (end) {
                type = RT_ITALIC;
                tlen = (int)(end - p - 1);
                if (tlen >= (int)sizeof(tmp)) tlen = sizeof(tmp) - 1;
                memcpy(tmp, p + 1, tlen);
                tmp[tlen] = '\0';
                r->type = type;
                lstrcpynA(r->text, tmp, sizeof(r->text) - 1);
                n++;
                p = end + 1;
                continue;
            }
        } else if (p[0] == '[') {
            /* link: [text](url) — render as "text" in normal style */
            const char *cb = strchr(p, ']');
            if (cb && cb[1] == '(') {
                const char *pe = strchr(cb + 2, ')');
                if (pe) {
                    tlen = (int)(cb - p - 1);
                    if (tlen >= (int)sizeof(tmp)) tlen = sizeof(tmp) - 1;
                    memcpy(tmp, p + 1, tlen);
                    tmp[tlen] = '\0';
                    r->type = RT_NORMAL;
                    lstrcpynA(r->text, tmp, sizeof(r->text) - 1);
                    n++;
                    p = pe + 1;
                    continue;
                }
            }
        }

        /* plain text: scan until next markup character */
        {
            const char *q = p + 1;
            while (*q && *q != '*' && *q != '_' && *q != '`' && *q != '[')
                q++;
            tlen = (int)(q - p);
            if (tlen >= (int)sizeof(tmp)) tlen = sizeof(tmp) - 1;
            memcpy(tmp, p, tlen);
            tmp[tlen] = '\0';
            r->type = RT_NORMAL;
            lstrcpynA(r->text, tmp, sizeof(r->text) - 1);
            n++;
            p = q;
        }

        (void)start; (void)type;
    }

    /* remaining text */
    if (*p && n < maxruns) {
        runs[n].type = RT_NORMAL;
        lstrcpynA(runs[n].text, p, sizeof(runs[n].text) - 1);
        n++;
    }

    return n;
}

/* ------------------------------------------------------------------ */
/* Markdown parser → PreviewLine array                                  */
/* ------------------------------------------------------------------ */

static void md_parse(const char *src)
{
    char line[1024];
    const char *p = src;
    int  in_code_block = 0;
    int  ni = 0;
    int  src_line_no = 0;

    g_nplines = 0;

    while (*p && g_nplines < MAX_PLINES - 1) {
        PreviewLine *pl = &g_plines[g_nplines];
        const char *nl;
        int llen;

        nl = strchr(p, '\n');
        if (nl) {
            llen = (int)(nl - p);
            if (llen > (int)sizeof(line) - 2) llen = sizeof(line) - 2;
            memcpy(line, p, llen);
            /* strip \r */
            if (llen > 0 && line[llen - 1] == '\r') llen--;
            line[llen] = '\0';
            p = nl + 1;
        } else {
            llen = (int)strlen(p);
            if (llen > (int)sizeof(line) - 2) llen = sizeof(line) - 2;
            memcpy(line, p, llen);
            line[llen] = '\0';
            p += llen;
        }

        memset(pl, 0, sizeof(*pl));
        pl->src_line = src_line_no++;  /* record before processing continues */

        /* fenced code block toggle */
        if (strncmp(line, "```", 3) == 0) {
            in_code_block = !in_code_block;
            g_nplines++;
            pl->is_codeblk = 2; /* sentinel: fence line (skip display) */
            pl->font = g_font_code;
            pl->line_h = 0;
            continue;
        }

        if (in_code_block) {
            pl->is_codeblk = 1;
            pl->font   = g_font_code;
            pl->indent = 8;
            pl->nruns  = 1;
            pl->runs[0].type = RT_CODE;
            lstrcpynA(pl->runs[0].text, line, sizeof(pl->runs[0].text) - 1);
            pl->line_h = 16;
            g_nplines++;
            continue;
        }

        /* horizontal rule */
        if ((strncmp(line, "---", 3) == 0 && llen >= 3) ||
            (strncmp(line, "***", 3) == 0 && llen >= 3) ||
            (strncmp(line, "___", 3) == 0 && llen >= 3)) {
            pl->is_rule = 1;
            pl->line_h  = 12;
            g_nplines++;
            continue;
        }

        /* headers */
        ni = 0;
        while (line[ni] == '#') ni++;
        if (ni > 0 && line[ni] == ' ') {
            const char *txt = line + ni + 1;
            pl->font   = (ni == 1) ? g_font_h1 :
                         (ni == 2) ? g_font_h2 :
                         (ni == 3) ? g_font_h3 : g_font_h4;
            pl->indent = 0;
            pl->line_h = (ni == 1) ? 32 : (ni == 2) ? 26 : (ni == 3) ? 20 : 18;
            pl->nruns  = parse_inline(txt, pl->runs,
                                      sizeof(pl->runs)/sizeof(pl->runs[0]));
            g_nplines++;
            continue;
        }

        /* blockquote */
        if (line[0] == '>' && (line[1] == ' ' || line[1] == '\0')) {
            pl->indent = 16;
            pl->font   = g_font_body;
            pl->line_h = 18;
            pl->nruns  = parse_inline(line[1] ? line + 2 : "",
                                      pl->runs,
                                      sizeof(pl->runs)/sizeof(pl->runs[0]));
            g_nplines++;
            continue;
        }

        /* unordered list / task list */
        if ((line[0] == '-' || line[0] == '*' || line[0] == '+') && line[1] == ' ') {
            const char *rest = line + 2;
            if (rest[0] == '[' &&
                (rest[1] == ' ' || rest[1] == 'x' || rest[1] == 'X') &&
                rest[2] == ']' && rest[3] == ' ') {
                /* GitHub-style task list item */
                pl->is_task = (rest[1] == 'x' || rest[1] == 'X') ? 2 : 1;
                pl->indent  = 24;
                pl->font    = g_font_body;
                pl->line_h  = 18;
                pl->nruns   = parse_inline(rest + 4, pl->runs,
                                           sizeof(pl->runs)/sizeof(pl->runs[0]));
                g_nplines++;
                continue;
            }
            {
                char bullet[1020];
                wsprintfA(bullet, "\x95 %s", rest);  /* bullet char */
                pl->indent = 8;
                pl->font   = g_font_body;
                pl->line_h = 18;
                pl->nruns  = parse_inline(bullet, pl->runs,
                                          sizeof(pl->runs)/sizeof(pl->runs[0]));
                g_nplines++;
                continue;
            }
        }

        /* ordered list  "1. " */
        if (line[0] >= '1' && line[0] <= '9') {
            const char *dot = strchr(line, '.');
            if (dot && dot[1] == ' ') {
                char prefix[16], combined[1040];
                int num = atoi(line);
                wsprintfA(prefix, "%d. ", num);
                wsprintfA(combined, "%s%s", prefix, dot + 2);
                pl->indent = 8;
                pl->font   = g_font_body;
                pl->line_h = 18;
                pl->nruns  = parse_inline(combined, pl->runs,
                                          sizeof(pl->runs)/sizeof(pl->runs[0]));
                g_nplines++;
                continue;
            }
        }

        /* blank line */
        if (llen == 0) {
            pl->line_h = 8;
            g_nplines++;
            continue;
        }

        /* normal paragraph line */
        pl->font   = g_font_body;
        pl->indent = 0;
        pl->line_h = 18;
        pl->nruns  = parse_inline(line, pl->runs,
                                  sizeof(pl->runs)/sizeof(pl->runs[0]));
        g_nplines++;
    }
}

/* ------------------------------------------------------------------ */
/* Preview window                                                       */
/* ------------------------------------------------------------------ */

static int g_prev_scroll = 0;

static void preview_paint(HWND hwnd)
{
    PAINTSTRUCT  ps;
    HDC          dc;
    RECT         rc, clip;
    int          y, pw, i;
    HBRUSH       br_code, br_quote;

    dc = BeginPaint(hwnd, &ps);
    GetClientRect(hwnd, &rc);
    pw = rc.right - rc.left;

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, g_aeldre_themes[g_theme_idx].body);
    {
        HBRUSH hbg = CreateSolidBrush(g_aeldre_themes[g_theme_idx].bg);
        FillRect(dc, &rc, hbg);
        DeleteObject(hbg);
    }

    /* code/quote blocks: use accent color from theme */
    br_code  = CreateSolidBrush(g_aeldre_themes[g_theme_idx].strip);
    br_quote = CreateSolidBrush(g_aeldre_themes[g_theme_idx].strip);

    y = 8 - g_prev_scroll;

    for (i = 0; i < g_nplines; i++) {
        PreviewLine *pl = &g_plines[i];
        HFONT old_font;
        int j;

        if (pl->line_h == 0 && pl->is_codeblk == 2) continue;

        /* clip check */
        if (y + pl->line_h < rc.top || y > rc.bottom) {
            y += pl->line_h;
            continue;
        }

        /* horizontal rule */
        if (pl->is_rule) {
            RECT rr;
            rr.left   = 8;
            rr.right  = pw - 8;
            rr.top    = y + 4;
            rr.bottom = y + 5;
            FillRect(dc, &rr, (HBRUSH)GetStockObject(GRAY_BRUSH));
            y += pl->line_h;
            continue;
        }

        /* blockquote bar */
        if (pl->indent == 16) {
            RECT qr;
            qr.left   = 8;
            qr.right  = 12;
            qr.top    = y;
            qr.bottom = y + pl->line_h;
            FillRect(dc, &qr, br_quote);
        }

        /* code block background */
        if (pl->is_codeblk == 1) {
            RECT cr;
            cr.left   = 4;
            cr.right  = pw - 4;
            cr.top    = y;
            cr.bottom = y + pl->line_h;
            FillRect(dc, &cr, br_code);
        }

        /* task list checkbox */
        if (pl->is_task) {
            RECT cbr;
            HPEN old_pen, pen;
            cbr.left   = 8;
            cbr.right  = 20;
            cbr.top    = y + 3;
            cbr.bottom = y + 15;
            FillRect(dc, &cbr, (HBRUSH)(COLOR_WINDOW + 1));
            FrameRect(dc, &cbr, (HBRUSH)GetStockObject(BLACK_BRUSH));
            if (pl->is_task == 2) {
                pen = CreatePen(PS_SOLID, 2, RGB(0, 0, 0));
                old_pen = (HPEN)SelectObject(dc, pen);
                MoveToEx(dc, 11, y + 9, NULL);
                LineTo(dc,  13, y + 13);
                LineTo(dc,  19, y + 5);
                SelectObject(dc, old_pen);
                DeleteObject(pen);
            }
        }

        if (pl->font)
            old_font = (HFONT)SelectObject(dc, pl->font);
        else
            old_font = (HFONT)SelectObject(dc, g_font_body);

        /* render inline runs (left-to-right) */
        {
            int x = 8 + pl->indent;
            SIZE sz;

            for (j = 0; j < pl->nruns; j++) {
                InlineRun *r = &pl->runs[j];
                HFONT run_font = NULL;
                COLORREF old_col = 0;
                int saved = 0;

                switch (r->type) {
                case RT_BOLD:
                    run_font = make_font("Times New Roman", 11, 1, 0);
                    break;
                case RT_ITALIC:
                    run_font = make_font("Times New Roman", 11, 0, 1);
                    break;
                case RT_BITALIC:
                    run_font = g_font_bi;
                    break;
                case RT_CODE:
                    run_font = g_font_code;
                    if (pl->is_codeblk != 1) {
                        /* inline code highlight — measure with code font */
                        RECT cr2;
                        SelectObject(dc, g_font_code);
                        GetTextExtentPoint32(dc, r->text,
                                             lstrlenA(r->text), &sz);
                        cr2.left   = x - 1;
                        cr2.right  = x + sz.cx + 2;
                        cr2.top    = y + 1;
                        cr2.bottom = y + pl->line_h - 1;
                        FillRect(dc, &cr2, br_code);
                    }
                    break;
                default:
                    break;
                }

                if (run_font && run_font != g_font_bi)
                    SelectObject(dc, run_font);
                else if (r->type == RT_BITALIC)
                    SelectObject(dc, g_font_bi);

                clip.left   = x;
                clip.top    = y;
                clip.right  = pw - 4;
                clip.bottom = y + pl->line_h;

                TextOut(dc, x, y, r->text, lstrlenA(r->text));
                GetTextExtentPoint32(dc, r->text, lstrlenA(r->text), &sz);
                x += sz.cx;

                if (run_font && run_font != g_font_bi)
                    DeleteObject(run_font);
            }
        }

        SelectObject(dc, old_font);
        y += pl->line_h;
    }

    DeleteObject(br_code);
    DeleteObject(br_quote);
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK PreviewWndProc(HWND hwnd, UINT msg,
                                       WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT:
        preview_paint(hwnd);
        return 0;

    case WM_VSCROLL: {
        SCROLLINFO si;
        si.cbSize = sizeof(si);
        si.fMask  = SIF_ALL;
        GetScrollInfo(hwnd, SB_VERT, &si);
        switch (LOWORD(wp)) {
        case SB_LINEUP:   si.nPos -= 16; break;
        case SB_LINEDOWN: si.nPos += 16; break;
        case SB_PAGEUP:   si.nPos -= si.nPage; break;
        case SB_PAGEDOWN: si.nPos += si.nPage; break;
        case SB_THUMBTRACK: si.nPos = si.nTrackPos; break;
        }
        si.fMask = SIF_POS;
        SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
        GetScrollInfo(hwnd, SB_VERT, &si);
        g_prev_scroll = si.nPos;
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }

    case WM_MOUSEWHEEL: {
        int delta = (short)HIWORD(wp);
        g_prev_scroll -= delta / 3;
        if (g_prev_scroll < 0) g_prev_scroll = 0;
        {
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask  = SIF_POS;
            si.nPos   = g_prev_scroll;
            SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        int click_x = (int)(short)LOWORD(lp);
        int click_y = (int)(short)HIWORD(lp);
        int ty = 8 - g_prev_scroll;
        int j;
        for (j = 0; j < g_nplines; j++) {
            PreviewLine *pl2 = &g_plines[j];
            int bot = ty + pl2->line_h;
            if (click_y >= ty && click_y < bot && pl2->is_task) {
                /* Accept click anywhere on the checkbox square + a few pixels margin */
                if (click_x >= 5 && click_x <= 26) {
                    int tlen = GetWindowTextLength(g_hwnd_edit);
                    char *tbuf = (char *)GlobalAlloc(GPTR, tlen + 2);
                    if (tbuf) {
                        char *lineptr;
                        int k;
                        GetWindowText(g_hwnd_edit, tbuf, tlen + 1);
                        lineptr = tbuf;
                        for (k = 0; k < pl2->src_line; k++) {
                            char *nlp = strchr(lineptr, '\n');
                            if (!nlp) { lineptr = NULL; break; }
                            lineptr = nlp + 1;
                        }
                        if (lineptr) {
                            char *eol = strchr(lineptr, '\n');
                            char *cb  = strstr(lineptr, "[ ]");
                            char *cx  = strstr(lineptr, "[x]");
                            if (!cx) cx = strstr(lineptr, "[X]");
                            if (cb && (!eol || cb < eol)) {
                                cb[1] = 'x';
                                SetWindowText(g_hwnd_edit, tbuf);
                                preview_refresh(0);
                            } else if (cx && (!eol || cx < eol)) {
                                cx[1] = ' ';
                                SetWindowText(g_hwnd_edit, tbuf);
                                preview_refresh(0);
                            }
                        }
                        GlobalFree((HGLOBAL)tbuf);
                    }
                }
                break;
            }
            ty = bot;
        }
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;

    case WM_SIZE: {
        RECT rc;
        int  total_h = 0, i;
        GetClientRect(hwnd, &rc);
        for (i = 0; i < g_nplines; i++)
            total_h += g_plines[i].line_h;
        total_h += 16;
        {
            SCROLLINFO si;
            si.cbSize = sizeof(si);
            si.fMask  = SIF_RANGE | SIF_PAGE;
            si.nMin   = 0;
            si.nMax   = total_h;
            si.nPage  = rc.bottom - rc.top;
            SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
        }
        return 0;
    }
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* Preview refresh                                                      */
/* ------------------------------------------------------------------ */

static void preview_refresh(int reset_scroll)
{
    int  len;
    char *buf;

    len = GetWindowTextLength(g_hwnd_edit);
    buf = (char *)GlobalAlloc(GPTR, len + 2);
    if (!buf) return;
    GetWindowText(g_hwnd_edit, buf, len + 1);

    if (reset_scroll) g_prev_scroll = 0;
    md_parse(buf);
    GlobalFree((HGLOBAL)buf);

    if (g_hwnd_prev) {
        RECT rc;
        GetClientRect(g_hwnd_prev, &rc);
        {
            int total_h = 0, i;
            for (i = 0; i < g_nplines; i++)
                total_h += g_plines[i].line_h;
            total_h += 16;
            {
                SCROLLINFO si;
                si.cbSize = sizeof(si);
                si.fMask  = SIF_RANGE | SIF_PAGE | SIF_POS;
                si.nMin   = 0;
                si.nMax   = total_h;
                si.nPage  = rc.bottom - rc.top;
                si.nPos   = g_prev_scroll;
                SetScrollInfo(g_hwnd_prev, SB_VERT, &si, TRUE);
            }
        }
        InvalidateRect(g_hwnd_prev, NULL, TRUE);
        UpdateWindow(g_hwnd_prev);
    }
}

/* ------------------------------------------------------------------ */
/* Toolbar                                                              */
/* ------------------------------------------------------------------ */

typedef struct { int id; const char *label; } TBBtn;

static const TBBtn k_tbb[] = {
    { IDB_NEW,    "New"  },
    { IDB_OPEN,   "Open" },
    { IDB_SAVE,   "Save" },
    { 0,          NULL   },   /* separator */
    { IDB_BOLD,   "B"    },
    { IDB_ITALIC, "I"    },
    { IDB_H1,     "H1"   },
    { IDB_H2,     "H2"   },
    { IDB_H3,     "H3"   },
    { IDB_CODE,   "`"    },
    { IDB_CODEBLK,"```"  },
    { IDB_BQUOTE, ">"    },
    { IDB_HR,     "---"  },
    { IDB_LIST,   "-"    },
};
#define N_TBBNS  ((int)(sizeof(k_tbb)/sizeof(k_tbb[0])))

static HWND g_tbwins[N_TBBNS];

static void toolbar_create(HWND parent)
{
    int x = 2, i;
    for (i = 0; i < N_TBBNS; i++) {
        if (k_tbb[i].id == 0) { x += 6; continue; }
        int w = (k_tbb[i].label[0] == '`') ? 32 :
                (lstrlenA(k_tbb[i].label) > 2) ? 36 : 28;
        g_tbwins[i] = CreateWindow("BUTTON", k_tbb[i].label,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, 3, w, 22, parent, (HMENU)(UINT_PTR)k_tbb[i].id,
            g_hinst, NULL);
        x += w + 2;
    }
}

/* ------------------------------------------------------------------ */
/* Editor wrap helpers                                                  */
/* ------------------------------------------------------------------ */

static void editor_insert(const char *prefix, const char *suffix)
{
    int  ss, se;
    int  selLen;
    char *selbuf;

    SendMessage(g_hwnd_edit, EM_GETSEL, (WPARAM)&ss, (LPARAM)&se);
    selLen = se - ss;

    if (selLen > 0) {
        selbuf = (char *)GlobalAlloc(GPTR, selLen + 1);
        if (!selbuf) return;
        SendMessage(g_hwnd_edit, EM_GETSEL, 0, 0);
        {
            int total = GetWindowTextLength(g_hwnd_edit);
            char *all = (char *)GlobalAlloc(GPTR, total + 2);
            if (!all) { GlobalFree((HGLOBAL)selbuf); return; }
            GetWindowText(g_hwnd_edit, all, total + 1);
            memcpy(selbuf, all + ss, selLen);
            selbuf[selLen] = '\0';

            {
                int plen = lstrlenA(prefix);
                int slen = lstrlenA(suffix);
                char *newbuf = (char *)GlobalAlloc(GPTR,
                                total + plen + slen + 2);
                if (newbuf) {
                    memcpy(newbuf, all, ss);
                    memcpy(newbuf + ss, prefix, plen);
                    memcpy(newbuf + ss + plen, selbuf, selLen);
                    memcpy(newbuf + ss + plen + selLen, suffix, slen);
                    memcpy(newbuf + ss + plen + selLen + slen,
                           all + se, total - se + 1);
                    SetWindowText(g_hwnd_edit, newbuf);
                    SendMessage(g_hwnd_edit, EM_SETSEL,
                                ss, ss + plen + selLen + slen);
                    GlobalFree((HGLOBAL)newbuf);
                }
            }
            GlobalFree((HGLOBAL)all);
        }
        GlobalFree((HGLOBAL)selbuf);
    } else {
        /* no selection: insert markers and put cursor between them */
        int plen = lstrlenA(prefix);
        int slen = lstrlenA(suffix);
        int total = GetWindowTextLength(g_hwnd_edit);
        char *all = (char *)GlobalAlloc(GPTR, total + plen + slen + 4);
        if (!all) return;
        GetWindowText(g_hwnd_edit, all, total + 1);
        {
            char *newbuf = (char *)GlobalAlloc(GPTR,
                            total + plen + slen + 4);
            if (newbuf) {
                memcpy(newbuf, all, ss);
                memcpy(newbuf + ss, prefix, plen);
                memcpy(newbuf + ss + plen, suffix, slen);
                memcpy(newbuf + ss + plen + slen, all + ss, total - ss + 1);
                SetWindowText(g_hwnd_edit, newbuf);
                SendMessage(g_hwnd_edit, EM_SETSEL, ss + plen, ss + plen);
                GlobalFree((HGLOBAL)newbuf);
            }
        }
        GlobalFree((HGLOBAL)all);
    }
    g_dirty = TRUE;
    if (g_show_prev) preview_refresh(0);
    SetFocus(g_hwnd_edit);
}

static void editor_prefix_line(const char *prefix)
{
    int ss, line, pos, llen;
    int total, plen;
    char *all, *newbuf;

    SendMessage(g_hwnd_edit, EM_GETSEL, (WPARAM)&ss, (LPARAM)NULL);
    line = (int)SendMessage(g_hwnd_edit, EM_LINEFROMCHAR, ss, 0);
    pos  = (int)SendMessage(g_hwnd_edit, EM_LINEINDEX, line, 0);
    llen = (int)SendMessage(g_hwnd_edit, EM_LINELENGTH, ss, 0);
    plen  = lstrlenA(prefix);
    total = GetWindowTextLength(g_hwnd_edit);

    all = (char *)GlobalAlloc(GPTR, total + 2);
    if (!all) return;
    GetWindowText(g_hwnd_edit, all, total + 1);

    newbuf = (char *)GlobalAlloc(GPTR, total + plen + 4);
    if (newbuf) {
        memcpy(newbuf, all, pos);
        memcpy(newbuf + pos, prefix, plen);
        memcpy(newbuf + pos + plen, all + pos, total - pos + 1);
        SetWindowText(g_hwnd_edit, newbuf);
        SendMessage(g_hwnd_edit, EM_SETSEL, pos + plen + llen,
                    pos + plen + llen);
        GlobalFree((HGLOBAL)newbuf);
    }
    GlobalFree((HGLOBAL)all);
    g_dirty = TRUE;
    if (g_show_prev) preview_refresh(0);
    SetFocus(g_hwnd_edit);
    (void)llen;
}

/* ------------------------------------------------------------------ */
/* File operations                                                      */
/* ------------------------------------------------------------------ */

static void file_set_title(void)
{
    char title[MAX_PATH + 64];
    if (g_filepath[0])
        wsprintfA(title, "%s \x97 markuped%s",
                  g_filepath, g_dirty ? " *" : "");
    else
        wsprintfA(title, "Untitled \x97 markuped%s",
                  g_dirty ? " *" : "");
    SetWindowText(g_hwnd_frame, title);
}

static int file_confirm_discard(void)
{
    if (!g_dirty) return 1;
    return MessageBoxA(g_hwnd_frame,
        "Save changes before closing?",
        "markuped",
        MB_YESNOCANCEL | MB_ICONQUESTION) != IDCANCEL;
}

static void file_new(void)
{
    if (!file_confirm_discard()) return;
    SetWindowText(g_hwnd_edit, "");
    g_filepath[0] = '\0';
    g_dirty = FALSE;
    file_set_title();
    preview_refresh(1);
}

static void file_open(void)
{
    OPENFILENAME ofn;
    char path[MAX_PATH] = "";
    FILE *f;
    long fsz;
    char *buf;

    if (!file_confirm_discard()) return;

    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hwnd_frame;
    ofn.lpstrFilter = "Markdown Files (*.md;*.txt)\0*.md;*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (!GetOpenFileName(&ofn)) return;

    f = fopen(path, "rb");
    if (!f) { MessageBoxA(g_hwnd_frame, "Cannot open file.", "markuped", MB_OK); return; }

    fseek(f, 0, SEEK_END);
    fsz = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = (char *)GlobalAlloc(GPTR, fsz + 2);
    if (!buf) { fclose(f); return; }
    fread(buf, 1, fsz, f);
    buf[fsz] = '\0';
    fclose(f);

    SetWindowText(g_hwnd_edit, buf);
    GlobalFree((HGLOBAL)buf);

    lstrcpynA(g_filepath, path, MAX_PATH - 1);
    g_dirty = FALSE;
    file_set_title();
    preview_refresh(1);
}

static int file_save_to(const char *path)
{
    int  len;
    char *buf;
    FILE *f;

    len = GetWindowTextLength(g_hwnd_edit);
    buf = (char *)GlobalAlloc(GPTR, len + 2);
    if (!buf) return 0;
    GetWindowText(g_hwnd_edit, buf, len + 1);

    f = fopen(path, "wb");
    if (!f) {
        GlobalFree((HGLOBAL)buf);
        MessageBoxA(g_hwnd_frame, "Cannot write file.", "markuped", MB_OK);
        return 0;
    }
    fwrite(buf, 1, len, f);
    fclose(f);
    GlobalFree((HGLOBAL)buf);
    return 1;
}

static void file_save(void)
{
    if (!g_filepath[0]) { /* fall through to save-as */ }
    else {
        if (file_save_to(g_filepath)) {
            g_dirty = FALSE;
            file_set_title();
        }
        return;
    }
    /* save-as */
    {
        OPENFILENAME ofn;
        char path[MAX_PATH] = "";
        memset(&ofn, 0, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner   = g_hwnd_frame;
        ofn.lpstrFilter = "Markdown Files (*.md)\0*.md\0Text Files (*.txt)\0*.txt\0All Files\0*.*\0";
        ofn.lpstrFile   = path;
        ofn.nMaxFile    = MAX_PATH;
        ofn.lpstrDefExt = "md";
        ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
        if (!GetSaveFileName(&ofn)) return;
        if (file_save_to(path)) {
            lstrcpynA(g_filepath, path, MAX_PATH - 1);
            g_dirty = FALSE;
            file_set_title();
        }
    }
}

static void file_saveas(void)
{
    g_filepath[0] = '\0';
    file_save();
}

/* ------------------------------------------------------------------ */
/* Menu creation                                                        */
/* ------------------------------------------------------------------ */

static HMENU build_menu(void)
{
    HMENU mb, mf, me, mfmt, mv, mh;
    mb   = CreateMenu();
    mf   = CreatePopupMenu();
    me   = CreatePopupMenu();
    mfmt = CreatePopupMenu();
    mv   = CreatePopupMenu();
    mh   = CreatePopupMenu();

    AppendMenu(mf, MF_STRING, IDM_NEW,    "&New\tCtrl+N");
    AppendMenu(mf, MF_STRING, IDM_OPEN,   "&Open\tCtrl+O");
    AppendMenu(mf, MF_STRING, IDM_SAVE,   "&Save\tCtrl+S");
    AppendMenu(mf, MF_STRING, IDM_SAVEAS, "Save &As...");
    AppendMenu(mf, MF_SEPARATOR, 0, NULL);
    AppendMenu(mf, MF_STRING, IDM_EXIT,   "E&xit");

    AppendMenu(me, MF_STRING, IDM_UNDO,   "&Undo\tCtrl+Z");
    AppendMenu(me, MF_SEPARATOR, 0, NULL);
    AppendMenu(me, MF_STRING, IDM_CUT,    "Cu&t\tCtrl+X");
    AppendMenu(me, MF_STRING, IDM_COPY,   "&Copy\tCtrl+C");
    AppendMenu(me, MF_STRING, IDM_PASTE,  "&Paste\tCtrl+V");
    AppendMenu(me, MF_SEPARATOR, 0, NULL);
    AppendMenu(me, MF_STRING, IDM_SELALL, "Select &All\tCtrl+A");

    AppendMenu(mfmt, MF_STRING, IDM_BOLD,    "&Bold\tCtrl+B");
    AppendMenu(mfmt, MF_STRING, IDM_ITALIC,  "&Italic\tCtrl+I");
    AppendMenu(mfmt, MF_STRING, IDM_CODE,    "Inline &Code");
    AppendMenu(mfmt, MF_STRING, IDM_CODEBLK, "Code &Block");
    AppendMenu(mfmt, MF_SEPARATOR, 0, NULL);
    AppendMenu(mfmt, MF_STRING, IDM_H1, "Heading &1");
    AppendMenu(mfmt, MF_STRING, IDM_H2, "Heading &2");
    AppendMenu(mfmt, MF_STRING, IDM_H3, "Heading &3");
    AppendMenu(mfmt, MF_SEPARATOR, 0, NULL);
    AppendMenu(mfmt, MF_STRING, IDM_BQUOTE, "&Blockquote");
    AppendMenu(mfmt, MF_STRING, IDM_LIST,   "&List Item");
    AppendMenu(mfmt, MF_STRING, IDM_HR,     "Horizontal &Rule");
    AppendMenu(mfmt, MF_STRING, IDM_LINK,   "H&yperlink");

    AppendMenu(mv, MF_STRING, IDM_TOGPREV, "Toggle &Preview\tCtrl+P");

    AppendMenu(mh, MF_STRING, IDM_ABOUT,  "&About");

    AppendMenu(mb, MF_POPUP, (UINT_PTR)mf,   "&File");
    AppendMenu(mb, MF_POPUP, (UINT_PTR)me,   "&Edit");
    AppendMenu(mb, MF_POPUP, (UINT_PTR)mfmt, "F&ormat");
    AppendMenu(mb, MF_POPUP, (UINT_PTR)mv,   "&View");
    AppendMenu(mb, MF_POPUP, (UINT_PTR)mh,   "&Help");

    return mb;
}

/* ------------------------------------------------------------------ */
/* Layout helper                                                        */
/* ------------------------------------------------------------------ */

static void layout_children(HWND hwnd)
{
    RECT rc;
    int  cw, ch, ey, eh;

    GetClientRect(hwnd, &rc);
    cw = rc.right;
    ch = rc.bottom;
    ey = TOOLBAR_H;
    eh = ch - ey;

    if (g_show_prev) {
        int sx = g_split_x;
        if (sx < 80)           sx = 80;
        if (sx > cw - 80)      sx = cw - 80;
        g_split_x = sx;

        MoveWindow(g_hwnd_edit, 0, ey, sx, eh, TRUE);
        /* splitter is a visual area, no HWND */
        MoveWindow(g_hwnd_prev, sx + SPLIT_W, ey,
                   cw - sx - SPLIT_W, eh, TRUE);
    } else {
        MoveWindow(g_hwnd_edit, 0, ey, cw, eh, TRUE);
    }
}

/* ------------------------------------------------------------------ */
/* Main frame WndProc                                                   */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK FrameWndProc(HWND hwnd, UINT msg,
                                     WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_CREATE:
        g_theme_idx = aeldre_theme_load();
        g_bg_brush  = CreateSolidBrush(g_aeldre_themes[g_theme_idx].bg);
        g_hwnd_edit = CreateWindowEx(
            0,
            "EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | WS_BORDER |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN,
            0, TOOLBAR_H, 300, 400, hwnd,
            (HMENU)IDC_EDITOR, g_hinst, NULL);
        SendMessage(g_hwnd_edit, WM_SETFONT,
                    (WPARAM)g_font_code, MAKELPARAM(FALSE, 0));

        {
            WNDCLASS wc2;
            memset(&wc2, 0, sizeof(wc2));
            wc2.lpfnWndProc   = PreviewWndProc;
            wc2.hInstance     = g_hinst;
            wc2.hbrBackground = g_bg_brush;
            wc2.lpszClassName = PREVIEW_CLS;
            wc2.hCursor       = LoadCursor(NULL, IDC_ARROW);
            RegisterClass(&wc2);
        }
        g_hwnd_prev = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            PREVIEW_CLS, "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL,
            300, TOOLBAR_H, 300, 400, hwnd,
            NULL, g_hinst, NULL);

        toolbar_create(hwnd);
        SetMenu(hwnd, build_menu());
        preview_refresh(1);
        return 0;

    case WM_SIZE:
        layout_children(hwnd);
        return 0;

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mm = (MINMAXINFO *)lp;
        mm->ptMinTrackSize.x = 480;
        mm->ptMinTrackSize.y = 320;
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        /* file */
        case IDM_NEW:    case IDB_NEW:    file_new();    break;
        case IDM_OPEN:   case IDB_OPEN:   file_open();   break;
        case IDM_SAVE:   case IDB_SAVE:   file_save();   break;
        case IDM_SAVEAS:                  file_saveas(); break;
        case IDM_EXIT:
            if (file_confirm_discard()) DestroyWindow(hwnd);
            break;

        /* edit pass-through to EDIT control */
        case IDM_UNDO:   SendMessage(g_hwnd_edit, WM_UNDO,  0, 0); break;
        case IDM_CUT:    SendMessage(g_hwnd_edit, WM_CUT,   0, 0); break;
        case IDM_COPY:   SendMessage(g_hwnd_edit, WM_COPY,  0, 0); break;
        case IDM_PASTE:  SendMessage(g_hwnd_edit, WM_PASTE, 0, 0); break;
        case IDM_SELALL:
            SendMessage(g_hwnd_edit, EM_SETSEL, 0, -1);
            break;

        /* format */
        case IDM_BOLD:   case IDB_BOLD:   editor_insert("**", "**");        break;
        case IDM_ITALIC: case IDB_ITALIC: editor_insert("*", "*");          break;
        case IDM_CODE:   case IDB_CODE:   editor_insert("`", "`");          break;
        case IDM_CODEBLK:case IDB_CODEBLK:editor_insert("```\n", "\n```"); break;
        case IDM_H1:     case IDB_H1:     editor_prefix_line("# ");         break;
        case IDM_H2:     case IDB_H2:     editor_prefix_line("## ");        break;
        case IDM_H3:     case IDB_H3:     editor_prefix_line("### ");       break;
        case IDM_BQUOTE: case IDB_BQUOTE: editor_prefix_line("> ");         break;
        case IDM_LIST:   case IDB_LIST:   editor_prefix_line("- ");         break;
        case IDM_HR:     case IDB_HR:     editor_insert("\n\n---\n\n", ""); break;
        case IDM_LINK:   editor_insert("[", "](url)"); break;

        /* view */
        case IDM_TOGPREV:
            g_show_prev = !g_show_prev;
            ShowWindow(g_hwnd_prev, g_show_prev ? SW_SHOW : SW_HIDE);
            layout_children(hwnd);
            if (g_show_prev) preview_refresh(0);
            break;

        /* edit control notifications */
        case IDC_EDITOR:
            if (HIWORD(wp) == EN_CHANGE) {
                g_dirty = TRUE;
                file_set_title();
                if (g_show_prev)
                    SetTimer(hwnd, PREVIEW_TIMER, PREVIEW_DELAY, NULL);
            }
            break;

        /* help */
        case IDM_ABOUT:
            MessageBoxA(hwnd,
                "markuped  \x97  Markdown Editor\r\n"
                "Win32s / Win32 compatible\r\n\r\n"
                "Supports: headers, bold, italic, inline code,\r\n"
                "fenced code blocks, blockquotes, lists (-, *, +),\r\n"
                "task checkboxes (- [ ] / - [x]), HR, links.\r\n\r\n"
                "\xc6ldreC2 toolkit",
                "About markuped",
                MB_OK | MB_ICONINFORMATION);
            break;
        }
        return 0;

    case WM_TIMER:
        if (wp == PREVIEW_TIMER) {
            KillTimer(hwnd, PREVIEW_TIMER);
            preview_refresh(0);
        }
        return 0;

    /* splitter dragging */
    case WM_LBUTTONDOWN: {
        int mx = LOWORD(lp);
        int my = HIWORD(lp);
        if (g_show_prev &&
            mx >= g_split_x && mx < g_split_x + SPLIT_W &&
            my >= TOOLBAR_H) {
            g_dragging = 1;
            SetCapture(hwnd);
        }
        return 0;
    }
    case WM_MOUSEMOVE:
        if (g_dragging) {
            RECT rc;
            GetClientRect(hwnd, &rc);
            g_split_x = LOWORD(lp);
            if (g_split_x < 80)            g_split_x = 80;
            if (g_split_x > rc.right - 80) g_split_x = rc.right - 80;
            layout_children(hwnd);
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    case WM_LBUTTONUP:
        if (g_dragging) { g_dragging = 0; ReleaseCapture(); }
        return 0;

    case WM_SETCURSOR: {
        POINT pt;
        RECT  rc;
        GetCursorPos(&pt);
        ScreenToClient(hwnd, &pt);
        GetClientRect(hwnd, &rc);
        if (g_show_prev &&
            pt.x >= g_split_x && pt.x < g_split_x + SPLIT_W &&
            pt.y >= TOOLBAR_H) {
            SetCursor(LoadCursor(NULL, IDC_SIZEWE));
            return TRUE;
        }
        break;
    }

    case WM_PAINT: {
        /* draw splitter bar */
        if (g_show_prev) {
            RECT rc2;
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            GetClientRect(hwnd, &rc2);
            rc2.left  = g_split_x;
            rc2.right = g_split_x + SPLIT_W;
            rc2.top   = TOOLBAR_H;
            FillRect(dc, &rc2,
                     (HBRUSH)(COLOR_BTNFACE + 1));
            EndPaint(hwnd, &ps);
        } else {
            PAINTSTRUCT ps;
            BeginPaint(hwnd, &ps);
            EndPaint(hwnd, &ps);
        }
        return 0;
    }

    case WM_CLOSE:
        if (file_confirm_discard()) DestroyWindow(hwnd);
        return 0;

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        const AeldreTheme *t = &g_aeldre_themes[g_theme_idx];
        SetTextColor(hdc, t->body); SetBkColor(hdc, t->bg);
        return (LRESULT)g_bg_brush;
    }

    case WM_DESTROY:
        if (g_bg_brush) { DeleteObject(g_bg_brush); g_bg_brush = NULL; }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------------ */
/* WinMain                                                              */
/* ------------------------------------------------------------------ */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nShow)
{
    WNDCLASS wc;
    MSG      msg;

    (void)hPrev;
    g_hinst = hInst;

    fonts_create();

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = FrameWndProc;
    wc.hInstance     = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = APP_NAME;
    wc.hIcon         = LoadIcon(hInst, MAKEINTRESOURCE(1));
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    RegisterClass(&wc);

    g_hwnd_frame = CreateWindow(APP_NAME, APP_TITLE,
        WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 700,
        NULL, NULL, hInst, NULL);

    if (!g_hwnd_frame) return 1;

    /* open file from command line if given */
    if (lpCmd && lpCmd[0] != '\0') {
        char path[MAX_PATH];
        lstrcpynA(path, lpCmd, MAX_PATH - 1);
        /* strip leading/trailing quotes */
        if (path[0] == '"') {
            int l = lstrlenA(path);
            if (l > 1 && path[l-1] == '"') path[l-1] = '\0';
            memmove(path, path + 1, lstrlenA(path));
        }
        if (path[0]) {
            FILE *f = fopen(path, "rb");
            if (f) {
                long fsz;
                char *buf;
                fseek(f, 0, SEEK_END); fsz = ftell(f); fseek(f, 0, SEEK_SET);
                buf = (char *)GlobalAlloc(GPTR, fsz + 2);
                if (buf) {
                    fread(buf, 1, fsz, f);
                    buf[fsz] = '\0';
                    SetWindowText(g_hwnd_edit, buf);
                    GlobalFree((HGLOBAL)buf);
                }
                fclose(f);
                lstrcpynA(g_filepath, path, MAX_PATH - 1);
                g_dirty = FALSE;
                file_set_title();
                preview_refresh(1);
            }
        }
    }

    ShowWindow(g_hwnd_frame, nShow);
    UpdateWindow(g_hwnd_frame);

    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(g_hwnd_frame, &msg)) {
            /* accelerators: Ctrl+N/O/S/B/I/P */
            if (msg.message == WM_KEYDOWN &&
                (GetKeyState(VK_CONTROL) & 0x8000)) {
                switch (msg.wParam) {
                case 'N': file_new();    continue;
                case 'O': file_open();   continue;
                case 'S': file_save();   continue;
                case 'B': editor_insert("**","**"); continue;
                case 'I': editor_insert("*","*");   continue;
                case 'P':
                    g_show_prev = !g_show_prev;
                    ShowWindow(g_hwnd_prev, g_show_prev ? SW_SHOW : SW_HIDE);
                    layout_children(g_hwnd_frame);
                    if (g_show_prev) preview_refresh(0);
                    continue;
                }
            }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    fonts_destroy();
    return (int)msg.wParam;
}
