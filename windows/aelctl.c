/*
 * aelctl.c -- AeldreC2 Win32s-compatible controls library
 *
 * Provides GDI-based shim implementations of the three most useful
 * COMCTL32 controls for Win32s / Windows NT 3.1 targets.  On systems
 * where COMCTL32.DLL is present the real library is used transparently.
 *
 * Progress bar implementation based on the Windows SDK 3.1 Gauge sample:
 *   Copyright (C) 1992 Microsoft Corporation.  All rights reserved.
 *   From: Microsoft Windows SDK, SAMPLES\GAUGE\GAUGE.C
 *   Used here with structural adaptations for Win32 and range support.
 *
 * Status bar and up-down implementations are original.
 *
 * Build:
 *   wcl386 -bt=nt -bd -za99 -ox -D_WINDOWS -D_WIN32 -DWIN32 -fo=aelctl.obj aelctl.c
 *   wlink system nt_dll name aelctl.dll file aelctl.obj export InitCommonControls.1 export AelCtl_Init.2
 */

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include "aelctl.h"

/* ------------------------------------------------------------------ */
/* Internal constants                                                   */
/* ------------------------------------------------------------------ */

#define SB_MAXPARTS   16
#define SB_DEF_HEIGHT 20   /* default status bar height in pixels */
#define UD_REPEAT_MS  50   /* up-down auto-repeat interval */
#define UD_DELAY_MS   400  /* up-down delay before auto-repeat starts */

/* cbWndExtra offsets — ProgressBar */
#define PB_X_POS   0   /* LONG: current position */
#define PB_X_LO    4   /* LONG: range low */
#define PB_X_HI    8   /* LONG: range high */
#define PB_X_STEP  12  /* LONG: step increment */

/* cbWndExtra offsets — StatusBar */
#define SB_X_DATA  0   /* LONG: pointer to heap-allocated SBData */

/* cbWndExtra offsets — UpDown */
#define UD_X_POS   0   /* LONG: current value */
#define UD_X_LO    4   /* LONG: range low */
#define UD_X_HI    8   /* LONG: range high */
#define UD_X_BUDDY 12  /* LONG: buddy HWND */
#define UD_X_STATE 16  /* LONG: pressed/timer state */

/* UD_X_STATE bit flags */
#define UD_ST_UP_DOWN  0x1  /* up arrow pressed */
#define UD_ST_DN_DOWN  0x2  /* down arrow pressed */
#define UD_ST_DELAY    0x4  /* in initial delay (not yet repeating) */

/* Status bar heap data */
typedef struct {
    int  nparts;
    int  rights[SB_MAXPARTS];     /* right edge of each part (-1 = stretch) */
    int  styles[SB_MAXPARTS];
    char text[SB_MAXPARTS][256];
    BOOL bsimple;
    char simple[256];
} SBData;

/* ------------------------------------------------------------------ */
/* Globals                                                              */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hinst     = NULL;
static BOOL      g_shims_on  = FALSE;   /* TRUE if we registered shims */

/* ------------------------------------------------------------------ */
/* Utility                                                              */
/* ------------------------------------------------------------------ */

static COLORREF sys(int idx) { return GetSysColor(idx); }

static void fill(HDC dc, RECT *r, COLORREF c)
{
    HBRUSH br = CreateSolidBrush(c);
    FillRect(dc, r, br);
    DeleteObject(br);
}

/* Draw a Win3.1-style sunken or raised edge around a rect using solid
   lines rather than DrawEdge, since DrawEdge may be absent on NT 3.1. */
static void draw_edge_simple(HDC dc, RECT *r, BOOL sunken)
{
    COLORREF top_left  = sys(sunken ? COLOR_BTNSHADOW  : COLOR_BTNHIGHLIGHT);
    COLORREF bot_right = sys(sunken ? COLOR_BTNHIGHLIGHT : COLOR_BTNSHADOW);
    HPEN ptl = CreatePen(PS_SOLID, 1, top_left);
    HPEN pbr = CreatePen(PS_SOLID, 1, bot_right);
    HPEN old = (HPEN)SelectObject(dc, ptl);

    MoveToEx(dc, r->left,      r->bottom - 1, NULL);
    LineTo  (dc, r->left,      r->top);
    LineTo  (dc, r->right - 1, r->top);

    SelectObject(dc, pbr);
    MoveToEx(dc, r->right - 1, r->top,        NULL);
    LineTo  (dc, r->right - 1, r->bottom - 1);
    LineTo  (dc, r->left,      r->bottom - 1);

    SelectObject(dc, old);
    DeleteObject(ptl);
    DeleteObject(pbr);
}

/* ------------------------------------------------------------------ */
/* ProgressBar shim                                                     */
/*                                                                      */
/* Based on Microsoft Windows SDK 3.1 SAMPLES\GAUGE\GAUGE.C            */
/* Copyright (C) 1992 Microsoft Corporation.  All rights reserved.     */
/* Adaptations: Win32 message IDs (PBM_*), LONG range, step support.   */
/* ------------------------------------------------------------------ */

static void pb_paint(HWND hwnd)
{
    PAINTSTRUCT ps;
    RECT        rc, filled;
    HDC         dc;
    LONG        pos, lo, hi, fillw;

    pos = GetWindowLong(hwnd, PB_X_POS);
    lo  = GetWindowLong(hwnd, PB_X_LO);
    hi  = GetWindowLong(hwnd, PB_X_HI);

    dc = BeginPaint(hwnd, &ps);
    GetClientRect(hwnd, &rc);

    if (hi <= lo) hi = lo + 1;
    fillw = (LONG)((double)(rc.right - rc.left) * (pos - lo) / (hi - lo));

    /* Filled portion — Microsoft Gauge sample uses COLOR_HIGHLIGHT */
    filled = rc;
    filled.right = rc.left + (int)fillw;
    fill(dc, &filled, sys(COLOR_HIGHLIGHT));

    /* Empty portion */
    filled.left  = rc.left + (int)fillw;
    filled.right = rc.right;
    if (filled.left < filled.right)
        fill(dc, &filled, sys(COLOR_WINDOW));

    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK ProgressBarWndProc(HWND hwnd, UINT msg,
                                            WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        SetWindowLong(hwnd, PB_X_POS,  0);
        SetWindowLong(hwnd, PB_X_LO,   0);
        SetWindowLong(hwnd, PB_X_HI,  100);
        SetWindowLong(hwnd, PB_X_STEP, 10);
        return 0;

    case WM_PAINT:
        pb_paint(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;   /* we paint everything in WM_PAINT */

    case PBM_SETRANGE: {
        LONG old_lo  = GetWindowLong(hwnd, PB_X_LO);
        LONG old_hi  = GetWindowLong(hwnd, PB_X_HI);
        SetWindowLong(hwnd, PB_X_LO, (LONG)(short)LOWORD(lp));
        SetWindowLong(hwnd, PB_X_HI, (LONG)(short)HIWORD(lp));
        InvalidateRect(hwnd, NULL, FALSE);
        return MAKELONG((short)old_lo, (short)old_hi);
    }

    case PBM_SETPOS: {
        LONG old = GetWindowLong(hwnd, PB_X_POS);
        SetWindowLong(hwnd, PB_X_POS, (LONG)wp);
        InvalidateRect(hwnd, NULL, FALSE);
        UpdateWindow(hwnd);
        return (LRESULT)old;
    }

    case PBM_DELTAPOS: {
        LONG old = GetWindowLong(hwnd, PB_X_POS);
        SetWindowLong(hwnd, PB_X_POS, old + (LONG)wp);
        InvalidateRect(hwnd, NULL, FALSE);
        UpdateWindow(hwnd);
        return (LRESULT)old;
    }

    case PBM_SETSTEP:
        SetWindowLong(hwnd, PB_X_STEP, (LONG)wp);
        return 0;

    case PBM_STEPIT: {
        LONG pos  = GetWindowLong(hwnd, PB_X_POS);
        LONG step = GetWindowLong(hwnd, PB_X_STEP);
        LONG hi   = GetWindowLong(hwnd, PB_X_HI);
        LONG lo   = GetWindowLong(hwnd, PB_X_LO);
        pos += step;
        if (pos > hi) pos = lo;
        SetWindowLong(hwnd, PB_X_POS, pos);
        InvalidateRect(hwnd, NULL, FALSE);
        UpdateWindow(hwnd);
        return 0;
    }
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static BOOL register_progress(HINSTANCE hi)
{
    WNDCLASS wc;
    if (GetClassInfo(hi, "msctls_progress32", &wc)) return TRUE;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = ProgressBarWndProc;
    wc.hInstance     = hi;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "msctls_progress32";
    wc.cbWndExtra    = 4 * sizeof(LONG);   /* pos, lo, hi, step */
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    return RegisterClass(&wc) != 0;
}

/* ------------------------------------------------------------------ */
/* StatusBar shim                                                       */
/* ------------------------------------------------------------------ */

static SBData *sb_data(HWND hwnd)
{
    return (SBData *)(LONG_PTR)GetWindowLong(hwnd, SB_X_DATA);
}

static void sb_resize_to_parent(HWND hwnd)
{
    HWND   parent = GetParent(hwnd);
    RECT   rp;
    int    h = SB_DEF_HEIGHT;
    if (!parent) return;
    GetClientRect(parent, &rp);
    SetWindowPos(hwnd, NULL,
                 0, rp.bottom - h, rp.right, h,
                 SWP_NOZORDER | SWP_NOACTIVATE);
}

static void sb_get_part_rect(HWND hwnd, int part, RECT *out)
{
    SBData *d = sb_data(hwnd);
    RECT    rc;
    int     left = 2, i;
    GetClientRect(hwnd, &rc);
    if (!d) { *out = rc; return; }
    if (d->bsimple || d->nparts == 0) { *out = rc; return; }
    for (i = 0; i < d->nparts && i <= part; i++) {
        int right = (d->rights[i] < 0) ? rc.right - 2 : d->rights[i];
        if (i == part) {
            out->left   = left;
            out->top    = 2;
            out->right  = right;
            out->bottom = rc.bottom - 2;
            return;
        }
        left = right + 2;
    }
    *out = rc;
}

static void sb_paint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC         dc;
    RECT        rc;
    SBData     *d;
    int         i;

    dc = BeginPaint(hwnd, &ps);
    GetClientRect(hwnd, &rc);
    d  = sb_data(hwnd);

    /* Background */
    fill(dc, &rc, sys(COLOR_BTNFACE));

    if (!d || d->nparts == 0 || d->bsimple) {
        /* Single sunken panel */
        RECT pr = rc;
        pr.left   += 2; pr.top    += 2;
        pr.right  -= 2; pr.bottom -= 2;
        draw_edge_simple(dc, &pr, TRUE);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, sys(COLOR_BTNTEXT));
        {
            HFONT old = (HFONT)SelectObject(dc,
                GetStockObject(DEFAULT_GUI_FONT));
            RECT tr = pr;
            tr.left += 3; tr.top += 1;
            if (d)
                DrawText(dc, d->bsimple ? d->simple : (d->nparts ? d->text[0] : ""),
                         -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, old);
        }
    } else {
        int left = 2;
        for (i = 0; i < d->nparts; i++) {
            RECT pr;
            int right = (d->rights[i] < 0) ? rc.right - 2 : d->rights[i];
            pr.left   = left;
            pr.top    = 2;
            pr.right  = right;
            pr.bottom = rc.bottom - 2;
            draw_edge_simple(dc, &pr, TRUE);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, sys(COLOR_BTNTEXT));
            {
                HFONT old = (HFONT)SelectObject(dc,
                    GetStockObject(DEFAULT_GUI_FONT));
                RECT tr = pr;
                tr.left += 4; tr.top += 1; tr.right -= 2;
                DrawText(dc, d->text[i], -1, &tr,
                         DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                SelectObject(dc, old);
            }
            left = right + 2;
        }
    }

    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK StatusBarWndProc(HWND hwnd, UINT msg,
                                          WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        SBData *d = (SBData *)GlobalAlloc(GPTR, sizeof(SBData));
        if (!d) return -1;
        d->nparts  = 0;
        d->bsimple = FALSE;
        SetWindowLong(hwnd, SB_X_DATA, (LONG)(LONG_PTR)d);
        sb_resize_to_parent(hwnd);
        return 0;
    }

    case WM_DESTROY: {
        SBData *d = sb_data(hwnd);
        if (d) GlobalFree((HGLOBAL)d);
        SetWindowLong(hwnd, SB_X_DATA, 0);
        return 0;
    }

    case WM_PAINT:
        sb_paint(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_SIZE:
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;

    case SB_SETTEXT: {
        int part  = (int)(wp & 0xFF);
        SBData *d = sb_data(hwnd);
        if (!d) return FALSE;
        if (d->bsimple) {
            if (lp) lstrcpynA(d->simple, (LPCSTR)lp, 255);
            else    d->simple[0] = '\0';
        } else {
            if (part >= 0 && part < d->nparts) {
                if (lp) lstrcpynA(d->text[part], (LPCSTR)lp, 255);
                else    d->text[part][0] = '\0';
            }
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return TRUE;
    }

    case SB_GETTEXT: {
        int part  = (int)(wp & 0xFF);
        SBData *d = sb_data(hwnd);
        if (!d || part < 0 || part >= d->nparts) return 0;
        if (lp) lstrcpyA((LPSTR)lp, d->text[part]);
        return lstrlenA(d->text[part]);
    }

    case SB_SETPARTS: {
        SBData *d = sb_data(hwnd);
        int n = (int)wp;
        int *ar = (int *)lp;
        int i;
        if (!d || n <= 0 || n > SB_MAXPARTS || !ar) return FALSE;
        d->nparts = n;
        for (i = 0; i < n; i++) {
            d->rights[i] = ar[i];
            d->text[i][0] = '\0';
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return TRUE;
    }

    case SB_GETPARTS: {
        SBData *d = sb_data(hwnd);
        int n = (int)wp, i;
        int *ar = (int *)lp;
        if (!d) return 0;
        if (ar && n > 0) {
            int cnt = (n < d->nparts) ? n : d->nparts;
            for (i = 0; i < cnt; i++) ar[i] = d->rights[i];
        }
        return d->nparts;
    }

    case SB_SIMPLE: {
        SBData *d = sb_data(hwnd);
        if (d) d->bsimple = (BOOL)wp;
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }

    case SB_GETRECT: {
        RECT *pr = (RECT *)lp;
        if (pr) sb_get_part_rect(hwnd, (int)wp, pr);
        return pr != NULL;
    }

    case SB_SETMINHEIGHT:
        /* accepted but ignored — we use a fixed height */
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static BOOL register_statusbar(HINSTANCE hi)
{
    WNDCLASS wc;
    if (GetClassInfo(hi, "msctls_statusbar32", &wc)) return TRUE;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = StatusBarWndProc;
    wc.hInstance     = hi;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "msctls_statusbar32";
    wc.cbWndExtra    = sizeof(LONG);   /* one pointer */
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    return RegisterClass(&wc) != 0;
}

/* ------------------------------------------------------------------ */
/* UpDown shim                                                          */
/* ------------------------------------------------------------------ */

static void ud_set_buddy_text(HWND buddy, LONG val)
{
    char buf[32];
    wsprintf(buf, "%ld", val);
    SetWindowText(buddy, buf);
}

static void ud_do_step(HWND hwnd, int dir)
{
    LONG pos  = GetWindowLong(hwnd, UD_X_POS);
    LONG lo   = GetWindowLong(hwnd, UD_X_LO);
    LONG hi   = GetWindowLong(hwnd, UD_X_HI);
    HWND buddy = (HWND)(LONG_PTR)GetWindowLong(hwnd, UD_X_BUDDY);
    DWORD style = GetWindowLong(hwnd, GWL_STYLE);

    pos += dir;
    if (pos > hi) pos = (style & UDS_WRAP) ? lo : hi;
    if (pos < lo) pos = (style & UDS_WRAP) ? hi : lo;
    SetWindowLong(hwnd, UD_X_POS, pos);

    if (buddy && (style & UDS_SETBUDDYINT))
        ud_set_buddy_text(buddy, pos);

    /* Notify parent via WM_NOTIFY (simplified: send WM_VSCROLL to parent) */
    {
        HWND parent = GetParent(hwnd);
        if (parent)
            SendMessage(parent, WM_VSCROLL,
                        MAKEWPARAM(dir > 0 ? SB_LINEUP : SB_LINEDOWN, 0),
                        (LPARAM)hwnd);
    }
}

static void ud_get_halves(HWND hwnd, RECT *up, RECT *dn)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    *up = rc;
    *dn = rc;
    up->bottom = rc.top + (rc.bottom - rc.top) / 2;
    dn->top    = up->bottom;
}

static void ud_paint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC    dc;
    RECT   up, dn;
    DWORD  state;

    state = (DWORD)GetWindowLong(hwnd, UD_X_STATE);
    dc = BeginPaint(hwnd, &ps);
    ud_get_halves(hwnd, &up, &dn);

    /* Draw buttons using DrawFrameControl (available NT3.1+, Win32s 1.30+).
       Fall back gracefully if the call fails on very old builds. */
    if (!DrawFrameControl(dc, &up, DFC_SCROLL,
            DFCS_SCROLLUP   | ((state & UD_ST_UP_DOWN) ? DFCS_PUSHED : 0)))
    {
        /* Fallback: solid-colour rectangles */
        fill(dc, &up, sys(COLOR_BTNFACE));
        draw_edge_simple(dc, &up, (state & UD_ST_UP_DOWN) != 0);
    }
    if (!DrawFrameControl(dc, &dn, DFC_SCROLL,
            DFCS_SCROLLDOWN | ((state & UD_ST_DN_DOWN) ? DFCS_PUSHED : 0)))
    {
        fill(dc, &dn, sys(COLOR_BTNFACE));
        draw_edge_simple(dc, &dn, (state & UD_ST_DN_DOWN) != 0);
    }

    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK UpDownWndProc(HWND hwnd, UINT msg,
                                       WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        SetWindowLong(hwnd, UD_X_POS,   0);
        SetWindowLong(hwnd, UD_X_LO,    0);
        SetWindowLong(hwnd, UD_X_HI,  100);
        SetWindowLong(hwnd, UD_X_BUDDY, 0);
        SetWindowLong(hwnd, UD_X_STATE, 0);
        return 0;

    case WM_PAINT:
        ud_paint(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_LBUTTONDOWN: {
        RECT up, dn;
        POINT pt;
        DWORD state = (DWORD)GetWindowLong(hwnd, UD_X_STATE);
        pt.x = LOWORD(lp); pt.y = HIWORD(lp);
        ud_get_halves(hwnd, &up, &dn);
        if (PtInRect(&up, pt)) {
            state = (state & ~UD_ST_DN_DOWN) | UD_ST_UP_DOWN | UD_ST_DELAY;
            ud_do_step(hwnd, +1);
        } else if (PtInRect(&dn, pt)) {
            state = (state & ~UD_ST_UP_DOWN) | UD_ST_DN_DOWN | UD_ST_DELAY;
            ud_do_step(hwnd, -1);
        }
        SetWindowLong(hwnd, UD_X_STATE, (LONG)state);
        SetTimer(hwnd, 1, UD_DELAY_MS, NULL);
        SetCapture(hwnd);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    case WM_LBUTTONUP:
        SetWindowLong(hwnd, UD_X_STATE, 0);
        KillTimer(hwnd, 1);
        ReleaseCapture();
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_TIMER: {
        DWORD state = (DWORD)GetWindowLong(hwnd, UD_X_STATE);
        if (state & UD_ST_DELAY) {
            /* Switch from delay timer to repeat timer */
            state &= ~UD_ST_DELAY;
            SetWindowLong(hwnd, UD_X_STATE, (LONG)state);
            KillTimer(hwnd, 1);
            SetTimer(hwnd, 1, UD_REPEAT_MS, NULL);
        }
        if (state & UD_ST_UP_DOWN) ud_do_step(hwnd, +1);
        if (state & UD_ST_DN_DOWN) ud_do_step(hwnd, -1);
        return 0;
    }

    case UDM_SETRANGE:
        /* Note: comctl32 packs as MAKELONG(hi, lo) — hi in high word */
        SetWindowLong(hwnd, UD_X_HI, (LONG)(short)HIWORD(lp));
        SetWindowLong(hwnd, UD_X_LO, (LONG)(short)LOWORD(lp));
        return 0;

    case UDM_GETRANGE:
        return MAKELONG(
            (short)GetWindowLong(hwnd, UD_X_HI),
            (short)GetWindowLong(hwnd, UD_X_LO));

    case UDM_SETPOS: {
        LONG old = GetWindowLong(hwnd, UD_X_POS);
        HWND buddy = (HWND)(LONG_PTR)GetWindowLong(hwnd, UD_X_BUDDY);
        DWORD style = GetWindowLong(hwnd, GWL_STYLE);
        SetWindowLong(hwnd, UD_X_POS, (LONG)(short)LOWORD(wp));
        if (buddy && (style & UDS_SETBUDDYINT))
            ud_set_buddy_text(buddy, (LONG)(short)LOWORD(wp));
        return MAKELONG((short)old, 0);
    }

    case UDM_GETPOS:
        return MAKELONG((short)GetWindowLong(hwnd, UD_X_POS), 0);

    case UDM_SETBUDDY: {
        HWND old = (HWND)(LONG_PTR)GetWindowLong(hwnd, UD_X_BUDDY);
        SetWindowLong(hwnd, UD_X_BUDDY, (LONG)(LONG_PTR)(HWND)wp);
        return (LRESULT)(LONG_PTR)old;
    }

    case UDM_GETBUDDY:
        return (LRESULT)(LONG_PTR)(HWND)(LONG_PTR)GetWindowLong(hwnd, UD_X_BUDDY);

    case UDM_SETACCEL:
    case UDM_GETACCEL:
    case UDM_SETBASE:
    case UDM_GETBASE:
        return 0;   /* accepted, not implemented */
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static BOOL register_updown(HINSTANCE hi)
{
    WNDCLASS wc;
    if (GetClassInfo(hi, "msctls_updown32", &wc)) return TRUE;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = UpDownWndProc;
    wc.hInstance     = hi;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "msctls_updown32";
    wc.cbWndExtra    = 5 * sizeof(LONG);   /* pos, lo, hi, buddy, state */
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    return RegisterClass(&wc) != 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

BOOL WINAPI AelCtl_Init(HINSTANCE hInst)
{
    HMODULE hComCtl;
    typedef VOID (WINAPI *PFNIC)(void);
    PFNIC pfn;

    if (hInst) g_hinst = hInst;
    if (!g_hinst) return FALSE;

    /* Prefer the real COMCTL32 if it exists on this system */
    hComCtl = LoadLibrary("COMCTL32.DLL");
    if (hComCtl) {
        pfn = (PFNIC)GetProcAddress(hComCtl, "InitCommonControls");
        if (pfn) pfn();
        /* Leave loaded — its window classes are now registered */
        g_shims_on = FALSE;
        return TRUE;
    }

    /* COMCTL32 absent (Win32s / NT 3.1) — register our shim classes */
    register_progress(g_hinst);
    register_statusbar(g_hinst);
    register_updown(g_hinst);
    g_shims_on = TRUE;
    return TRUE;
}

void WINAPI InitCommonControls(void)
{
    AelCtl_Init(g_hinst);
}

/* ------------------------------------------------------------------ */
/* DLL entry point                                                      */
/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_hinst = hInst;
        /* Auto-init on load so apps that forget InitCommonControls still work */
        AelCtl_Init(hInst);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
