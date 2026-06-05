/*
 * aelctl.h -- AeldreC2 Win32s-compatible controls library
 *
 * Drop-in replacement for comctl32.lib on Win32s / Windows NT 3.1 targets.
 * Link against aelctl.lib instead of comctl32.lib; source is unchanged.
 *
 * On Windows 95 / NT 3.51+:  loads COMCTL32.DLL and calls through.
 * On Win32s / NT 3.1:        registers own GDI-based shim classes.
 *
 * Controls provided:
 *   msctls_progress32  --  Progress bar  (ProgressBar)
 *   msctls_statusbar32 --  Status bar    (StatusBar)
 *   msctls_updown32    --  Up-down spin  (UpDown)
 */

#ifndef AELCTL_H
#define AELCTL_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Export / import decoration                                           */
/* ------------------------------------------------------------------ */

/* When building aelctl.dll itself, compile with -DAELCTL_BUILD_DLL so
   that the public functions are marked __declspec(dllexport).
   Consumers that include this header get __declspec(dllimport). */
#ifdef AELCTL_BUILD_DLL
#  define AELAPI __declspec(dllexport)
#else
#  define AELAPI __declspec(dllimport)
#endif

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

/* InitCommonControls — identical signature to comctl32's version.
   Call this instead of (or in addition to) the real InitCommonControls.
   Safe to call multiple times. */
AELAPI void WINAPI InitCommonControls(void);

/* AelCtl_Init — extended entry point that accepts hInst explicitly.
   Not needed when linked as a DLL (DllMain captures hInst automatically),
   but provided for static-link or test scenarios. */
AELAPI BOOL WINAPI AelCtl_Init(HINSTANCE hInst);

/* ------------------------------------------------------------------ */
/* Progress bar messages (values match comctl32)                        */
/* ------------------------------------------------------------------ */
#ifndef PBM_SETRANGE
#define PBM_SETRANGE   (WM_USER+1)   /* lParam=MAKELONG(lo,hi) */
#define PBM_SETPOS     (WM_USER+2)   /* wParam=pos, returns old */
#define PBM_DELTAPOS   (WM_USER+3)   /* wParam=delta */
#define PBM_SETSTEP    (WM_USER+4)   /* wParam=step */
#define PBM_STEPIT     (WM_USER+5)   /* advance by step */
#define PBST_NORMAL    0
#endif

/* ------------------------------------------------------------------ */
/* Status bar messages (values match comctl32)                          */
/* ------------------------------------------------------------------ */
#ifndef SB_SETTEXT
#define SB_SETTEXT        (WM_USER+1)  /* wParam=part|style lParam=text */
#define SB_GETTEXT        (WM_USER+2)  /* wParam=part lParam=buf */
#define SB_GETTEXTLENGTH  (WM_USER+3)  /* wParam=part */
#define SB_SETPARTS       (WM_USER+4)  /* wParam=count lParam=int[]rights */
#define SB_GETPARTS       (WM_USER+6)  /* wParam=count lParam=int[]buf */
#define SB_SETMINHEIGHT   (WM_USER+8)
#define SB_SIMPLE         (WM_USER+9)  /* wParam=TRUE/FALSE */
#define SB_GETRECT        (WM_USER+10) /* wParam=part lParam=RECT* */
#define SBARS_SIZEGRIP    0x0100
#endif

/* ------------------------------------------------------------------ */
/* Up-down control messages (values match comctl32)                     */
/* ------------------------------------------------------------------ */
#ifndef UDM_SETRANGE
#define UDM_SETRANGE  (WM_USER+101)  /* lParam=MAKELONG(hi,lo) NOTE: hi,lo order */
#define UDM_GETRANGE  (WM_USER+102)
#define UDM_SETPOS    (WM_USER+103)  /* wParam=pos */
#define UDM_GETPOS    (WM_USER+104)  /* returns pos; hi word non-zero on error */
#define UDM_SETBUDDY  (WM_USER+105)  /* wParam=hwndBuddy */
#define UDM_GETBUDDY  (WM_USER+106)
#define UDM_SETACCEL  (WM_USER+107)
#define UDM_GETACCEL  (WM_USER+108)
#define UDM_SETBASE   (WM_USER+109)
#define UDM_GETBASE   (WM_USER+110)
#define UDS_WRAP         0x0001
#define UDS_SETBUDDYINT  0x0002
#define UDS_ALIGNRIGHT   0x0004
#define UDS_ALIGNLEFT    0x0008
#define UDS_AUTOBUDDY    0x0010
#define UDS_ARROWKEYS    0x0020
#define UDS_HORZ         0x0040
#define UDS_NOTHOUSANDS  0x0080
#endif

#ifdef __cplusplus
}
#endif

#endif /* AELCTL_H */
