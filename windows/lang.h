/*
 * lang.h  --  AeldreC2 runtime language selection
 *
 * Include this in any file that uses localised strings.
 * Call lang_detect() once at startup (before any window is created).
 * Then use LS(IDS_FOO) everywhere a string literal used to appear.
 *
 * Language block offsets in the STRINGTABLE resource:
 *   EN-GB  1000   British English — the default
 *   EN-US  2000   American English
 *   DA     3000   Dansk
 *   DE     4000   Deutsch
 *
 * Fall-back chain: exact locale -> primary language -> EN-GB.
 */

#ifndef LANG_H
#define LANG_H

#include <windows.h>
#include "strings.h"

#define LANG_BASE_EN_GB  1000
#define LANG_BASE_EN_US  2000
#define LANG_BASE_DA     3000
#define LANG_BASE_DE     4000

/* Exposed so apps can save/restore or override */
extern int g_lang_base;

#ifdef LANG_IMPL
int g_lang_base = LANG_BASE_EN_GB;
#else
extern int g_lang_base;
#endif

/* lang_detect() — call once at program start */
static void lang_detect(HINSTANCE hinst)
{
    LANGID lid = GetUserDefaultLangID();
    WORD   pri = PRIMARYLANGID(lid);
    WORD   sub = SUBLANGID(lid);

    (void)hinst;

    if (pri == LANG_ENGLISH) {
        /* Distinguish GB from everything else */
        g_lang_base = (sub == SUBLANG_ENGLISH_UK)
                      ? LANG_BASE_EN_GB
                      : LANG_BASE_EN_US;
    } else if (pri == LANG_DANISH) {
        g_lang_base = LANG_BASE_DA;
    } else if (pri == LANG_GERMAN) {
        g_lang_base = LANG_BASE_DE;
    } else {
        g_lang_base = LANG_BASE_EN_GB;   /* fallback */
    }
}

/*
 * LS(id) — load a localised string into a static buffer.
 * NOT re-entrant; don't nest two LS() calls in the same expression.
 */
static const char *LS(int id)
{
    static char buf[512];
    if (!LoadString(GetModuleHandle(NULL), g_lang_base + id, buf, sizeof(buf) - 1))
        if (!LoadString(GetModuleHandle(NULL), LANG_BASE_EN_GB + id, buf, sizeof(buf) - 1))
            buf[0] = '\0';
    return buf;
}

/*
 * LSF(id, ...) — formatted localised string.
 * Result in a second static buffer.
 */
static const char *LSF(int id, ...)
{
    static char fmt[512], out[1024];
    va_list ap;
    if (!LoadString(GetModuleHandle(NULL), g_lang_base + id, fmt, sizeof(fmt) - 1))
        if (!LoadString(GetModuleHandle(NULL), LANG_BASE_EN_GB + id, fmt, sizeof(fmt) - 1))
            fmt[0] = '\0';
    va_start(ap, id);
    wvsprintfA(out, fmt, ap);
    va_end(ap);
    return out;
}

#endif /* LANG_H */
