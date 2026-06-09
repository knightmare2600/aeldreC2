/*
 * aeldre_theme.h  --  AeldreC2 shared colour theme table
 *
 * All GUI tools (except Joshua, which is the source of truth) include
 * this header and call aeldre_theme_load() once at startup.  The theme
 * name is read from WIN.INI [AeldreC2] Theme=<name>, which Joshua writes
 * when the user picks a theme.  Absent any entry, "solarized" is the
 * default, matching Joshua's default.
 *
 * Each .c file that includes this header gets its own static copy of
 * the array (by design — no external linkage required).
 */

#ifndef AELDRE_THEME_H
#define AELDRE_THEME_H

#include <windows.h>

typedef struct {
    const char *name;   /* key stored in WIN.INI               */
    const char *label;  /* human-readable label (unused here)  */
    COLORREF    bg;     /* window / list background            */
    COLORREF    strip;  /* accent bar / selected-item bg       */
    COLORREF    title;  /* heading / highlighted text          */
    COLORREF    body;   /* body / normal text                  */
} AeldreTheme;

static const AeldreTheme g_aeldre_themes[] = {
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
#define AELDRE_THEME_COUNT ((int)(sizeof(g_aeldre_themes)/sizeof(g_aeldre_themes[0])))

/* Read WIN.INI [AeldreC2] Theme=<name> and return the matching index.
 * Returns 0 (solarized) if the key is absent or unrecognised. */
static int aeldre_theme_load(void)
{
    char buf[64];
    int  i;
    GetProfileString("AeldreC2", "Theme", "solarized", buf, sizeof(buf));
    for (i = 0; i < AELDRE_THEME_COUNT; i++)
        if (lstrcmpi(buf, g_aeldre_themes[i].name) == 0)
            return i;
    return 0;
}

#endif /* AELDRE_THEME_H */
