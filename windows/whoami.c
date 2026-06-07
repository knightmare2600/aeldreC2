/*
 * whoami.c  --  AeldreC2  --  whoami for Windows NT 3.x / 4.0
 *
 * Windows NT 3.1 / 3.51 / 4.0 lack a whoami command (it arrived with XP).
 * This fills that gap: prints username, domain, computer, and optionally
 * the token SID + groups + privileges.
 *
 * Usage:
 *   whoami          Username and computer name
 *   whoami -v       Verbose: + SID + groups + privileges
 *   whoami -sid     SID only
 *   whoami -all     Everything
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 whoami.c advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Manual SID-to-string (ConvertSidToStringSid needs XP / Win2k)      */
/* ------------------------------------------------------------------ */

static void sid_to_str(PSID sid, char *out, int outsz)
{
    SID *s = (SID *)sid;
    char tmp[256];
    int  i;
    DWORD auth;

    if (!IsValidSid(sid)) { strncpy(out, "(invalid SID)", outsz - 1); return; }

    auth = (DWORD)s->IdentifierAuthority.Value[5]
         | ((DWORD)s->IdentifierAuthority.Value[4] << 8)
         | ((DWORD)s->IdentifierAuthority.Value[3] << 16)
         | ((DWORD)s->IdentifierAuthority.Value[2] << 24);

    sprintf(out, "S-%d-%lu", (int)s->Revision, auth);
    for (i = 0; i < (int)s->SubAuthorityCount; i++) {
        sprintf(tmp, "-%lu", s->SubAuthority[i]);
        strncat(out, tmp, outsz - (int)strlen(out) - 1);
    }
}

/* ------------------------------------------------------------------ */
/* Privilege name lookup (common subset)                               */
/* ------------------------------------------------------------------ */

static const struct { DWORD attr; const char *name; } k_priv_attrs[] = {
    { SE_PRIVILEGE_ENABLED,           "Enabled"  },
    { SE_PRIVILEGE_ENABLED_BY_DEFAULT,"Default"  },
    { SE_PRIVILEGE_USED_FOR_ACCESS,   "UsedForAccess" },
};

static void print_priv(LUID_AND_ATTRIBUTES *la)
{
    char  name[128] = "";
    DWORD needed = sizeof(name);
    LookupPrivilegeName(NULL, &la->Luid, name, &needed);
    printf("    %-40s  ", name[0] ? name : "(unknown)");
    if (la->Attributes & SE_PRIVILEGE_ENABLED)           printf("Enabled");
    if (la->Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) printf("+Default");
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    HANDLE  token = NULL;
    BOOL    verbose = FALSE, sid_only = FALSE;
    int     i;

    for (i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "-v") == 0)   verbose  = TRUE;
        if (_stricmp(argv[i], "-sid") == 0) sid_only = TRUE;
        if (_stricmp(argv[i], "-all") == 0) { verbose = TRUE; sid_only = FALSE; }
        if (strcmp(argv[i], "-?") == 0 || _stricmp(argv[i], "--help") == 0) {
            printf("Usage: whoami [-v] [-sid] [-all]\n"
                   "  (default)  username and computer\n"
                   "  -v         + SID, groups, privileges\n"
                   "  -sid       SID only\n"
                   "  -all       everything\n");
            return 0;
        }
    }

    /* Basic info */
    {
        char uname[256] = "", cname[256] = "", dname[256] = "";
        DWORD sz = sizeof(uname);
        GetUserName(uname, &sz);
        sz = sizeof(cname);
        GetComputerName(cname, &sz);

        /* Try to get domain via NetWkstaUserGetInfo (best-effort, not on NT 3.1) */
        {
            HMODULE hNet = LoadLibrary("netapi32.dll");
            if (hNet) {
                typedef DWORD (WINAPI *PFN_NWUGI)(LPWSTR, DWORD, LPBYTE*);
                typedef DWORD (WINAPI *PFN_NBS)(LPVOID);
                PFN_NWUGI pfn = (PFN_NWUGI)GetProcAddress(hNet, "NetWkstaUserGetInfo");
                PFN_NBS   pfb = (PFN_NBS)  GetProcAddress(hNet, "NetApiBufferFree");
                if (pfn && pfb) {
                    LPBYTE buf = NULL;
                    if (pfn(NULL, 1, &buf) == 0 && buf) {
                        /* Structure starts with logon_domain pointer (LPWSTR) */
                        LPWSTR dom = *(LPWSTR *)buf;
                        if (dom) WideCharToMultiByte(CP_ACP, 0, dom, -1, dname, sizeof(dname), NULL, NULL);
                        pfb(buf);
                    }
                }
                FreeLibrary(hNet);
            }
        }

        if (sid_only) goto print_sid;

        printf("Username:  %s%s%s\n",
               dname[0] ? dname : "", dname[0] ? "\\" : "", uname);
        printf("Computer:  %s\n", cname);
    }

print_sid:
    /* Get token */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (sid_only || verbose)
            fprintf(stderr, "whoami: cannot open process token (%lu)\n", GetLastError());
        return 0;
    }

    /* User SID */
    {
        DWORD         needed = 0;
        TOKEN_USER   *tu;
        char          sidstr[128];
        GetTokenInformation(token, TokenUser, NULL, 0, &needed);
        tu = (TOKEN_USER *)malloc(needed);
        if (tu && GetTokenInformation(token, TokenUser, tu, needed, &needed)) {
            sid_to_str(tu->User.Sid, sidstr, sizeof(sidstr));
            if (sid_only) { printf("%s\n", sidstr); free(tu); CloseHandle(token); return 0; }
            printf("SID:       %s\n", sidstr);
        }
        if (tu) free(tu);
    }

    if (!verbose) { CloseHandle(token); return 0; }

    /* Groups */
    {
        DWORD         needed = 0;
        TOKEN_GROUPS *tg;
        GetTokenInformation(token, TokenGroups, NULL, 0, &needed);
        tg = (TOKEN_GROUPS *)malloc(needed);
        if (tg && GetTokenInformation(token, TokenGroups, tg, needed, &needed)) {
            DWORD j;
            printf("\nGroups (%lu):\n", tg->GroupCount);
            for (j = 0; j < tg->GroupCount; j++) {
                char sidstr[128], gname[128] = "", gdomain[128] = "";
                DWORD gsz = sizeof(gname), dsz = sizeof(gdomain);
                SID_NAME_USE snu;
                sid_to_str(tg->Groups[j].Sid, sidstr, sizeof(sidstr));
                LookupAccountSid(NULL, tg->Groups[j].Sid, gname, &gsz, gdomain, &dsz, &snu);
                printf("  %s\\%s  %s\n", gdomain, gname, sidstr);
            }
        }
        if (tg) free(tg);
    }

    /* Privileges */
    {
        DWORD              needed = 0;
        TOKEN_PRIVILEGES  *tp;
        GetTokenInformation(token, TokenPrivileges, NULL, 0, &needed);
        tp = (TOKEN_PRIVILEGES *)malloc(needed);
        if (tp && GetTokenInformation(token, TokenPrivileges, tp, needed, &needed)) {
            DWORD j;
            printf("\nPrivileges (%lu):\n", tp->PrivilegeCount);
            for (j = 0; j < tp->PrivilegeCount; j++)
                print_priv(&tp->Privileges[j]);
        }
        if (tp) free(tp);
    }

    CloseHandle(token);
    return 0;
}
