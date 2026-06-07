/*
 * regcli.c  --  AeldreC2  --  Command-line Registry Tool
 *
 * Fills the gap before reg.exe arrived in Windows 2000.
 * Works on Windows NT 3.1 / 3.51 / 4.0 (advapi32 only, no shell32).
 * Win95/98 also supported (RegXxx functions present).
 *
 * Usage:
 *   regcli query  <key> [/v <name>]                enumerate or read a value
 *   regcli set    <key> /v <name> /t <type> /d <data>
 *   regcli delete <key> [/v <name>]                delete value or key tree
 *   regcli export <key> <file.reg>                 .reg 5.00 format
 *   regcli import <file.reg>
 *
 * Key syntax:  HKLM\Software\...  HKCU\...  HKCR\...  HKU\...  HKCC\...
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 regcli.c advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Hive table                                                          */
/* ------------------------------------------------------------------ */

typedef struct { const char *prefix; HKEY hive; } HiveEntry;

static const HiveEntry k_hives[] = {
    { "HKLM\\",                     HKEY_LOCAL_MACHINE  },
    { "HKEY_LOCAL_MACHINE\\",       HKEY_LOCAL_MACHINE  },
    { "HKCU\\",                     HKEY_CURRENT_USER   },
    { "HKEY_CURRENT_USER\\",        HKEY_CURRENT_USER   },
    { "HKCR\\",                     HKEY_CLASSES_ROOT   },
    { "HKEY_CLASSES_ROOT\\",        HKEY_CLASSES_ROOT   },
    { "HKU\\",                      HKEY_USERS          },
    { "HKEY_USERS\\",               HKEY_USERS          },
    { "HKCC\\",                     HKEY_CURRENT_CONFIG },
    { "HKEY_CURRENT_CONFIG\\",      HKEY_CURRENT_CONFIG },
    /* bare (no trailing backslash — root of hive) */
    { "HKLM",                       HKEY_LOCAL_MACHINE  },
    { "HKCU",                       HKEY_CURRENT_USER   },
    { "HKCR",                       HKEY_CLASSES_ROOT   },
    { "HKU",                        HKEY_USERS          },
    { "HKCC",                       HKEY_CURRENT_CONFIG },
};
#define N_HIVES ((int)(sizeof(k_hives)/sizeof(k_hives[0])))

static const char *k_hive_names[] = {
    "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER",
    "HKEY_CLASSES_ROOT",  "HKEY_USERS", "HKEY_CURRENT_CONFIG",
};
static const HKEY k_hive_vals[] = {
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER,
    HKEY_CLASSES_ROOT,  HKEY_USERS, HKEY_CURRENT_CONFIG,
};

static const char *hive_name(HKEY h)
{
    int i;
    for (i = 0; i < 5; i++) if (k_hive_vals[i] == h) return k_hive_names[i];
    return "HKEY_UNKNOWN";
}

static int parse_key(const char *full, HKEY *out_hive, const char **out_subkey)
{
    int i;
    for (i = 0; i < N_HIVES; i++) {
        int n = (int)strlen(k_hives[i].prefix);
        if (_strnicmp(full, k_hives[i].prefix, n) == 0) {
            *out_hive   = k_hives[i].hive;
            *out_subkey = full + n;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Query                                                               */
/* ------------------------------------------------------------------ */

static void print_value(const char *vname, DWORD vtype, const BYTE *vdata, DWORD dsz)
{
    const char *display_name = vname[0] ? vname : "(Default)";
    switch (vtype) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        printf("  %-40s  REG_SZ          \"%s\"\n", display_name, (const char *)vdata);
        break;
    case REG_DWORD:
        if (dsz >= 4)
            printf("  %-40s  REG_DWORD       0x%08lX (%lu)\n",
                   display_name, *(DWORD *)vdata, *(DWORD *)vdata);
        break;
    case REG_MULTI_SZ: {
        const char *p = (const char *)vdata;
        printf("  %-40s  REG_MULTI_SZ\n", display_name);
        while (p && *p && (DWORD)(p - (const char *)vdata) < dsz) {
            printf("      \"%s\"\n", p); p += strlen(p) + 1;
        }
        break;
    }
    case REG_BINARY: {
        DWORD i;
        printf("  %-40s  REG_BINARY      ", display_name);
        for (i = 0; i < dsz && i < 32; i++) printf("%02X ", vdata[i]);
        if (dsz > 32) printf("...");
        printf("\n");
        break;
    }
    default:
        printf("  %-40s  type(%lu)        [%lu bytes]\n", display_name, vtype, dsz);
        break;
    }
}

static void cmd_query(const char *keypath, const char *valname)
{
    HKEY        hive, hkey;
    const char *subkey;
    LONG        ret;
    DWORD       idx;

    if (!parse_key(keypath, &hive, &subkey)) {
        fprintf(stderr, "regcli: unknown hive in '%s'\n", keypath); exit(1);
    }

    ret = RegOpenKeyEx(hive, subkey, 0, KEY_READ, &hkey);
    if (ret != ERROR_SUCCESS) {
        fprintf(stderr, "regcli: cannot open key '%s' (%ld)\n", keypath, ret); exit(1);
    }

    printf("[%s]\n", keypath);

    if (valname) {
        /* Read one specific value */
        BYTE  vdata[4096];
        DWORD dsz = sizeof(vdata), vtype;
        ret = RegQueryValueEx(hkey, valname, NULL, &vtype, vdata, &dsz);
        if (ret != ERROR_SUCCESS) {
            fprintf(stderr, "regcli: value '%s' not found (%ld)\n", valname, ret);
            RegCloseKey(hkey); exit(1);
        }
        print_value(valname, vtype, vdata, dsz);
    } else {
        /* Enumerate all values */
        for (idx = 0; ; idx++) {
            char  vname[256];
            BYTE  vdata[4096];
            DWORD vsz = sizeof(vname), dsz = sizeof(vdata), vtype;
            ret = RegEnumValue(hkey, idx, vname, &vsz, NULL, &vtype, vdata, &dsz);
            if (ret == ERROR_NO_MORE_ITEMS) break;
            if (ret != ERROR_SUCCESS) break;
            print_value(vname, vtype, vdata, dsz);
        }

        /* Also enumerate subkeys */
        for (idx = 0; ; idx++) {
            char  kname[256];
            DWORD ksz = sizeof(kname);
            ret = RegEnumKeyEx(hkey, idx, kname, &ksz, NULL, NULL, NULL, NULL);
            if (ret == ERROR_NO_MORE_ITEMS) break;
            if (ret != ERROR_SUCCESS) break;
            printf("  %-40s  (subkey)\n", kname);
        }
    }

    RegCloseKey(hkey);
}

/* ------------------------------------------------------------------ */
/* Set                                                                 */
/* ------------------------------------------------------------------ */

static void cmd_set(const char *keypath, const char *valname, const char *typstr, const char *data)
{
    HKEY        hive, hkey;
    const char *subkey;
    LONG        ret;
    DWORD       vtype;
    BYTE        vdata[4096];
    DWORD       dsz;

    if (!valname || !data) {
        fprintf(stderr, "regcli set: need /v <name> /t <type> /d <data>\n"); exit(1);
    }
    if (!parse_key(keypath, &hive, &subkey)) {
        fprintf(stderr, "regcli: unknown hive\n"); exit(1);
    }

    /* Determine type */
    if (!typstr || _stricmp(typstr, "REG_SZ") == 0)
        vtype = REG_SZ;
    else if (_stricmp(typstr, "REG_EXPAND_SZ") == 0)
        vtype = REG_EXPAND_SZ;
    else if (_stricmp(typstr, "REG_DWORD") == 0)
        vtype = REG_DWORD;
    else if (_stricmp(typstr, "REG_BINARY") == 0)
        vtype = REG_BINARY;
    else if (_stricmp(typstr, "REG_MULTI_SZ") == 0)
        vtype = REG_MULTI_SZ;
    else {
        fprintf(stderr, "regcli: unknown type '%s'\n", typstr); exit(1);
    }

    /* Convert data */
    switch (vtype) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        strncpy((char *)vdata, data, sizeof(vdata) - 1);
        dsz = (DWORD)strlen(data) + 1;
        break;
    case REG_DWORD: {
        DWORD d = (DWORD)strtoul(data, NULL, 0);
        memcpy(vdata, &d, 4); dsz = 4;
        break;
    }
    case REG_BINARY: {
        /* hex string: "deadbeef" or "DE AD BE EF" */
        const char *p = data; dsz = 0;
        while (*p && dsz < sizeof(vdata) - 1) {
            char hex[3]; DWORD val;
            while (*p == ' ') p++;
            if (!*p) break;
            hex[0] = *p++; hex[1] = *p ? *p++ : '0'; hex[2] = '\0';
            val = strtoul(hex, NULL, 16);
            vdata[dsz++] = (BYTE)val;
        }
        break;
    }
    case REG_MULTI_SZ: {
        /* semicolon-separated substrings */
        const char *p = data; char *q = (char *)vdata; dsz = 0;
        while (*p && dsz < sizeof(vdata) - 2) {
            const char *sep = strchr(p, ';');
            int len = sep ? (int)(sep - p) : (int)strlen(p);
            if (len > 0) { memcpy(q, p, len); q += len; dsz += len; }
            *q++ = '\0'; dsz++;
            if (!sep) break;
            p = sep + 1;
        }
        *q = '\0'; dsz++;  /* double NUL terminator */
        break;
    }
    default:
        dsz = 0;
    }

    /* Create or open the key */
    ret = RegCreateKeyEx(hive, subkey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hkey, NULL);
    if (ret != ERROR_SUCCESS) {
        fprintf(stderr, "regcli: cannot create/open key (%ld)\n", ret); exit(1);
    }

    ret = RegSetValueEx(hkey, valname, 0, vtype, vdata, dsz);
    RegCloseKey(hkey);
    if (ret != ERROR_SUCCESS) {
        fprintf(stderr, "regcli: RegSetValueEx failed (%ld)\n", ret); exit(1);
    }
    printf("Value '%s' set in '%s'\n", valname, keypath);
}

/* ------------------------------------------------------------------ */
/* Delete                                                              */
/* ------------------------------------------------------------------ */

static void cmd_delete(const char *keypath, const char *valname)
{
    HKEY        hive, hkey;
    const char *subkey;
    LONG        ret;

    if (!parse_key(keypath, &hive, &subkey)) {
        fprintf(stderr, "regcli: unknown hive\n"); exit(1);
    }

    if (valname) {
        ret = RegOpenKeyEx(hive, subkey, 0, KEY_SET_VALUE, &hkey);
        if (ret != ERROR_SUCCESS) { fprintf(stderr, "regcli: cannot open key (%ld)\n", ret); exit(1); }
        ret = RegDeleteValue(hkey, valname);
        RegCloseKey(hkey);
        if (ret != ERROR_SUCCESS) { fprintf(stderr, "regcli: cannot delete value (%ld)\n", ret); exit(1); }
        printf("Value '%s' deleted from '%s'\n", valname, keypath);
    } else {
        ret = RegDeleteKey(hive, subkey);
        if (ret != ERROR_SUCCESS) { fprintf(stderr, "regcli: cannot delete key (%ld)\n", ret); exit(1); }
        printf("Key '%s' deleted.\n", keypath);
    }
}

/* ------------------------------------------------------------------ */
/* Export                                                              */
/* ------------------------------------------------------------------ */

static void export_key_recursive(FILE *f, HKEY parent_hive, const char *full_path, HKEY hkey)
{
    DWORD idx;

    fprintf(f, "[%s]\r\n", full_path);

    /* Values */
    for (idx = 0; ; idx++) {
        char  vname[256]; DWORD vsz = sizeof(vname);
        BYTE  vdata[4096]; DWORD dsz = sizeof(vdata);
        DWORD vtype;
        LONG  ret = RegEnumValue(hkey, idx, vname, &vsz, NULL, &vtype, vdata, &dsz);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) break;

        if (!vname[0])
            fprintf(f, "@=");
        else
            fprintf(f, "\"%s\"=", vname);

        switch (vtype) {
        case REG_SZ:
            fprintf(f, "\"%s\"", (char *)vdata);
            break;
        case REG_EXPAND_SZ:
            fprintf(f, "hex(2):");
            { DWORD i; for (i = 0; i < dsz; i++) { if (i) fprintf(f, ","); fprintf(f, "%02x", vdata[i]); } }
            break;
        case REG_DWORD:
            fprintf(f, "dword:%08lx", *(DWORD *)vdata);
            break;
        default: {
            DWORD i;
            fprintf(f, "hex:");
            for (i = 0; i < dsz; i++) { if (i) fprintf(f, ","); fprintf(f, "%02x", vdata[i]); }
            break;
        }
        }
        fprintf(f, "\r\n");
    }
    fprintf(f, "\r\n");

    /* Recurse into subkeys */
    for (idx = 0; ; idx++) {
        char  kname[256]; DWORD ksz = sizeof(kname);
        HKEY  subhkey;
        char  sub_full[2048];
        LONG  ret = RegEnumKeyEx(hkey, idx, kname, &ksz, NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) break;
        sprintf(sub_full, "%s\\%s", full_path, kname);
        if (RegOpenKeyEx(hkey, kname, 0, KEY_READ, &subhkey) == ERROR_SUCCESS) {
            export_key_recursive(f, parent_hive, sub_full, subhkey);
            RegCloseKey(subhkey);
        }
    }
}

static void cmd_export(const char *keypath, const char *outfile)
{
    HKEY        hive, hkey;
    const char *subkey;
    FILE       *f;

    if (!parse_key(keypath, &hive, &subkey)) {
        fprintf(stderr, "regcli: unknown hive\n"); exit(1);
    }

    if (RegOpenKeyEx(hive, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
        fprintf(stderr, "regcli: cannot open key '%s'\n", keypath); exit(1);
    }

    f = fopen(outfile, "w");
    if (!f) { fprintf(stderr, "regcli: cannot create '%s'\n", outfile); RegCloseKey(hkey); exit(1); }

    fprintf(f, "Windows Registry Editor Version 5.00\r\n\r\n");
    export_key_recursive(f, hive, keypath, hkey);
    fclose(f);
    RegCloseKey(hkey);
    printf("Exported '%s' to '%s'\n", keypath, outfile);
}

/* ------------------------------------------------------------------ */
/* Import                                                              */
/* ------------------------------------------------------------------ */

static void cmd_import(const char *infile)
{
    FILE  *f;
    char   line[4096];
    HKEY   hive = NULL, hkey = NULL;
    char   cur_full[2048] = "";
    int    lineno = 0;

    f = fopen(infile, "r");
    if (!f) { fprintf(stderr, "regcli: cannot open '%s'\n", infile); exit(1); }

    while (fgets(line, sizeof(line), f)) {
        int len;
        lineno++;
        /* strip CRLF */
        len = (int)strlen(line);
        while (len > 0 && (line[len-1]=='\r'||line[len-1]=='\n')) line[--len]='\0';

        if (!line[0] || line[0] == ';') continue;
        if (lineno == 1) continue;  /* header */

        if (line[0] == '[') {
            /* Key section */
            if (hkey) { RegCloseKey(hkey); hkey = NULL; }
            {
                char *end = strchr(line + 1, ']');
                if (!end) continue;
                *end = '\0';
                strncpy(cur_full, line + 1, sizeof(cur_full) - 1);
                if (parse_key(cur_full, &hive, (const char **)&end)) {
                    /* end is now the subkey string — but parse_key modified a const pointer...
                       use a local copy */
                    const char *sk;
                    parse_key(cur_full, &hive, &sk);
                    RegCreateKeyEx(hive, sk, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkey, NULL);
                }
            }
        } else if (hkey && strchr(line, '=')) {
            /* Value line: "name"=data or @=data */
            char  *eq = strchr(line, '=');
            char  vname[256] = "";
            const char *data_str;
            *eq = '\0';
            data_str = eq + 1;
            if (line[0] == '@') {
                vname[0] = '\0';
            } else if (line[0] == '"') {
                int nlen = (int)strlen(line) - 2;
                if (nlen > 255) nlen = 255;
                if (nlen > 0) strncpy(vname, line + 1, nlen);
            }

            if (strncmp(data_str, "\"", 1) == 0) {
                /* REG_SZ */
                int dlen = (int)strlen(data_str) - 2;
                char val[4096] = "";
                if (dlen > 0 && dlen < 4095) strncpy(val, data_str + 1, dlen);
                RegSetValueEx(hkey, vname, 0, REG_SZ, (BYTE *)val, (DWORD)strlen(val) + 1);
            } else if (strncmp(data_str, "dword:", 6) == 0) {
                DWORD d = (DWORD)strtoul(data_str + 6, NULL, 16);
                RegSetValueEx(hkey, vname, 0, REG_DWORD, (BYTE *)&d, 4);
            } else if (strncmp(data_str, "hex:", 4) == 0 ||
                       strncmp(data_str, "hex(", 4) == 0) {
                /* Binary / REG_EXPAND_SZ etc — parse hex */
                DWORD  vtype = REG_BINARY;
                BYTE   bin[4096]; DWORD blen = 0;
                const char *p;
                if (strncmp(data_str, "hex(2):", 7) == 0) { vtype = REG_EXPAND_SZ; p = data_str + 7; }
                else if (strncmp(data_str, "hex(7):", 7) == 0) { vtype = REG_MULTI_SZ; p = data_str + 7; }
                else p = data_str + 4;
                while (*p && blen < sizeof(bin)) {
                    char hx[3]; DWORD v;
                    while (*p == ' ' || *p == ',' || *p == '\\' || *p == '\r' || *p == '\n') {
                        if (*p == '\\') { /* continuation line */ fgets(line, sizeof(line), f); p = line; }
                        else p++;
                    }
                    if (!*p) break;
                    hx[0] = *p++; hx[1] = *p ? *p++ : '0'; hx[2] = '\0';
                    v = strtoul(hx, NULL, 16);
                    bin[blen++] = (BYTE)v;
                }
                RegSetValueEx(hkey, vname, 0, vtype, bin, blen);
            }
        }
    }
    if (hkey) RegCloseKey(hkey);
    fclose(f);
    printf("Imported '%s'\n", infile);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *verb, *key = NULL, *valname = NULL, *typstr = NULL;
    const char *data = NULL, *file = NULL;
    int i;

    if (argc < 2) {
        fprintf(stderr,
            "regcli  --  AeldreC2 Command-line Registry Tool\n"
            "Fills the gap before reg.exe (Windows 2000+) on NT 3.x / 4.0\n\n"
            "Usage:\n"
            "  regcli query  <key> [/v <name>]\n"
            "  regcli set    <key> /v <name> /t <type> /d <data>\n"
            "  regcli delete <key> [/v <name>]\n"
            "  regcli export <key> <file.reg>\n"
            "  regcli import <file.reg>\n\n"
            "Key prefix: HKLM\\ HKCU\\ HKCR\\ HKU\\ HKCC\\\n"
            "Types:      REG_SZ  REG_EXPAND_SZ  REG_DWORD  REG_BINARY  REG_MULTI_SZ\n");
        return 1;
    }

    verb = argv[1];
    if (argc >= 3) key = argv[2];

    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "/v") == 0 && i + 1 < argc) valname = argv[++i];
        else if (strcmp(argv[i], "/t") == 0 && i + 1 < argc) typstr  = argv[++i];
        else if (strcmp(argv[i], "/d") == 0 && i + 1 < argc) data    = argv[++i];
        else if (argv[i][0] != '/') file = argv[i];
    }

    if (_stricmp(verb, "query") == 0) {
        if (!key) { fprintf(stderr, "regcli query: need <key>\n"); return 1; }
        cmd_query(key, valname);
    } else if (_stricmp(verb, "set") == 0) {
        if (!key) { fprintf(stderr, "regcli set: need <key>\n"); return 1; }
        cmd_set(key, valname, typstr, data);
    } else if (_stricmp(verb, "delete") == 0) {
        if (!key) { fprintf(stderr, "regcli delete: need <key>\n"); return 1; }
        cmd_delete(key, valname);
    } else if (_stricmp(verb, "export") == 0) {
        if (!key || !file) { fprintf(stderr, "regcli export: need <key> <file.reg>\n"); return 1; }
        cmd_export(key, file);
    } else if (_stricmp(verb, "import") == 0) {
        if (!key) { fprintf(stderr, "regcli import: need <file.reg>\n"); return 1; }
        cmd_import(key);   /* key used as filename when verb=import */
    } else {
        fprintf(stderr, "regcli: unknown verb '%s'\n", verb);
        return 1;
    }

    return 0;
}
