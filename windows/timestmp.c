/*
 * timestmp.c  --  AeldreC2  --  File timestamp manipulation  (8.3: timestmp)
 *
 * Read and write creation, last-write, and last-access timestamps.
 * Useful for timestamp matching in authorised forensic testing.
 *
 * Usage:
 *   timestamp <target> <source>
 *       Copy all timestamps from <source> onto <target>
 *
 *   timestamp <target> <date> <time>
 *       Set all three timestamps to the specified date/time
 *       date: YYYY-MM-DD  time: HH:MM:SS  (24-hour)
 *
 *   timestamp <target> -c <date> <time>   created only
 *   timestamp <target> -w <date> <time>   last write only
 *   timestamp <target> -a <date> <time>   last access only
 *
 *   timestamp -q <file>    Query and print timestamps
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 timestamp.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void print_ft(const char *label, FILETIME *ft)
{
    FILETIME   lft;
    SYSTEMTIME st;
    FileTimeToLocalFileTime(ft, &lft);
    FileTimeToSystemTime(&lft, &st);
    printf("  %-14s  %04d-%02d-%02d  %02d:%02d:%02d\n",
           label,
           st.wYear, st.wMonth, st.wDay,
           st.wHour, st.wMinute, st.wSecond);
}

/* ------------------------------------------------------------------ */
/* Query                                                               */
/* ------------------------------------------------------------------ */

static int cmd_query(const char *path)
{
    HANDLE h = CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    FILETIME ct, at, wt;
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "timestamp: cannot open '%s' (%lu)\n", path, GetLastError());
        return 1;
    }
    if (!GetFileTime(h, &ct, &at, &wt)) {
        fprintf(stderr, "timestamp: GetFileTime failed (%lu)\n", GetLastError());
        CloseHandle(h); return 1;
    }
    printf("File: %s\n", path);
    print_ft("Created:",     &ct);
    print_ft("Last write:",  &wt);
    print_ft("Last access:", &at);
    CloseHandle(h);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Copy timestamps from source → target                               */
/* ------------------------------------------------------------------ */

static int cmd_copy(const char *target, const char *source)
{
    HANDLE hs, ht;
    FILETIME ct, at, wt;

    hs = CreateFile(source, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hs == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "timestamp: cannot open source '%s' (%lu)\n", source, GetLastError());
        return 1;
    }
    if (!GetFileTime(hs, &ct, &at, &wt)) {
        fprintf(stderr, "timestamp: GetFileTime failed (%lu)\n", GetLastError());
        CloseHandle(hs); return 1;
    }
    CloseHandle(hs);

    ht = CreateFile(target, FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (ht == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "timestamp: cannot open target '%s' (%lu)\n", target, GetLastError());
        return 1;
    }
    if (!SetFileTime(ht, &ct, &at, &wt)) {
        fprintf(stderr, "timestamp: SetFileTime failed (%lu)\n", GetLastError());
        CloseHandle(ht); return 1;
    }
    CloseHandle(ht);

    printf("Timestamps copied: %s -> %s\n", source, target);
    print_ft("  Created:",     &ct);
    print_ft("  Last write:",  &wt);
    print_ft("  Last access:", &at);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Parse date / time strings                                           */
/* ------------------------------------------------------------------ */

static int parse_datetime(const char *date_s, const char *time_s, FILETIME *ft_out)
{
    SYSTEMTIME st;
    FILETIME   lft;
    int        year, mon, day, hour, min, sec;

    /* date: YYYY-MM-DD */
    if (sscanf(date_s, "%d-%d-%d", &year, &mon, &day) != 3) {
        /* Try DD/MM/YYYY */
        if (sscanf(date_s, "%d/%d/%d", &day, &mon, &year) != 3) {
            fprintf(stderr, "timestamp: bad date '%s'  (YYYY-MM-DD or DD/MM/YYYY)\n", date_s);
            return 0;
        }
    }
    if (sscanf(time_s, "%d:%d:%d", &hour, &min, &sec) != 3) {
        fprintf(stderr, "timestamp: bad time '%s'  (HH:MM:SS)\n", time_s);
        return 0;
    }

    memset(&st, 0, sizeof(st));
    st.wYear   = (WORD)year;
    st.wMonth  = (WORD)mon;
    st.wDay    = (WORD)day;
    st.wHour   = (WORD)hour;
    st.wMinute = (WORD)min;
    st.wSecond = (WORD)sec;

    if (!SystemTimeToFileTime(&st, &lft)) {
        fprintf(stderr, "timestamp: invalid date/time\n"); return 0;
    }
    LocalFileTimeToFileTime(&lft, ft_out);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Set timestamps                                                      */
/* ------------------------------------------------------------------ */

/* which: bit 1=created, bit 2=access, bit 4=write; 0=all three */
static int cmd_set(const char *target, const char *date_s, const char *time_s, int which)
{
    HANDLE   ht;
    FILETIME ft, ct, at, wt;

    if (!parse_datetime(date_s, time_s, &ft)) return 1;

    /* Read existing timestamps first so we can preserve those we're not changing */
    ht = CreateFile(target, GENERIC_READ | FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (ht == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "timestamp: cannot open '%s' (%lu)\n", target, GetLastError());
        return 1;
    }
    GetFileTime(ht, &ct, &at, &wt);

    if (!which || (which & 1)) ct = ft;
    if (!which || (which & 2)) at = ft;
    if (!which || (which & 4)) wt = ft;

    if (!SetFileTime(ht, &ct, &at, &wt)) {
        fprintf(stderr, "timestamp: SetFileTime failed (%lu)\n", GetLastError());
        CloseHandle(ht); return 1;
    }
    CloseHandle(ht);
    printf("Timestamp set on '%s'\n", target);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "timestamp  --  AeldreC2 File Timestamp Tool\n\n"
            "Usage:\n"
            "  timestamp -q  <file>               Query timestamps\n"
            "  timestamp <target> <source>         Copy timestamps from source\n"
            "  timestamp <target> <date> <time>    Set all timestamps\n"
            "  timestamp <target> -c <date> <time> Created only\n"
            "  timestamp <target> -w <date> <time> Last-write only\n"
            "  timestamp <target> -a <date> <time> Last-access only\n\n"
            "  date: YYYY-MM-DD   time: HH:MM:SS\n");
        return 1;
    }

    /* -q query mode */
    if (strcmp(argv[1], "-q") == 0) {
        if (argc < 3) { fprintf(stderr, "timestamp -q: need <file>\n"); return 1; }
        return cmd_query(argv[2]);
    }

    /* timestamp <target> ... */
    {
        const char *target = argv[1];

        if (argc < 3) {
            fprintf(stderr, "timestamp: need at least <target> <source|date> ...\n"); return 1;
        }

        /* Distinguish copy (source=file) vs set (next arg looks like a date/time) */
        if (argc == 3) {
            /* copy or query-print target */
            return cmd_copy(target, argv[2]);
        }

        /* argc >= 4 */
        {
            const char *flag = argv[2];

            /* timestamp <target> -c/-w/-a <date> <time> */
            if (strcmp(flag, "-c") == 0 && argc >= 5) return cmd_set(target, argv[3], argv[4], 1);
            if (strcmp(flag, "-a") == 0 && argc >= 5) return cmd_set(target, argv[3], argv[4], 2);
            if (strcmp(flag, "-w") == 0 && argc >= 5) return cmd_set(target, argv[3], argv[4], 4);

            /* timestamp <target> <date> <time> — all three */
            if (flag[0] != '-' && argc >= 4) return cmd_set(target, flag, argv[3], 0);
        }

        fprintf(stderr, "timestamp: unrecognised arguments\n");
        return 1;
    }
}
