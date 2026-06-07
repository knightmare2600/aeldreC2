/*
 * clip.c  --  AeldreC2  --  Clipboard utility for Windows NT / 95
 *
 * Read, write, set, and clear the clipboard from the command line.
 * Windows NT 3.1+ and Windows 95+.
 *
 * Usage:
 *   clip read                Print clipboard text to stdout
 *   clip write <text>        Set clipboard text from argument
 *   clip set   <file>        Set clipboard from file contents
 *   clip clear               Empty the clipboard
 *   clip info                Print clipboard format info
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 clip.c user32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void write_stdout(const char *buf, DWORD len)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w;
    if (h && h != INVALID_HANDLE_VALUE)
        WriteFile(h, buf, len, &w, NULL);
}

/* ------------------------------------------------------------------ */
/* read                                                                */
/* ------------------------------------------------------------------ */

static int cmd_read(void)
{
    HANDLE hData;
    const char *p;

    if (!IsClipboardFormatAvailable(CF_TEXT)) {
        fprintf(stderr, "clip: clipboard does not contain text\n");
        return 1;
    }
    if (!OpenClipboard(NULL)) {
        fprintf(stderr, "clip: cannot open clipboard (%lu)\n", GetLastError());
        return 1;
    }
    hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); fprintf(stderr, "clip: GetClipboardData failed\n"); return 1; }
    p = (const char *)GlobalLock(hData);
    if (p) {
        DWORD len = (DWORD)strlen(p);
        write_stdout(p, len);
        if (len > 0 && p[len - 1] != '\n') write_stdout("\r\n", 2);
        GlobalUnlock(hData);
    }
    CloseClipboard();
    return 0;
}

/* ------------------------------------------------------------------ */
/* write (from argument or file)                                       */
/* ------------------------------------------------------------------ */

static int set_clipboard_text(const char *text, DWORD len)
{
    HGLOBAL hg;
    char   *p;
    BOOL    ok;

    hg = GlobalAlloc(GMEM_MOVEABLE, len + 1);
    if (!hg) { fprintf(stderr, "clip: out of memory\n"); return 1; }
    p = (char *)GlobalLock(hg);
    if (!p) { GlobalFree(hg); return 1; }
    memcpy(p, text, len);
    p[len] = '\0';
    GlobalUnlock(hg);

    if (!OpenClipboard(NULL)) {
        GlobalFree(hg);
        fprintf(stderr, "clip: cannot open clipboard (%lu)\n", GetLastError());
        return 1;
    }
    EmptyClipboard();
    ok = (SetClipboardData(CF_TEXT, hg) != NULL);
    CloseClipboard();
    if (!ok) { fprintf(stderr, "clip: SetClipboardData failed (%lu)\n", GetLastError()); return 1; }
    fprintf(stderr, "clip: %lu bytes written to clipboard\n", len);
    return 0;
}

static int cmd_write(const char *text)
{
    return set_clipboard_text(text, (DWORD)strlen(text));
}

static int cmd_set_file(const char *path)
{
    FILE  *f;
    long   fsz;
    char  *buf;
    int    rc;

    f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "clip: cannot open '%s'\n", path); return 1; }
    fseek(f, 0, SEEK_END); fsz = ftell(f); fseek(f, 0, SEEK_SET);
    buf = (char *)malloc((size_t)fsz + 1);
    if (!buf) { fclose(f); fprintf(stderr, "clip: out of memory\n"); return 1; }
    fread(buf, 1, (size_t)fsz, f);
    buf[fsz] = '\0';
    fclose(f);
    rc = set_clipboard_text(buf, (DWORD)fsz);
    free(buf);
    return rc;
}

/* ------------------------------------------------------------------ */
/* clear                                                               */
/* ------------------------------------------------------------------ */

static int cmd_clear(void)
{
    if (!OpenClipboard(NULL)) {
        fprintf(stderr, "clip: cannot open clipboard (%lu)\n", GetLastError());
        return 1;
    }
    EmptyClipboard();
    CloseClipboard();
    fprintf(stderr, "clip: clipboard cleared\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* info                                                                */
/* ------------------------------------------------------------------ */

static int cmd_info(void)
{
    static const struct { UINT fmt; const char *name; } k_fmts[] = {
        { CF_TEXT,         "CF_TEXT"         },
        { CF_BITMAP,       "CF_BITMAP"       },
        { CF_METAFILEPICT, "CF_METAFILEPICT" },
        { CF_SYLK,         "CF_SYLK"         },
        { CF_DIF,          "CF_DIF"          },
        { CF_TIFF,         "CF_TIFF"         },
        { CF_OEMTEXT,      "CF_OEMTEXT"      },
        { CF_DIB,          "CF_DIB"          },
        { CF_PALETTE,      "CF_PALETTE"      },
        { CF_UNICODETEXT,  "CF_UNICODETEXT"  },
        { CF_ENHMETAFILE,  "CF_ENHMETAFILE"  },
        { CF_HDROP,        "CF_HDROP"        },
        { CF_LOCALE,       "CF_LOCALE"       },
        { 0, NULL }
    };
    UINT fmt = 0;
    int  count = 0;

    if (!OpenClipboard(NULL)) { fprintf(stderr, "clip: cannot open clipboard\n"); return 1; }
    printf("Clipboard formats:\n");
    while ((fmt = EnumClipboardFormats(fmt)) != 0) {
        int i; const char *name = NULL;
        char num[32];
        for (i = 0; k_fmts[i].name; i++)
            if (k_fmts[i].fmt == fmt) { name = k_fmts[i].name; break; }
        if (!name) { sprintf(num, "CF_%u (private/registered)", fmt); name = num; }
        printf("  %s\n", name);
        count++;
    }
    CloseClipboard();
    if (!count) printf("  (empty)\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "clip  --  AeldreC2 Clipboard Utility\n\n"
            "Usage:\n"
            "  clip read              Print clipboard text to stdout\n"
            "  clip write <text>      Set clipboard text\n"
            "  clip set   <file>      Set clipboard from file\n"
            "  clip clear             Empty the clipboard\n"
            "  clip info              Show clipboard format list\n");
        return 1;
    }

    if (_stricmp(argv[1], "read") == 0) {
        return cmd_read();
    } else if (_stricmp(argv[1], "write") == 0) {
        if (argc < 3) { fprintf(stderr, "clip write: need <text>\n"); return 1; }
        /* Concatenate remaining args with spaces */
        {
            char buf[65536];
            int  i, pos = 0;
            for (i = 2; i < argc; i++) {
                int len = (int)strlen(argv[i]);
                if (pos + len + 1 >= (int)sizeof(buf)) break;
                if (i > 2) buf[pos++] = ' ';
                memcpy(buf + pos, argv[i], len); pos += len;
            }
            buf[pos] = '\0';
            return cmd_write(buf);
        }
    } else if (_stricmp(argv[1], "set") == 0) {
        if (argc < 3) { fprintf(stderr, "clip set: need <file>\n"); return 1; }
        return cmd_set_file(argv[2]);
    } else if (_stricmp(argv[1], "clear") == 0) {
        return cmd_clear();
    } else if (_stricmp(argv[1], "info") == 0) {
        return cmd_info();
    } else {
        fprintf(stderr, "clip: unknown verb '%s'\n", argv[1]);
        return 1;
    }
}
