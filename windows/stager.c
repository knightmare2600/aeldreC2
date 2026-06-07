/*
 * stager.c  --  AeldreC2  --  Tiny HTTP file server
 *
 * Binds to a port and serves a single file over HTTP.  Exits after the
 * file has been downloaded N times (default 1).  Useful for staging
 * payloads when you already have a shell but need to pull a file across.
 *
 * Usage:
 *   stager <file> [-p <port>] [-n <count>] [-q] [-o <output-path>]
 *
 *   <file>       File to serve
 *   -p <port>    Listen port  (default: random 1024-49151)
 *   -n <count>   Serve this many times then exit (default 1, 0=unlimited)
 *   -q           Quiet — no status output
 *   -o <path>    Override the URL path (default: basename of <file>)
 *   -a           Allow any path (ignore URL path matching)
 *
 * Build:
 *   wcl386 -bt=nt -l=nt -za99 -ox -D_WIN32 stager.c wsock32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

static char  g_filepath[MAX_PATH] = "";
static char  g_urlpath[256]       = "";
static int   g_port               = 0;
static int   g_max_serves         = 1;
static int   g_quiet              = 0;
static int   g_any_path           = 0;
static long  g_filesize           = 0;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void vlog(const char *msg)
{
    if (!g_quiet) fprintf(stderr, "%s", msg);
}

static int random_port(void)
{
    /* Use tick count + PID as seed for a port in 10240-49151 range */
    srand(GetTickCount() ^ GetCurrentProcessId());
    return 10240 + (rand() % 38912);
}

static void url_basename(const char *path, char *out, int outsz)
{
    const char *sl = strrchr(path, '\\');
    const char *fs = strrchr(path, '/');
    const char *p = path;
    if (sl && sl > p) p = sl + 1;
    if (fs && fs > p) p = fs + 1;
    strncpy(out, p, outsz - 1);
    out[outsz - 1] = '\0';
}

static const char *content_type(const char *path)
{
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    if (_stricmp(ext, ".exe") == 0) return "application/octet-stream";
    if (_stricmp(ext, ".dll") == 0) return "application/octet-stream";
    if (_stricmp(ext, ".zip") == 0) return "application/zip";
    if (_stricmp(ext, ".txt") == 0) return "text/plain";
    if (_stricmp(ext, ".html")== 0) return "text/html";
    if (_stricmp(ext, ".htm") == 0) return "text/html";
    return "application/octet-stream";
}

/* ------------------------------------------------------------------ */
/* Handle one HTTP connection                                          */
/* ------------------------------------------------------------------ */

static int handle_conn(SOCKET cs)
{
    char   req[2048], hdr[512], buf[8192], peerstr[32];
    int    n, in_body, served = 0;
    FILE  *f;
    struct sockaddr_in peer;
    int    plen = sizeof(peer);
    DWORD  sent_bytes = 0;
    char   req_path[512] = "";

    memset(&peer, 0, sizeof(peer));
    getpeername(cs, (struct sockaddr *)&peer, &plen);
    sprintf(peerstr, "%s:%d", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

    /* Read request (until double CRLF) */
    {
        int req_len = 0;
        req[0] = '\0';
        while (req_len < (int)sizeof(req) - 1) {
            n = recv(cs, req + req_len, 1, 0);
            if (n <= 0) goto close_conn;
            req_len++;
            req[req_len] = '\0';
            if (req_len >= 4 && strcmp(req + req_len - 4, "\r\n\r\n") == 0) break;
        }
    }

    /* Parse GET line */
    {
        char *p = req, *end;
        if (strncmp(p, "GET ", 4) != 0 && strncmp(p, "HEAD ", 5) != 0) {
            /* Not GET/HEAD — send 405 */
            const char *r405 = "HTTP/1.0 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
            send(cs, r405, (int)strlen(r405), 0);
            goto close_conn;
        }
        p = strchr(req, ' ') + 1;
        end = strchr(p, ' ');
        if (!end) end = strchr(p, '\r');
        if (!end) end = p + strlen(p);
        { int plen2 = (int)(end - p); if (plen2 >= 511) plen2 = 511; memcpy(req_path, p, plen2); req_path[plen2] = '\0'; }
    }

    /* Check path */
    if (!g_any_path) {
        char want[300];
        sprintf(want, "/%s", g_urlpath);
        if (strcmp(req_path, want) != 0 && strcmp(req_path, "/") != 0) {
            const char *r404 = "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            send(cs, r404, (int)strlen(r404), 0);
            {   char msg[256]; sprintf(msg, "stager: 404  %s from %s\n", req_path, peerstr); vlog(msg); }
            goto close_conn;
        }
    }

    /* Send file */
    f = fopen(g_filepath, "rb");
    if (!f) {
        const char *r500 = "HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
        send(cs, r500, (int)strlen(r500), 0); goto close_conn;
    }

    sprintf(hdr,
            "HTTP/1.0 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n"
            "Connection: close\r\n\r\n",
            content_type(g_filepath),
            g_filesize,
            g_urlpath);
    send(cs, hdr, (int)strlen(hdr), 0);

    while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0) {
        if (send(cs, buf, n, 0) == SOCKET_ERROR) break;
        sent_bytes += n;
    }
    fclose(f);
    served = 1;

    {
        char msg[256];
        sprintf(msg, "stager: served %s to %s (%lu bytes)\n", g_urlpath, peerstr, sent_bytes);
        vlog(msg);
    }

close_conn:
    closesocket(cs);
    (void)in_body;
    return served;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    WSADATA wsa;
    SOCKET  ls, cs;
    struct sockaddr_in addr;
    int     i, served = 0;
    char    msg[512];

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            g_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            g_max_serves = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-q") == 0) {
            g_quiet = 1;
        } else if (strcmp(argv[i], "-a") == 0) {
            g_any_path = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(g_urlpath, argv[++i], sizeof(g_urlpath) - 1);
        } else if (argv[i][0] != '-' && !g_filepath[0]) {
            strncpy(g_filepath, argv[i], sizeof(g_filepath) - 1);
        } else if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("stager  --  AeldreC2 HTTP file stager\n\n"
                   "Usage: stager <file> [-p port] [-n count] [-q] [-o urlpath] [-a]\n"
                   "  -p <port>   listen port (default random)\n"
                   "  -n <n>      serve n times then exit (default 1, 0=unlimited)\n"
                   "  -q          quiet\n"
                   "  -o <path>   URL path to serve on (default: filename)\n"
                   "  -a          serve on any URL path\n");
            return 0;
        }
    }

    if (!g_filepath[0]) {
        fprintf(stderr, "stager: specify a file to serve\n"
                        "Usage: stager <file> [-p port] [-n count] [-q]\n");
        return 1;
    }

    /* Check file exists and get size */
    {
        FILE *f = fopen(g_filepath, "rb");
        if (!f) { fprintf(stderr, "stager: cannot open '%s'\n", g_filepath); return 1; }
        fseek(f, 0, SEEK_END);
        g_filesize = ftell(f);
        fclose(f);
    }

    if (!g_urlpath[0])
        url_basename(g_filepath, g_urlpath, sizeof(g_urlpath));

    if (!g_port)
        g_port = random_port();

    if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0) {
        fprintf(stderr, "stager: WSAStartup failed\n"); return 1;
    }

    ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) { fprintf(stderr, "stager: socket() failed\n"); return 1; }

    {   int reuse = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)); }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((unsigned short)g_port);
    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(ls, 4) != 0) {
        fprintf(stderr, "stager: bind/listen failed (%d)\n", WSAGetLastError());
        closesocket(ls); WSACleanup(); return 1;
    }

    sprintf(msg, "stager: serving '%s' on http://0.0.0.0:%d/%s\n"
                 "        File size: %ld bytes  |  Serves: %s\n",
            g_filepath, g_port, g_urlpath, g_filesize,
            g_max_serves == 0 ? "unlimited" :
            (sprintf(msg + 200, "%d", g_max_serves), msg + 200));
    vlog(msg);

    for (;;) {
        cs = accept(ls, NULL, NULL);
        if (cs == INVALID_SOCKET) break;
        served += handle_conn(cs);
        if (g_max_serves > 0 && served >= g_max_serves) {
            sprintf(msg, "stager: served %d time(s), exiting.\n", served);
            vlog(msg);
            break;
        }
    }

    closesocket(ls);
    WSACleanup();
    return 0;
}
