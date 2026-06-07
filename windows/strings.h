/*
 * strings.h  --  AeldreC2 string ID table
 *
 * All user-visible strings in every tool are referenced by these IDs.
 * The runtime language is chosen at startup by lang_detect() in lang.h;
 * the language block offsets are:
 *
 *   EN-GB  +1000   (default — the Queen's English)
 *   EN-US  +2000
 *   DA     +3000   (Dansk)
 *   DE     +4000   (Deutsch)
 *
 * Use LS(IDS_FOO) everywhere instead of a hardcoded string.
 */

#ifndef STRINGS_H
#define STRINGS_H

/* ------------------------------------------------------------------ */
/* Common (base IDs 1-99)                                             */
/* ------------------------------------------------------------------ */
#define IDS_OK                  1
#define IDS_CANCEL              2
#define IDS_ERROR               3
#define IDS_CLOSE               4
#define IDS_BROWSE              5
#define IDS_SAVE                6
#define IDS_COPY                7
#define IDS_NEW                 8
#define IDS_OPEN                9
#define IDS_YES                10
#define IDS_NO                 11
#define IDS_HELP               12
#define IDS_ABOUT              13
#define IDS_EXIT               14
#define IDS_CONNECT            15
#define IDS_DISCONNECT         16
#define IDS_STOP               17
#define IDS_GENERATE           18
#define IDS_SEND               19
#define IDS_READY              20
#define IDS_LANG_NOTE          21   /* humorous British English notice */
#define IDS_ABOUT_TITLE        22

/* ------------------------------------------------------------------ */
/* Joshua (100-199)                                                   */
/* ------------------------------------------------------------------ */
#define IDS_JOSH_TITLE              100
#define IDS_JOSH_CONSOLE_TITLE      101
#define IDS_JOSH_MENU_FILE          102
#define IDS_JOSH_MENU_TANK          103
#define IDS_JOSH_MENU_WINDOW        104
#define IDS_JOSH_FILE_NEW           105
#define IDS_JOSH_FILE_DISCONNECT    106
#define IDS_JOSH_FILE_EXIT          107
#define IDS_JOSH_TANK_SYSINFO       108
#define IDS_JOSH_TANK_PS            109
#define IDS_JOSH_TANK_LS            110
#define IDS_JOSH_TANK_GET           111
#define IDS_JOSH_TANK_PUT           112
#define IDS_JOSH_TANK_SS            113
#define IDS_JOSH_TANK_REGQ          114
#define IDS_JOSH_WIN_TILEH          115
#define IDS_JOSH_WIN_TILEV          116
#define IDS_JOSH_WIN_CASCADE        117
#define IDS_JOSH_WIN_CLOSEALL       118
#define IDS_JOSH_STARTUP_TITLE      119
#define IDS_JOSH_STARTUP_PORT       120
#define IDS_JOSH_STARTUP_KEY        121
#define IDS_JOSH_STARTUP_REGEN      122
#define IDS_JOSH_STARTUP_START      123
#define IDS_JOSH_STATUS_LISTENING   124
#define IDS_JOSH_STATUS_TANK_CONN   125
#define IDS_JOSH_STATUS_READY       126
#define IDS_JOSH_STATUS_BUSY        127
#define IDS_JOSH_STATUS_DC          128
#define IDS_JOSH_RELAY_MENU         129
#define IDS_JOSH_RELAY_PORTFWD      130
#define IDS_JOSH_RELAY_SOCKS4       131
#define IDS_JOSH_RELAY_STOP         132

/* ------------------------------------------------------------------ */
/* Grid (200-299)                                                     */
/* ------------------------------------------------------------------ */
#define IDS_GRID_TITLE              200
#define IDS_GRID_TARGET             201
#define IDS_GRID_PORTS              202
#define IDS_GRID_TIMEOUT            203
#define IDS_GRID_POOL               204
#define IDS_GRID_BANNER_CHK         205
#define IDS_GRID_SCAN               206
#define IDS_GRID_MENU_VIEW          207
#define IDS_GRID_THEME_DEFAULT      208
#define IDS_GRID_THEME_SOL_DARK     209
#define IDS_GRID_THEME_SOL_LIGHT    210
#define IDS_GRID_THEME_TERMINAL     211
#define IDS_GRID_STATUS_READY       212
#define IDS_GRID_STATUS_DONE        213

/* ------------------------------------------------------------------ */
/* Lightman (300-349)                                                 */
/* ------------------------------------------------------------------ */
#define IDS_LM_TITLE                300
#define IDS_LM_DLG_TITLE            301
#define IDS_LM_HANDLE_PROMPT        302
#define IDS_LM_CONNECT_BTN          303
#define IDS_LM_USAGE                304
#define IDS_LM_DISCONNECTED         305

/* ------------------------------------------------------------------ */
/* Flynn (350-399)                                                    */
/* ------------------------------------------------------------------ */
#define IDS_FL_TITLE                350
#define IDS_FL_DLG_TITLE            351
#define IDS_FL_HOST                 352
#define IDS_FL_PORT                 353
#define IDS_FL_KEY                  354
#define IDS_FL_HANDLE               355
#define IDS_FL_CONNECT_BTN          356
#define IDS_FL_DISCONNECTED         357

/* ------------------------------------------------------------------ */
/* CLU (400-449)                                                      */
/* ------------------------------------------------------------------ */
#define IDS_CLU_TITLE               400
#define IDS_CLU_TEMPLATE            401
#define IDS_CLU_OUTPUT              402
#define IDS_CLU_HOST                403
#define IDS_CLU_PORT                404
#define IDS_CLU_TLS                 405
#define IDS_CLU_GENERATE            406

/* ------------------------------------------------------------------ */
/* markuped (450-499)                                                 */
/* ------------------------------------------------------------------ */
#define IDS_ME_TITLE                450
#define IDS_ME_APP                  451   /* "markuped" */
#define IDS_ME_ABOUT_TEXT           452
#define IDS_ME_FILE                 453
#define IDS_ME_EDIT                 454
#define IDS_ME_FORMAT               455
#define IDS_ME_VIEW                 456
#define IDS_ME_BOLD                 457
#define IDS_ME_ITALIC               458
#define IDS_ME_CODE                 459
#define IDS_ME_H1                   460
#define IDS_ME_H2                   461
#define IDS_ME_H3                   462
#define IDS_ME_BQUOTE               463
#define IDS_ME_LIST_ITEM            464
#define IDS_ME_HR                   465
#define IDS_ME_TOGGLE_PREVIEW       466

/* ------------------------------------------------------------------ */
/* wget (500-549)                                                     */
/* ------------------------------------------------------------------ */
#define IDS_WG_TITLE                500
#define IDS_WG_DLG_TITLE            501
#define IDS_WG_URL_LABEL            502
#define IDS_WG_SAVE_AS_LABEL        503
#define IDS_WG_DOWNLOAD_BTN         504
#define IDS_WG_DOWNLOADING          505
#define IDS_WG_DONE_FMT             506

/* ------------------------------------------------------------------ */
/* ncnt (550-599)                                                     */
/* ------------------------------------------------------------------ */
#define IDS_NC_USAGE                550
#define IDS_NC_LISTENING            551
#define IDS_NC_CONNECTED            552
#define IDS_NC_CLOSED               553

/* ------------------------------------------------------------------ */
/* svcany (600-649)                                                   */
/* ------------------------------------------------------------------ */
#define IDS_SVC_USAGE               600
#define IDS_SVC_INSTALLED           601
#define IDS_SVC_REMOVED             602
#define IDS_SVC_STARTED             603
#define IDS_SVC_STOPPED             604
#define IDS_SVC_NOT_NT              605

/* ------------------------------------------------------------------ */
/* regcli (650-699)                                                   */
/* ------------------------------------------------------------------ */
#define IDS_REG_USAGE               650
#define IDS_REG_NOT_FOUND           651
#define IDS_REG_SUCCESS             652
#define IDS_REG_EXPORT_HEADER       653

/* ------------------------------------------------------------------ */
/* Utility tools: whoami, arp, stager, clip, timestamp (700-799)      */
/* ------------------------------------------------------------------ */
#define IDS_WHO_USAGE               700
#define IDS_ARP_USAGE               710
#define IDS_STG_USAGE               720
#define IDS_STG_LISTENING           721
#define IDS_STG_SERVED              722
#define IDS_CP_USAGE                730
#define IDS_TS_USAGE                740

#endif /* STRINGS_H */
