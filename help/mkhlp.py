#!/usr/bin/env python3
"""
mkhlp.py -- Generate aeldreC2.HLP (Windows 3.1 WinHelp format)

WinHelp 3.x binary format references:
  - Matthew Russotto, "WinHelp File Format" (reverse-engineering notes)
  - Various open-source WinHelp implementations

Usage:
    python3 mkhlp.py <output.hlp>

The |TOPIC record format (type bytes, field layout) is the least
standardised part across sources; if WinHelp.exe displays garbled
text adjust TOPIC_HDR_TYPE / TOPIC_TEXT_TYPE in the constants below.
"""

import struct, io, sys, os

# ======================================================================
# Binary format constants
# ======================================================================

WINHELP_MAGIC  = 0x00035F3F   # first DWORD of every WinHelp 3.x file
BTREE_MAGIC    = 0x293B        # internal B-tree filesystem magic
BLOCK_SIZE     = 4096          # B-tree page size == topic block size

# |SYSTEM header values (WinHelp 3.1)
SYS_MAGIC      = 0x036C
SYS_MINOR      = 0x0015        # format minor version
SYS_MAJOR      = 0x0001

# |SYSTEM option record types
SYS_REC_TITLE  = 0x0001
SYS_REC_CR     = 0x0002

# |TOPIC record types (WinHelp 3.x)
TOPIC_HDR_TYPE  = 0x02         # topic header record
TOPIC_TEXT_TYPE = 0x20         # text paragraph record

# |FONT family codes (Windows LOGFONT lfPitchAndFamily)
FF_SWISS        = 0x22         # e.g. Helv/Arial

# ======================================================================
# Topic data (all documentation content defined here)
# ======================================================================

TOPICS = [
    {
        "id":    "contents",
        "title": "ÆldreC2 Help — Contents",
        "keys":  ["contents"],
        "body":
            "ÆldreC2  —  Retro C2 Framework for Windows 3.11 / Win32s / NT\r\n"
            "\r\n"
            "CONTENTS\r\n"
            "--------\r\n"
            "  Overview\r\n"
            "  Joshua  —  C2 Controller\r\n"
            "  Tank Commands  —  Win32 implant commands\r\n"
            "  Tank16 Commands  —  Win16 implant commands\r\n"
            "  CLU  —  Implant Generator\r\n"
            "  Lightman / Flynn  —  Operator Clients\r\n"
            "  Grid  —  Port Scanner\r\n"
            "  ncwfw  —  MDI Netcat\r\n"
            "  ipcalc  —  Subnet Calculator\r\n"
            "  wget  —  HTTP Downloader\r\n"
            "  netstat  —  Active TCP/UDP connections\r\n"
            "  route    —  IP routing table\r\n"
            "  Network Utilities\r\n"
            "  NT Utilities\r\n"
            "  Themes\r\n",
    },
    {
        "id":    "overview",
        "title": "Overview",
        "keys":  ["overview", "introduction"],
        "body":
            "ÆldreC2 is an educational retro C2 framework targeting:\r\n"
            "  Windows 3.1 / Windows for Workgroups 3.11 (Win16)\r\n"
            "  Win32s (on top of Windows 3.11)\r\n"
            "  Windows NT 3.x / 4.0\r\n"
            "  Windows 95 (best effort)\r\n"
            "\r\n"
            "Built on PuTTY 0.83's crypto and SSH stack, compiled with\r\n"
            "OpenWatcom 2.0. All binaries run on real 1990s hardware.\r\n"
            "\r\n"
            "COMPONENTS\r\n"
            "----------\r\n"
            "  joshua.exe   C2 controller (MDI, TLS, multi-session)\r\n"
            "  tank.exe     Win32/Win32s connect-back implant\r\n"
            "  tank16.exe   Win16/WFW 3.11 connect-back implant\r\n"
            "  clu.exe      Implant generator / binary patcher\r\n"
            "  lightman.exe CLI operator client\r\n"
            "  flynn.exe    GUI operator client\r\n"
            "  grid.exe     TCP port scanner (GUI, Win32s)\r\n"
            "  ncwfw.exe    MDI Netcat with optional TLS\r\n"
            "  ipcalc32.exe Subnet calculator (Win32s)\r\n"
            "  wget.exe     HTTP/HTTPS/FTP downloader (Win32s)\r\n",
    },
    {
        "id":    "joshua",
        "title": "Joshua — C2 Controller",
        "keys":  ["joshua", "controller", "C2"],
        "body":
            "JOSHUA.EXE  —  C2 Controller\r\n"
            "Platforms: Win32s / NT 3.1+ / Win95\r\n"
            "\r\n"
            "MDI application. Listens on TCP port 4444 (configurable).\r\n"
            "Supports multiple simultaneous tank and operator sessions.\r\n"
            "Optional Schannel TLS (NT 4 SP3+ / Win95 OSR2+).\r\n"
            "\r\n"
            "FEATURES\r\n"
            "--------\r\n"
            "  Multi-session MDI with session list panel\r\n"
            "  Tank banner parsing (OS, hostname, shell)\r\n"
            "  File send/receive with progress bar\r\n"
            "  Screenshot capture and display\r\n"
            "  Session scripting  (Tank > Run Script...)\r\n"
            "  Macro recording / playback\r\n"
            "  Packet viewer (live hex dump MDI child)\r\n"
            "  21 colour themes (View > Theme)\r\n"
            "  Sound events on connect/disconnect\r\n"
            "  Subnet scan > Dumont pipeline (/scansubnet)\r\n"
            "  Tab completion for commands\r\n"
            "  Operator chat and key authentication\r\n"
            "  Full session logging to joshua.log\r\n"
            "\r\n"
            "STARTUP\r\n"
            "-------\r\n"
            "joshua.exe starts a config dialog where you set the listen\r\n"
            "port and server key. The server key is an 8-hex-digit token\r\n"
            "used to authenticate operator clients (Lightman / Flynn).\r\n",
    },
    {
        "id":    "tank",
        "title": "Tank Commands (Win32)",
        "keys":  ["tank", "implant", "commands", "Win32"],
        "body":
            "TANK.EXE  —  Win32 Connect-back Implant\r\n"
            "Platforms: Win32s / NT 3.1+ / Win95\r\n"
            "\r\n"
            "Connects to Joshua on the configured host:port. Commands\r\n"
            "are sent by the operator; output is streamed back.\r\n"
            "Reconnects automatically every 30 seconds on disconnect.\r\n"
            "\r\n"
            "SYSTEM COMMANDS\r\n"
            "---------------\r\n"
            "  sysinfo          OS, hostname, user, RAM, drives\r\n"
            "  env              List all environment variables\r\n"
            "\r\n"
            "PROCESS COMMANDS\r\n"
            "----------------\r\n"
            "  ps               List running processes (ToolHelp32)\r\n"
            "  pinfo <pid>      Detailed info for one process\r\n"
            "  kill <pid>       Terminate process by PID\r\n"
            "  tasklist         Enhanced ps with full executable paths\r\n"
            "\r\n"
            "FILE COMMANDS\r\n"
            "-------------\r\n"
            "  ls [path]        Directory listing\r\n"
            "  get <path>       Download file to operator\r\n"
            "  put <path>       Upload file from operator\r\n"
            "  del <path>       Delete file\r\n"
            "  ren <old> <new>  Rename / move file\r\n"
            "  find [root] <pat> Recursive file search\r\n"
            "  cwd / pwd        Print working directory\r\n"
            "  cd <path>        Change directory\r\n"
            "  cat <path>       Print file contents\r\n"
            "  less <path>      Paged file viewer\r\n"
            "\r\n"
            "REGISTRY COMMANDS\r\n"
            "-----------------\r\n"
            "  regq <key>       List registry key values\r\n"
            "  regs <key> <term> Recursive string search\r\n"
            "  rege <key> <name> <data>  Set REG_SZ value\r\n"
            "  regx <key>       Recursive export in .reg format\r\n"
            "\r\n"
            "NETWORK COMMANDS\r\n"
            "----------------\r\n"
            "  resolve <host>   DNS forward lookup\r\n"
            "  ifconfig         Network adapters and IPs (NT4+)\r\n"
            "  netstat          Active TCP/UDP connections (NT4+)\r\n"
            "  route            IP routing table (NT4+)\r\n"
            "  scan <args>      Embedded async TCP port scanner\r\n"
            "  portfwd <args>   TCP port forward\r\n"
            "  socks4 <port>    SOCKS4 proxy listener\r\n"
            "  relaystop [id]   Stop a relay\r\n"
            "\r\n"
            "OTHER COMMANDS\r\n"
            "--------------\r\n"
            "  screenshot       Capture screen as BMP\r\n"
            "  shell            Interactive command shell\r\n"
            "  persist [off]    Add/remove Win.INI load= persistence\r\n"
            "  smb <args>       NetBIOS/SMB info (shares, users, domain)\r\n"
            "  rdp <args>       RDP info (registry-based)\r\n"
            "  exit / quit      Disconnect session\r\n"
            "\r\n"
            "Note: ifconfig/netstat/route require iphlpapi.dll (NT4+).\r\n"
            "On NT 3.x these return 'not available'.\r\n",
    },
    {
        "id":    "tank16",
        "title": "Tank16 Commands (Win16)",
        "keys":  ["tank16", "Win16", "WFW", "implant"],
        "body":
            "TANK16.EXE  —  Win16 Connect-back Implant\r\n"
            "Platforms: Windows 3.1 / WFW 3.11 (no Win32s required)\r\n"
            "\r\n"
            "Connects to Joshua via WINSOCK.DLL (16-bit Winsock 1.1).\r\n"
            "TOOLHELP.DLL required for ps/kill/pinfo (standard on Win3.1).\r\n"
            "\r\n"
            "COMMANDS\r\n"
            "--------\r\n"
            "  sysinfo          Windows version, free memory, hostname\r\n"
            "  env              List environment via GetDOSEnvironment()\r\n"
            "  ps               List tasks via TOOLHELP TaskFirst/TaskNext\r\n"
            "  kill <mod|0xHH>  TerminateApp by module name or task handle\r\n"
            "  pinfo <mod|0xHH> Task details (TASKENTRY fields)\r\n"
            "  resolve <host>   DNS lookup via gethostbyname\r\n"
            "  ifconfig         Hostname + IP via gethostbyname; SYSTEM.INI fallback\r\n"
            "  netstat          Not available on Win16\r\n"
            "  route            Not available on Win16\r\n"
            "  ls [path]        Directory listing (_dos_findfirst)\r\n"
            "  get <path>       Download file\r\n"
            "  put <path>       Upload file\r\n"
            "  exit / quit      Disconnect\r\n"
            "  <anything else>  Passed to COMMAND.COM via WinExec\r\n",
    },
    {
        "id":    "clu",
        "title": "CLU — Implant Generator",
        "keys":  ["CLU", "patcher", "generator"],
        "body":
            "CLU.EXE  —  Implant Generator / Binary Patcher\r\n"
            "Platforms: Win32s / NT 3.1+ / Win95\r\n"
            "\r\n"
            "CLU scans a compiled tank.exe or tank16.exe for the magic\r\n"
            "signature 'AELDRECLU0001', then patches the host, port and\r\n"
            "TLS flag in-place to produce a configured implant binary.\r\n"
            "\r\n"
            "USAGE\r\n"
            "-----\r\n"
            "1. Browse to select a template binary (tank.exe or tank16.exe)\r\n"
            "2. Browse to set the output path for the patched binary\r\n"
            "3. Enter the C2 Host address (e.g. 192.168.1.100)\r\n"
            "4. Enter the C2 Port (default 4444)\r\n"
            "5. Tick TLS if the Joshua listener uses TLS\r\n"
            "6. Click Generate\r\n"
            "\r\n"
            "CONFIG BLOCK LAYOUT (offset from magic signature)\r\n"
            "--------------------------------------------------\r\n"
            "  Offset  0  :  magic[14]  'AELDRECLU0001\\0'\r\n"
            "  Offset 14  :  host[64]   null-terminated, null-padded\r\n"
            "  Offset 78  :  port[2]    little-endian WORD\r\n"
            "  Offset 80  :  tls[1]     0=plain, 1=TLS\r\n",
    },
    {
        "id":    "lightman",
        "title": "Lightman / Flynn — Operator Clients",
        "keys":  ["lightman", "Flynn", "operator"],
        "body":
            "LIGHTMAN.EXE  —  CLI Operator Client\r\n"
            "Platforms: Win32s / NT 3.1+ / Win95\r\n"
            "\r\n"
            "Command-line operator client. Connects to a running Joshua\r\n"
            "instance using the server key. Runs in a console window.\r\n"
            "\r\n"
            "FLYNN.EXE  —  GUI Operator Client\r\n"
            "Platforms: Win32s / NT 3.1+ / Win95\r\n"
            "\r\n"
            "Two-pane GUI client: left panel shows connected operators,\r\n"
            "right panel shows the session output and input area.\r\n"
            "\r\n"
            "PROTOCOL\r\n"
            "--------\r\n"
            "Both clients send:  Flynn/1 key=XXXXXXXX\\r\\n\r\n"
            "Then:               HANDLE <name>\\r\\n\r\n"
            "Then:               <text>\\r\\n  (chat or /commands)\r\n"
            "\r\n"
            "COMMANDS\r\n"
            "--------\r\n"
            "  /tanks           List connected tank sessions\r\n"
            "  /ops             List connected operator handles\r\n"
            "  /session <n>     Send next command to tank session N\r\n"
            "  /broadcast <cmd> Send command to all tank sessions\r\n",
    },
    {
        "id":    "grid",
        "title": "Grid — Port Scanner",
        "keys":  ["grid", "scanner", "ports"],
        "body":
            "GRID.EXE  —  TCP Port Scanner (GUI)\r\n"
            "Platforms: Win32s / NT / Win95\r\n"
            "\r\n"
            "Async non-blocking TCP scanner using a select() pool.\r\n"
            "No threads. Winsock 1.1 compatible. Owner-draw listbox\r\n"
            "with theme colours read from Joshua's WIN.INI entry.\r\n"
            "\r\n"
            "GRIDCLI.EXE  —  TCP Port Scanner (Console)\r\n"
            "Platforms: Win32 / NT\r\n"
            "\r\n"
            "Tab-delimited output for scripting and piping to Dumont.\r\n"
            "\r\n"
            "USAGE (GUI)\r\n"
            "-----------\r\n"
            "  Target   IP, CIDR (10.0.0.0/24), range (10.0.0.1-50)\r\n"
            "  Ports    Single, range (1-1024), or CSV (22,80,443)\r\n"
            "  Timeout  Connect timeout in milliseconds (default 500)\r\n"
            "  Banner   Grab first line after connect\r\n"
            "  Pool     Max concurrent connections (default 64)\r\n"
            "\r\n"
            "USAGE (CLI)\r\n"
            "-----------\r\n"
            "  grid <target> -p <ports> [-t ms] [-b] [-q] [-T n]\r\n"
            "\r\n"
            "  -q  Quiet: tab-delimited only, no progress, no window\r\n"
            "  -b  Banner grab first response line\r\n"
            "  -T  Pool size (max concurrent, default 64)\r\n"
            "\r\n"
            "SERVICES.DAT\r\n"
            "------------\r\n"
            "Grid reads a port-to-service name mapping from SERVICES.DAT\r\n"
            "(same directory as grid.exe, or %GRIDDATA%\\SERVICES.DAT).\r\n"
            "Format: one 'port/tcp  service_name' entry per line.\r\n",
    },
    {
        "id":    "ncwfw",
        "title": "ncwfw — MDI Netcat",
        "keys":  ["ncwfw", "netcat", "TCP"],
        "body":
            "NCWFW.EXE  —  MDI Netcat for Windows\r\n"
            "Platforms: Win32s / NT / Win95 (plain TCP)\r\n"
            "           NT 4 SP3+ / Win95 OSR2+ (TLS)\r\n"
            "\r\n"
            "Multiple concurrent TCP sessions in a Win32 MDI window.\r\n"
            "TLS uses Windows Schannel (secur32.dll), loaded dynamically;\r\n"
            "the binary runs anywhere, TLS checkbox greys out if absent.\r\n"
            "\r\n"
            "USAGE\r\n"
            "-----\r\n"
            "File > New Connection  opens a connect dialog.\r\n"
            "Enter host, port, and optionally check TLS or Listen mode.\r\n"
            "In Listen mode the application waits for an inbound connection\r\n"
            "instead of connecting outbound.\r\n"
            "\r\n"
            "Each connection opens as an MDI child window with an output\r\n"
            "area (read-only edit) and an input line with a Send button.\r\n"
            "Press Enter or click Send to transmit.\r\n",
    },
    {
        "id":    "ipcalc",
        "title": "ipcalc — Subnet Calculator",
        "keys":  ["ipcalc", "subnet", "CIDR"],
        "body":
            "IPCALC32.EXE  —  Subnet Calculator (Win32s / NT)\r\n"
            "IPCALC16.EXE  —  Subnet Calculator (Win16 / WFW 3.11)\r\n"
            "\r\n"
            "Command-line subnet calculator. Accepts CIDR notation or a\r\n"
            "separate dotted-quad mask argument.\r\n"
            "\r\n"
            "USAGE\r\n"
            "-----\r\n"
            "  ipcalc32 192.168.1.0/24\r\n"
            "  ipcalc32 10.0.0.0/8\r\n"
            "  ipcalc32 172.16.0.0 255.255.0.0\r\n"
            "  ipcalc32 -o result.txt 192.168.1.0/24\r\n"
            "\r\n"
            "OUTPUT\r\n"
            "------\r\n"
            "  Network address, broadcast, host range, host count\r\n"
            "  Address class (A/B/C) and flags:\r\n"
            "    RFC 1918 (PRIVATE), APIPA, MULTICAST, LOOPBACK\r\n"
            "\r\n"
            "  -o <file>  Write output to file (for Win32s clipboard use)\r\n",
    },
    {
        "id":    "wget",
        "title": "wget — HTTP Downloader",
        "keys":  ["wget", "HTTP", "download", "FTP"],
        "body":
            "WGET.EXE   —  HTTP/HTTPS/FTP Downloader (Win32s / NT)\r\n"
            "WGET16.EXE —  HTTP Downloader (Win16 / WFW 3.11)\r\n"
            "\r\n"
            "USAGE\r\n"
            "-----\r\n"
            "  wget <url> [-O <outfile>] [-q]\r\n"
            "\r\n"
            "  -O <file>  Save to named file (default: from URL)\r\n"
            "  -q         Quiet mode: suppress progress output\r\n"
            "\r\n"
            "PROTOCOLS\r\n"
            "---------\r\n"
            "  HTTP    Native Winsock 1.1 (works on Win32s)\r\n"
            "  HTTPS   WinInet (dynamically loaded; NT 3.51+ / Win95)\r\n"
            "  FTP     WinInet (as above)\r\n"
            "\r\n"
            "Note: HTTPS ignores SSL certificate errors (useful for\r\n"
            "internal/self-signed servers on vintage hardware).\r\n"
            "\r\n"
            "Win16 version (wget16.exe) supports HTTP only. Displays a\r\n"
            "MessageBox on completion instead of progress output.\r\n",
    },
    {
        "id":    "netstat",
        "title": "netstat — Active Connections",
        "keys":  ["netstat", "connections", "TCP", "UDP", "ports"],
        "body":
            "NETSTAT.EXE   —  Active TCP/UDP Connections (Win32 console)\r\n"
            "NETSTAT16.EXE —  Active TCP/UDP Connections (Win16 / WFW 3.11)\r\n"
            "\r\n"
            "USAGE\r\n"
            "-----\r\n"
            "  netstat        Show ESTABLISHED and LISTEN TCP connections\r\n"
            "  netstat -a     Show all connections including UDP listeners\r\n"
            "\r\n"
            "PLATFORM NOTES\r\n"
            "--------------\r\n"
            "  NT 4 / Win95+\r\n"
            "    Uses iphlpapi.dll GetTcpTable / GetUdpTable natively.\r\n"
            "\r\n"
            "  NT 3.x (3.1 / 3.5 / 3.51)\r\n"
            "    iphlpapi.dll not available on these platforms.\r\n"
            "    netstat.exe automatically falls back to executing the\r\n"
            "    system netstat.exe from %SystemRoot%\\system32\\ and\r\n"
            "    relaying its output.  NT 3.1 ships with netstat.exe\r\n"
            "    so this path works reliably.\r\n"
            "\r\n"
            "  Win32s / WFW 3.11\r\n"
            "    netstat.exe falls back to exec; if the system has no\r\n"
            "    netstat.exe a clear 'not available' message is shown.\r\n"
            "    netstat16.exe uses a GUI dialog and executes\r\n"
            "    'netstat -an' via COMMAND.COM, capturing output to\r\n"
            "    a temp file and displaying it in a scrollable window.\r\n"
            "    Requires Microsoft TCP/IP-32 or compatible stack.\r\n"
            "\r\n"
            "OUTPUT COLUMNS\r\n"
            "--------------\r\n"
            "  Proto   TCP or UDP\r\n"
            "  Local   Local IP address and port\r\n"
            "  Foreign Remote IP address and port (* = any for UDP)\r\n"
            "  State   TCP connection state (LISTEN, ESTABLISHED, etc.)\r\n",
    },
    {
        "id":    "route",
        "title": "route — Routing Table",
        "keys":  ["route", "routing", "gateway", "IP"],
        "body":
            "ROUTE.EXE   —  IP Routing Table (Win32 console)\r\n"
            "ROUTE16.EXE —  IP Routing Table (Win16 / WFW 3.11)\r\n"
            "\r\n"
            "USAGE\r\n"
            "-----\r\n"
            "  route print\r\n"
            "    Display the full IP routing table.\r\n"
            "\r\n"
            "  route add <dest> mask <mask> <gateway> [metric <n>]\r\n"
            "    Add a route.  Example:\r\n"
            "    route add 10.0.0.0 mask 255.0.0.0 192.168.1.1\r\n"
            "\r\n"
            "  route delete <dest>\r\n"
            "    Delete all routes matching the destination.\r\n"
            "\r\n"
            "PLATFORM NOTES\r\n"
            "--------------\r\n"
            "  NT 4 / Win95+\r\n"
            "    Uses iphlpapi.dll GetIpForwardTable natively.\r\n"
            "    Add/delete use CreateIpForwardEntry / DeleteIpForwardEntry.\r\n"
            "\r\n"
            "  NT 3.x (3.1 / 3.5 / 3.51)\r\n"
            "    Falls back to executing the system route.exe from\r\n"
            "    %SystemRoot%\\system32\\.  Also reads persistent routes\r\n"
            "    from the registry key:\r\n"
            "    HKLM\\SYSTEM\\CurrentControlSet\\Services\\\r\n"
            "         Tcpip\\Parameters\\PersistentRoutes\r\n"
            "\r\n"
            "  Win32s / WFW 3.11\r\n"
            "    route.exe falls back to exec; route16.exe shows the\r\n"
            "    routing table in a GUI window via COMMAND.COM capture.\r\n"
            "    Requires Microsoft TCP/IP-32 or compatible stack.\r\n"
            "\r\n"
            "OUTPUT COLUMNS\r\n"
            "--------------\r\n"
            "  Destination  Network destination address\r\n"
            "  Mask         Subnet mask\r\n"
            "  Gateway      Next-hop IP address\r\n"
            "  If           Interface index\r\n"
            "  Metric       Route cost (lower is preferred)\r\n",
    },
    {
        "id":    "network",
        "title": "Network Utilities",
        "keys":  ["arp", "stager", "ncnt", "network"],
        "body":
            "NETWORK UTILITIES\r\n"
            "-----------------\r\n"
            "\r\n"
            "ARP.EXE  —  ARP Table Viewer + ICMP Ping Sweep\r\n"
            "Platforms: Win32 / NT 4+\r\n"
            "  arp          Display ARP table\r\n"
            "  arp -p <net> Ping sweep the /24 subnet of <net>\r\n"
            "\r\n"
            "STAGER.EXE  —  HTTP File Staging Server\r\n"
            "Platforms: Win32 / NT\r\n"
            "  stager <port> <dir>  Serve files from <dir> on <port>\r\n"
            "  Useful for delivering payloads via wget on the target.\r\n"
            "\r\n"
            "NCNT.EXE  —  Netcat for NT (Console)\r\n"
            "Platforms: Win32 / NT\r\n"
            "  ncnt <host> <port>   Connect and relay stdio\r\n"
            "  ncnt -l <port>       Listen for inbound connection\r\n"
            "\r\n"
            "DUMONT.EXE  —  Network Mapper\r\n"
            "Platforms: Win32s / NT / Win95\r\n"
            "  Reads grid -q TSV output and renders a scrollable node map.\r\n"
            "  Joshua launches it automatically after /scansubnet.\r\n"
            "  Accepts piped stdin or File > Open.\r\n",
    },
    {
        "id":    "ntutils",
        "title": "NT Utilities",
        "keys":  ["svcany", "regcli", "whoami", "clip", "timestmp", "NT"],
        "body":
            "NT UTILITIES  (Win32 / NT 3.1+)\r\n"
            "------------------------------\r\n"
            "\r\n"
            "SVCANY.EXE  —  Install any executable as an NT service\r\n"
            "  svcany install <name> <exe> [args]\r\n"
            "  svcany remove <name>\r\n"
            "  svcany start <name>  /  stop <name>\r\n"
            "\r\n"
            "REGCLI.EXE  —  CLI Registry Tool (NT 3.x / NT 4.0)\r\n"
            "  regcli query  HKLM\\Software\\...\r\n"
            "  regcli set    HKLM\\Software\\... ValueName Data\r\n"
            "  regcli delete HKLM\\Software\\...\r\n"
            "\r\n"
            "WHOAMI.EXE  —  Identity / SID / Groups (pre-XP NT)\r\n"
            "  Prints current user, domain, SID, and group memberships.\r\n"
            "\r\n"
            "CLIP.EXE  —  Clipboard Read / Write\r\n"
            "  clip           Print clipboard text contents to stdout\r\n"
            "  echo text|clip Copy stdin to clipboard\r\n"
            "\r\n"
            "TIMESTMP.EXE  —  File Timestamp Utility\r\n"
            "  timestmp -c src dst   Copy timestamps from src to dst\r\n"
            "  timestmp -s file YYYYMMDDhhmmss   Set timestamps\r\n",
    },
    {
        "id":    "themes",
        "title": "Themes",
        "keys":  ["themes", "colours", "appearance"],
        "body":
            "COLOUR THEMES\r\n"
            "-------------\r\n"
            "\r\n"
            "Joshua has 21 built-in colour themes (View > Theme).\r\n"
            "The active theme is written to WIN.INI [AeldreC2] Theme=<name>\r\n"
            "and all other GUI tools (CLU, Grid, Flynn, ncwfw, jloshtog,\r\n"
            "markuped, dumont) read it at startup.\r\n"
            "\r\n"
            "Joshua is the only tool with a theme picker menu.\r\n"
            "Other apps follow Joshua's selection automatically.\r\n"
            "\r\n"
            "AVAILABLE THEMES\r\n"
            "----------------\r\n"
            "  solarized         Solarized Dark (default)\r\n"
            "  british           British Rail\r\n"
            "  class91           InterCity Class 91\r\n"
            "  dark              Dark\r\n"
            "  db-1980s          Deutsche Bundesbahn\r\n"
            "  dsb               DSB (Danish Railways)\r\n"
            "  gemstones         Gemstones\r\n"
            "  intercity-swallow InterCity Swallow\r\n"
            "  irn-bru           IRN-BRU\r\n"
            "  light             Light\r\n"
            "  matrix            Matrix\r\n"
            "  network-southeast Network SouthEast\r\n"
            "  ns                NS (Dutch Railways)\r\n"
            "  pan-am            Pan Am\r\n"
            "  procomm           ProComm\r\n"
            "  renaissance       Renaissance\r\n"
            "  scotrail          ScotRail\r\n"
            "  teletext          Teletext\r\n"
            "  twa               TWA\r\n"
            "  viarail           VIA Rail\r\n"
            "  viarail-soft      VIA Rail Soft\r\n",
    },
]

# ======================================================================
# |FONT builder
# ======================================================================

def build_font():
    """
    |FONT: font table.
    Header: num_fonts(W) num_descriptors(W) default_font(W)
    Each entry: attrs(B) halfpoints(B) family(B) facename[20]
    """
    buf = io.BytesIO()
    buf.write(struct.pack('<HHH', 1, 0, 0))           # 1 font, no char descs, default=0
    face = b'Helv\x00' + b'\x00' * 15                 # 20-byte face name
    buf.write(struct.pack('<BBB', 0, 20, FF_SWISS))    # normal, 10pt, Swiss family
    buf.write(face)
    return buf.getvalue()

# ======================================================================
# |SYSTEM builder
# ======================================================================

def build_system(title, copyright_str=''):
    """
    |SYSTEM: help file metadata.
    Header (12 bytes) + option records.
    """
    buf = io.BytesIO()
    buf.write(struct.pack('<HHHIH',
        SYS_MAGIC,   # 0x036C
        SYS_MINOR,   # 0x0015
        SYS_MAJOR,   # 0x0001
        0,           # GenDate
        0x0004))     # Flags

    # Title record
    tb = title.encode('windows-1252') + b'\x00'
    buf.write(struct.pack('<HH', SYS_REC_TITLE, len(tb)))
    buf.write(tb)

    # Copyright record
    if copyright_str:
        cb = copyright_str.encode('windows-1252') + b'\x00'
        buf.write(struct.pack('<HH', SYS_REC_CR, len(cb)))
        buf.write(cb)

    return buf.getvalue()

# ======================================================================
# |TOPIC builder
# ======================================================================

def build_topic_file(topics):
    """
    |TOPIC: one 4096-byte block per topic.

    Block layout:
      [0..7]   block header: prev_offset(i), next_offset(i)
      [8..]    topic header record + text record(s)

    Topic header record (TOPIC_HDR_TYPE = 0x02):
      type(B) | total_size(I) | next_topic_off(i) | prev_topic_off(i)
      | null-terminated title | null-terminated context-id

    Text record (TOPIC_TEXT_TYPE = 0x20):
      type(B) | total_size(I) | para_flags(H) | text (null-terminated)

    Note: if WinHelp displays garbled content, adjust TOPIC_HDR_TYPE /
    TOPIC_TEXT_TYPE constants at the top of this file.
    """
    blocks = []
    offsets = {}   # topic id -> byte offset in |TOPIC

    n = len(topics)
    for i, topic in enumerate(topics):
        offsets[topic['id']] = i * BLOCK_SIZE
        prev_off = (i - 1) * BLOCK_SIZE if i > 0 else -1
        next_off = (i + 1) * BLOCK_SIZE if i < n - 1 else -1

        blk = io.BytesIO()

        # Block header (8 bytes)
        blk.write(struct.pack('<ii', prev_off, next_off))

        # --- Topic header record ---
        title_b = topic['title'].encode('windows-1252') + b'\x00'
        ctx_b   = topic['id'].encode('ascii') + b'\x00'
        rec_payload = struct.pack('<ii', -1, -1) + title_b + ctx_b
        # type(1) + size(4) + payload
        rec_size = 1 + 4 + len(rec_payload)
        blk.write(bytes([TOPIC_HDR_TYPE]))
        blk.write(struct.pack('<I', rec_size))
        blk.write(rec_payload)

        # --- Text paragraph record(s) ---
        # Split body into paragraphs and write each as a separate record
        for para in topic['body'].split('\r\n'):
            para_b = para.encode('windows-1252') + b'\x00'
            # type(1) + size(4) + para_flags(2) + text
            rec_size = 1 + 4 + 2 + len(para_b)
            blk.write(bytes([TOPIC_TEXT_TYPE]))
            blk.write(struct.pack('<I', rec_size))
            blk.write(struct.pack('<H', 0x0000))   # no paragraph formatting
            blk.write(para_b)

        # Pad / truncate to BLOCK_SIZE
        data = blk.getvalue()
        data = (data + b'\x00' * BLOCK_SIZE)[:BLOCK_SIZE]
        blocks.append(data)

    return b''.join(blocks), offsets

# ======================================================================
# |CONTEXT builder
# ======================================================================

def _ctx_hash(s):
    """WinHelp context string hash (simple polynomial CRC over lowercased chars)."""
    h = 0
    for c in s.lower():
        h = (h * 43 + ord(c)) & 0xFFFFFFFF
    return h

def build_context(topic_offsets):
    """
    |CONTEXT: sorted array of (hash, topic_block_offset) pairs.
    Preceded by a 4-byte count.
    """
    entries = sorted(
        ((_ctx_hash(k), v) for k, v in topic_offsets.items()),
        key=lambda x: x[0]
    )
    buf = io.BytesIO()
    buf.write(struct.pack('<I', len(entries)))
    for h, off in entries:
        buf.write(struct.pack('<Ii', h, off))
    return buf.getvalue()

# ======================================================================
# B-tree internal-file-system directory
# ======================================================================

def build_btree(dir_entries):
    """
    dir_entries: list of (name_bytes_without_null, abs_offset, size)

    B-tree header (34 bytes) + one 4096-byte leaf page.
    The leaf page maps filenames (|SYSTEM, |TOPIC, ...) to
    (absolute_file_offset, byte_size) pairs.
    """
    # Sort entries alphabetically by name (WinHelp B-tree is sorted)
    dir_entries = sorted(dir_entries, key=lambda e: e[0].upper())

    # Build leaf page content
    page_hdr_sz = 8   # 4 × INT16: nUsed, nEntries, prevPage, nextPage
    page_body = io.BytesIO()
    for name, offset, size in dir_entries:
        page_body.write(name + b'\x00')
        page_body.write(struct.pack('<II', offset, size))

    body_bytes = page_body.getvalue()
    n_used = page_hdr_sz + len(body_bytes)

    leaf_page = struct.pack('<hhhh', n_used, len(dir_entries), -1, -1)
    leaf_page += body_bytes
    leaf_page = (leaf_page + b'\x00' * BLOCK_SIZE)[:BLOCK_SIZE]

    # B-tree header:
    # magic(H) flags(B) pagebits(B) structure(14s)
    # zero(H) splits(H) rootpage(h) neg1(h) totalpages(H) levels(H) entries(i)
    structure = b'z44\x00' + b'\x00' * 10   # 14 bytes: null-str key, 2×4-byte values
    btree_hdr = struct.pack('<HBB14sHHhhHHi',
        BTREE_MAGIC,      # 0x293B
        0x04,             # Flags (leaf-only tree)
        12,               # PageBits (2^12 = 4096 byte pages)
        structure,
        0,                # MustBeZero
        0,                # PageSplits
        0,                # RootPage index
        -1,               # MustBeNeg1
        1,                # TotalPages
        1,                # Levels
        len(dir_entries), # TotalEntries
    )

    return btree_hdr + leaf_page

# ======================================================================
# Top-level assembly
# ======================================================================

HEADER_SIZE  = 16   # FILEHEADER: magic(I) dirstart(I) freestart(i) filesize(I)
BTREE_HDR_SZ = 34   # sizeof(BTREEHDR) — computed above
BTREE_TOTAL  = BTREE_HDR_SZ + BLOCK_SIZE   # header + one leaf page

def build_hlp(topics, title, copyright_str=''):
    # Build internal files
    system_data  = build_system(title, copyright_str)
    topic_data, offsets = build_topic_file(topics)
    font_data    = build_font()
    context_data = build_context(offsets)

    # Lay out the file:
    #   [file header 16B] [B-tree dir 4130B] [|SYSTEM] [|TOPIC] [|FONT] [|CONTEXT]
    dir_start      = HEADER_SIZE
    system_offset  = dir_start + BTREE_TOTAL
    topic_offset   = system_offset + len(system_data)
    font_offset    = topic_offset  + len(topic_data)
    context_offset = font_offset   + len(font_data)
    total_size     = context_offset + len(context_data)

    # Build directory B-tree
    btree_data = build_btree([
        (b'|CONTEXT', context_offset, len(context_data)),
        (b'|FONT',    font_offset,    len(font_data)),
        (b'|SYSTEM',  system_offset,  len(system_data)),
        (b'|TOPIC',   topic_offset,   len(topic_data)),
    ])
    assert len(btree_data) == BTREE_TOTAL, f"B-tree size mismatch: {len(btree_data)}"

    # Build file header
    file_hdr = (
        struct.pack('<I', WINHELP_MAGIC) +
        struct.pack('<I', dir_start) +
        struct.pack('<i', -1) +         # FreeBlockStart: none
        struct.pack('<I', total_size)
    )
    assert len(file_hdr) == HEADER_SIZE

    hlp = file_hdr + btree_data + system_data + topic_data + font_data + context_data
    assert len(hlp) == total_size, f"Size mismatch: got {len(hlp)}, expected {total_size}"
    return hlp

# ======================================================================
# Entry point
# ======================================================================

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else 'aeldreC2.hlp'
    data = build_hlp(
        topics=TOPICS,
        title='\xC6ldreC2 Help',
        copyright_str='\xC6ldreC2 Project  --  Educational C2 Framework',
    )
    with open(out, 'wb') as f:
        f.write(data)
    print(f'  Generated {out} ({len(data):,} bytes, {len(TOPICS)} topics)')

if __name__ == '__main__':
    main()
