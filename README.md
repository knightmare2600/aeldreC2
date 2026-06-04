# ÆldreC2 - C2 for the masses

> "Shall we play a game?"

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

## Planned Capabilities

### Remote Administration

* Remote command execution
* Remote shell
* Environment variable viewing
* System information collection
* User information collection

### Process Management

* Process listing
* Process termination
* Process information
* Task monitoring

### File Operations

* File upload
* File download
* Directory browsing
* File deletion
* File renaming
* File search

### Registry Operations

* Registry viewing
* Registry searching
* Registry export
* Registry editing (optional)

### Networking

* Connection enumeration
* Route table viewing
* Hostname resolution
* Interface information
* Remote ping
* Basic service discovery

### Monitoring

* Event logging
* Session timeline
* Connection statistics
* Host inventory

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

## TODO

### Port Scanner

Develop a standalone Windows 3.x-compatible network scanner.

Planned components:

* Command-line scanner
* GUI scanner
* TCP connect scanning
* Service identification
* Banner grabbing
* Host discovery
* Import of service fingerprints

The goal is not to recreate Nmap, but to provide a capable vintage Windows network scanner that can interoperate with contemporary service fingerprint data where practical.

### Future Work

* Session scripting
* Plugin architecture
* Macro support
* Integrated packet viewer
* Network mapping
* Historical Windows theme packs
* Sound support for session events
* WinG visual enhancements
* Offline log analysis

---

## Disclaimer

ÆldreC2 is an educational and research project intended for authorised administration, testing, and historical computing experimentation.

Users are responsible for ensuring compliance with all applicable laws, regulations, and policies.
