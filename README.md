# JOCKY Defensive Forensics Prototype

JOCKY is a small, cross-platform defensive DSL prototype for computer/network forensic collection.

## Safety boundary

This prototype intentionally does **not** implement antivirus/EDR bypass, polymorphic payload generation, process injection/hollowing, API unhooking/direct-syscall evasion, BYOVD/kernel tampering, persistence, privilege escalation, covert C2, or domain fronting.

It demonstrates the defensive core:

**JOCKY source -> parser -> JSON intermediate representation (IR) -> forensic runtime -> JSON report**

## Features

- Cross-platform Python runtime for Windows and Ubuntu/Linux
- Host inventory
- Current-user/session information
- Process inventory
- Network connection inventory
- Windows service inventory where supported
- SHA-256 hashing of explicitly selected files
- Bounded recursive directory inventory
- JSON reports suitable for a central collector
- Optional central collector using normal HTTP on a trusted network
- Explicit JSON IR boundary for future compiler/front-end work

## Quick start

```bash
python -m pip install -r requirements.txt
python -m jocky.cli examples/triage.jky --pretty
python -m jocky.cli examples/triage.jky --output triage_report.json
python -m jocky.cli examples/triage.jky --emit-ir triage_ir.json
```

Run the central collector:

```bash
python -m jocky.server --host 127.0.0.1 --port 8765
```

Send a report:

```bash
python -m jocky.cli examples/triage.jky --post http://127.0.0.1:8765/api/reports
```

## JOCKY syntax

```text
JOCKY 0.1

profile "endpoint_triage"

collect host
collect users
collect processes
collect network
collect services

hash "/etc/hosts" sha256
scan_dir "/tmp" max_depth=1
output "json"
```

Windows paths can be written with forward slashes, e.g. `C:/Windows/System32/drivers/etc/hosts`.

## Architecture

```text
JOCKY source
     |
     v
+------------+       +-------------+       +------------------+
| Parser /   | ----> | JSON IR     | ----> | Forensic Runtime |
| Front-end  |       | actions[]   |       | collectors       |
+------------+       +-------------+       +--------+---------+
                                                   |
                                                   v
                                           +------------------+
                                           | Evidence Report  |
                                           | JSON             |
                                           +--------+---------+
                                                    |
                                                    v
                                           +------------------+
                                           | Central Collector|
                                           | HTTP + SQLite    |
                                           +------------------+
```
