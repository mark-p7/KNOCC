# KNOCC — Knock-based Network Operations over Covert Channels

> **Academic project — COMP 8505.** This is an educational backdoor/rootkit simulation built to study how covert remote-access tooling works and, just as importantly, how it is detected and defended against. It is intended for use only in isolated lab environments (VMs or machines you own and control). It is **not** a tool for use against any system you do not have explicit authorization to test.

## Overview

KNOCC is a commander–victim backdoor simulation written in Python that demonstrates the core techniques a covert remote-access tool relies on: staying hidden on the network, staying hidden on the host, and maintaining reliable control over an unreliable channel.

A **commander** program drives the session through a menu-based interface, and a **victim** program listens for and carries out requests. Rather than opening an obvious listening port, the victim stays silent until it observes a specific **port-knock sequence**, at which point it confirms the connection and begins accepting commands. All subsequent communication is hidden in a **covert channel** — data is smuggled inside UDP header fields (length and checksum) rather than packet payloads. Because UDP is unreliable and the usable space per packet is only a few bytes, KNOCC implements a small go-back-N protocol on top to keep transfers ordered and complete.

Once connected, the commander can run shell commands on the victim and read the output, transfer files in either direction, watch a file or directory for changes and mirror them back, run a keylogger, and uninstall the victim cleanly. On the host side, the victim conceals itself by renaming its process to evade casual inspection with tools like `top` and `htop`.

## Features

- **Port-knocking authentication** — victim stays dark until the correct knock sequence is received
- **Covert channel** — data hidden in UDP length/checksum header fields, not payloads
- **Reliable transport** — go-back-N layered over UDP for ordered, complete delivery
- **Remote command execution** — run commands on the victim, return output to the commander
- **Bidirectional file transfer** — upload to and download from the victim
- **File & directory watching** — monitor for changes and mirror them back
- **Keylogging** — capture keystrokes and retrieve the log
- **Process concealment** — victim renames its own process on the host
- **Self-uninstall** — victim removes itself and exits on command

## Detection & defense

A deliberate goal of this project is to document how these techniques fail against good security practice. The covert channel used here (bulk-modifying UDP length/checksum) produces malformed packets that are readily caught by a properly configured IDS or firewall, which can drop them before they reach the host. More advanced covert channels evade this by altering only a few bits at a time behind believable payloads. Host-side, process renaming can be unmasked by comparing multiple sources in `/proc` (`comm`, `cmdline`, `exe`), since a concealed process often fails to keep all of them consistent. Firewalls, IDS, and routine monitoring and auditing remain the practical defenses.

## Platforms

Tested on macOS 26.2, Windows 10, and Ubuntu 24.04 LTS.

> **Note:** the keylogger backend is OS-specific — on Linux it uses evdev via `/dev/input`.

## Installation

Obtain both the commander and victim from the `./source` directory, then set up a virtual environment:

```bash
cd source
python -m venv .venv
```

Activate the environment:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the **victim first**, since the commander needs to connect to it. Both require root/administrator privileges.

```bash
# On the victim machine
sudo python victim.py

# On the commander machine
sudo python commander.py <target_ip_addr>
```

### Arguments

| Argument | Purpose |
| --- | --- |
| `<target_ip_addr>` | IP address of the victim machine |

### Example

```bash
# victim
sudo python victim.py

# commander
sudo python commander.py 192.168.1.85
```

Once connected, the commander presents a numbered menu of operations (disconnect, uninstall, start/stop keylogger, retrieve keylog, transfer to/from victim, watch file, watch directory, run command).

## Tech

Python. Communication is raw UDP with a custom covert-channel protocol over the header fields.

## License / disclaimer

Coursework for educational purposes only. Use exclusively in controlled, isolated environments on systems you own or are explicitly authorized to test.
