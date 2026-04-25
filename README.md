# Lightweight Bash Host Discovery and TCP Port Scanner

A small Bash-based scanner for authorized internal testing when `nmap` is unavailable, inappropriate, or intentionally avoided. It performs basic host discovery and TCP connect checks without requiring root privileges.

## Purpose

This script is intended to provide a lightweight way to:

- Discover live hosts in a single `/24`-style subnet range.
- Load targets from a file.
- Check common TCP ports using Bash's `/dev/tcp` feature.
- Run in restricted environments without installing or invoking `nmap`.
- Operate without root privileges.

It is not a replacement for a full-featured scanner. It does not perform service detection, OS detection, UDP scanning, SYN scanning, vulnerability checks, stealth scanning, or banner grabbing.

## Requirements

Tested for Bash-compatible Linux environments with:

- `bash`
- `timeout`
- `sed`
- `ping` when using `-D ping` or `-D both`

Root privileges are not required. The script uses normal ICMP ping where available and standard TCP connect attempts through Bash `/dev/tcp`.

## Installation

```bash
chmod +x lightweight_scanner.sh
```

## Usage

### Subnet Mode

Scan a single subnet prefix and host range:

```bash
./lightweight_scanner.sh -s 192.168.1 -a 1 -z 254
```

Scan a smaller range with custom ports:

```bash
./lightweight_scanner.sh -s 10.10.10 -a 20 -z 50 -p 22,80,443
```

### File Mode

Create a target file with one IPv4 address per line:

```text
192.168.1.10
192.168.1.15
192.168.1.25
# Comments are ignored
```

Run the scanner against that file:

```bash
./lightweight_scanner.sh -f targets.txt
```

Run against a file with custom ports:

```bash
./lightweight_scanner.sh -f targets.txt -p 22,445,3389
```

## Discovery Modes

Use `-D` to choose how the script identifies live hosts before scanning ports.

| Mode | Description |
| --- | --- |
| `ping` | Default. Uses ICMP echo requests. Fast and simple, but hosts blocking ping may be missed. |
| `tcp` | Uses TCP connect checks against discovery ports. Useful when ICMP is blocked. |
| `both` | Treats a host as live if either ping or TCP discovery succeeds. |
| `none` | Skips discovery and scans every supplied target. Useful when discovery is unreliable. |

Examples:

```bash
./lightweight_scanner.sh -f targets.txt -D tcp
./lightweight_scanner.sh -f targets.txt -D both -P 22,80,443
./lightweight_scanner.sh -s 192.168.1 -a 1 -z 254 -D none -p 22,80,443,445
```

## Options

| Option | Description |
| --- | --- |
| `-s` | First three octets of a single subnet, such as `192.168.1`. |
| `-a` | Starting host number for subnet mode. |
| `-z` | Ending host number for subnet mode. |
| `-f` | Target file with one IPv4 address per line. |
| `-p` | Comma-separated TCP ports to scan. Default: `22,23,53,80,443,445,3389`. |
| `-D` | Discovery mode: `ping`, `tcp`, `both`, or `none`. Default: `ping`. |
| `-P` | Comma-separated TCP ports used for TCP discovery. Default: `22,80,443,445,3389`. |
| `-t` | TCP connection timeout in seconds. Default: `1`. |
| `-h` | Show help. |

## Example Output

```text
Starting host discovery using mode: both
Targets loaded: 3
----------------------------------------------
[+] Host is up: 192.168.1.10
[+] Host is up: 192.168.1.15

Starting TCP port scan...
Ports: 22 80 443
----------------------------------------------

Scanning 192.168.1.10...
  [OPEN] tcp/22
  [OPEN] tcp/443

Scanning 192.168.1.15...
  [OPEN] tcp/80

Open TCP ports found: 3

Scan complete.
```

## Limitations

- ICMP discovery can miss hosts that block ping.
- TCP discovery only identifies hosts that respond on the selected discovery ports.
- TCP connect scans are not stealthy and may be logged.
- `/dev/tcp` is a Bash feature and may not work in shells that are not Bash.
- UDP scanning is not supported.
- IPv6 is not supported.

## Legal and Ethical Use

Use this script only on systems and networks you own or have explicit authorization to test. Unauthorized scanning may violate laws, contracts, or acceptable use policies.

## Suggested Repository Structure

```text
.
├── lightweight_scanner.sh
├── README.md
└── targets.example.txt
```

## Optional Example Target File

```text
# targets.example.txt
192.168.1.10
192.168.1.15
192.168.1.25
```
