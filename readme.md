# Recon Framework

A raw-packet network reconnaissance framework built with Python and Scapy, inspired by Nmap, Recon-ng, and the recon phase of Metasploit. Designed for hands-on learning of TCP/IP internals, low-level packet crafting, and offensive security concepts.

> **Legal Notice:** This tool is intended for use on networks and systems you own or have explicit written permission to test. Unauthorised scanning is illegal in most jurisdictions. The authors accept no liability for misuse.

---

## Features

### Scan Types

| Scan | Flag | Description |
|---|---|---|
| SYN Scan | `syn` | Half-open stealth scan — sends SYN, reads SYN-ACK/RST |
| ACK Scan | `ack` | Firewall mapping — determines FILTERED vs UNFILTERED |
| FIN Scan | `fin` | Sends FIN; closed ports reply RST, open ports are silent |
| Xmas Scan | `xmas` | Sends FIN+PSH+URG; same logic as FIN scan |
| UDP Scan | `udp` | ICMP port-unreachable detection for UDP services |
| OS Fingerprint | `os` | TTL + window size + TCP options + ICMP behaviour |
| Banner Grab | `banner` | HTTP headers, SSH version strings, FTP banners |
| Ping Sweep | `ping` | ICMP echo across a subnet (multi-threaded) |
| ARP Sweep | `arp` | Layer-2 host discovery (LAN only) |
| All | `all` | Runs every scan and correlates OS evidence |

### Evasion Techniques
- **Scan timing randomisation** — random inter-packet delay (50–300 ms)
- **Random TTL values** — avoids consistent fingerprinting by IDS/IPS
- **Spoofed source ports** — uses trusted port numbers (20, 53, 67, 123, 443)

### OS Fingerprinting
Correlates four independent signals:
1. **TTL Analysis** — Linux ≤64, Windows ≤128, Cisco ≤255
2. **TCP Window Size** — maps known values to OS families
3. **TCP Options** — Timestamp + WScale → Linux; NOP → Windows
4. **Banner Evidence** — SSH/HTTP version strings confirm or override

### Banner Grabbing
- HTTP/HTTPS header extraction (Server: field)
- SSH version string (`SSH-2.0-OpenSSH_...`)
- FTP welcome banner
- TLS-aware connection on port 443

---

## Project Structure

```
recon-framework/
│
├── core/                   # Shared utilities and analysis modules
│   ├── __init__.py
│   ├── banner.py           # Banner grabbing and service detection
│   ├── evasion.py          # Timing, TTL, and source-port evasion helpers
│   ├── fingerprint.py      # OS fingerprinting logic
│   ├── output.py           # JSON result serialisation
│   └── utils.py            # DNS resolution, port parsing, service names
│
├── scanner/                # Individual scan modules
│   ├── __init__.py
│   ├── ack_scan.py
│   ├── arp_sweep.py
│   ├── fin_scan.py
│   ├── ping_sweep.py
│   ├── syn_scan.py
│   ├── udp_scan.py
│   └── xmas_scan.py
│
├── main.py                 # CLI entry point
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Requirements

- Python 3.8+
- Linux or WSL2 (raw sockets require a real Linux kernel — WSL1 and native Windows are not supported)
- Root / sudo privileges

---

## Installation

### Linux (native)

```bash
git clone https://github.com/Lynessa07/recon-framework.git
cd recon-framework
pip install -r requirements.txt
```

### Windows via WSL2

Raw sockets require a real Linux kernel, which WSL2 provides (WSL1 does not — make sure you're on WSL2).

**1. Confirm you're on WSL2** (run in PowerShell):
```powershell
wsl --list --verbose
```
The VERSION column must show `2`. If it shows `1`, upgrade:
```powershell
wsl --set-version <DistroName> 2
```

**2. Open your WSL2 terminal** (Ubuntu, Debian, etc.) and clone the repo:
```bash
git clone https://github.com/Lynessa07/recon-framework.git
cd recon-framework
```

**3. Install Python dependencies inside WSL2:**
```bash
pip install -r requirements.txt
```

**4. Run scans from inside WSL2** (not from PowerShell directly):
```bash
sudo python3 main.py -t 192.168.1.10 -s syn
```

> **Note:** ARP sweeps (`-s arp`) only discover hosts on the same Layer-2 network as your WSL2 interface. For scanning your actual LAN, use ping sweep (`-s ping`) or target the WSL2 virtual network adapter's subnet.

---

## Usage

All commands must be run as **root** (raw socket access):

```bash
sudo python3 main.py -s <scan_type> [options]
```

### Options

```
-t, --target    Target IP address or hostname
-n, --network   Target subnet in CIDR notation (e.g. 192.168.1.0/24)
-p, --ports     Port specification:
                  Single:  80
                  List:    22,80,443
                  Range:   1-1024
                  Default: 14 common ports
-s, --scan      Scan type (required): syn ack fin xmas udp os banner ping arp all
```

### Examples

```bash
# SYN scan on default common ports
sudo python3 main.py -t 192.168.1.10 -s syn

# SYN scan on custom port range
sudo python3 main.py -t 192.168.1.10 -s syn -p 1-1024

# ACK scan (firewall rule mapping)
sudo python3 main.py -t 192.168.1.10 -s ack -p 22,80,443

# FIN scan
sudo python3 main.py -t 192.168.1.10 -s fin -p 22,80,443

# Xmas scan
sudo python3 main.py -t 192.168.1.10 -s xmas -p 1-500

# UDP scan
sudo python3 main.py -t 192.168.1.10 -s udp -p 53,67,123,161

# OS fingerprinting
sudo python3 main.py -t 192.168.1.10 -s os

# Banner grabbing on open ports
sudo python3 main.py -t 192.168.1.10 -s banner -p 22,80,443

# Ping sweep across a subnet
sudo python3 main.py -n 192.168.1.0/24 -s ping

# ARP sweep (LAN only)
sudo python3 main.py -n 192.168.1.0/24 -s arp

# Full scan — all techniques + correlated OS guess + saved JSON report
sudo python3 main.py -t 192.168.1.10 -s all -p 1-1024
```

---

## Output

Scan results are printed to stdout in aligned columns. The `all` scan additionally writes a structured JSON report:

```
results.json  ← excluded from git via .gitignore
```

Example `results.json`:
```json
{
    "timestamp": "2026-05-22 23:56:16.601293",
    "scan_results": {
        "target": "45.33.32.156",
        "open_ports": [22, 80],
        "os_fingerprint": {
            "ttl": 43,
            "ttl_guess": "Linux/Unix",
            "window_size": 64240,
            "window_guess": "Windows",
            "signature_guess": "Unknown",
            "final_guess": "Mixed/Unknown"
        },
        "services": {
            "22": {
                "service": "SSH Server",
                "version": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
                "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
            },
            "80": {
                "service": "Apache Web Server",
                "version": "Apache/2.4.7 (Ubuntu)",
                "banner": "HTTP/1.1 200 OK\r\n..."
            }
        },
        "correlated_os_guess": {
            "banner_guess": "Linux/Unix",
            "final_guess": "Linux/Unix",
            "confidence": "High"
        }
    }
}
```

---

## How Each Scan Works

### SYN Scan (Half-Open)
Sends a TCP SYN packet. A SYN-ACK reply means the port is **open**; a RST-ACK means **closed**; no reply means **filtered**. The scanner immediately sends a RST to tear down the half-open connection without completing the handshake — leaving minimal log traces.

### ACK Scan
Sends a TCP ACK packet (no prior SYN). Because there is no established session, compliant firewalls **drop** the packet (FILTERED) while stateless or misconfigured firewalls let it through and the host replies with RST (UNFILTERED). This maps firewall rules rather than open ports.

### FIN / Xmas Scans
Both exploit RFC 793 behaviour: packets with unexpected flags (FIN alone, or FIN+PSH+URG for Xmas) are silently dropped by **open** ports and answered with RST by **closed** ports. Note that Windows deviates from the RFC and replies RST regardless, so these scans are most reliable against Linux/Unix targets.

### UDP Scan
Sends an empty UDP datagram. An **ICMP Port Unreachable** (type 3, code 3) response means **closed**. No response means **open|filtered** (the port may be open or a firewall is dropping packets). An actual UDP response confirms **open**.

### OS Fingerprinting
Collects four signals from a single SYN probe and one ICMP echo:
- **TTL** from the IP header
- **Window size** from the TCP header
- **TCP options** (presence of Timestamp, WScale, NOP)
- **ICMP echo** behaviour

Signals are cross-correlated and, in `all` mode, further validated against banner evidence to produce a confidence-rated final guess.

---

## Evasion Details

| Technique | Implementation | Purpose |
|---|---|---|
| Random delay | `time.sleep(uniform(0.05, 0.3))` | Breaks timing-based IDS signatures |
| Random TTL | `randint(50, 120)` | Avoids consistent TTL fingerprinting |
| Spoofed source port | Chosen from `[20,53,67,123,443]` | Mimics DNS/NTP/HTTPS traffic to bypass ACLs |

---

## Learning Outcomes

Working through this codebase gives practical exposure to:

- **TCP/IP fundamentals** — flags, handshakes, and RFC 793 edge cases
- **Raw socket programming** — bypassing the OS network stack with Scapy
- **Packet crafting** — constructing IP/TCP/UDP/ICMP headers manually
- **OS fingerprinting techniques** — used by Nmap's `-O` flag
- **Firewall evasion** — how stateful vs stateless inspection differs
- **Linux networking internals** — how the kernel responds to malformed packets
- **Concurrent I/O** — `ThreadPoolExecutor` for fast subnet sweeps

---

## License

MIT License — see [LICENSE](LICENSE) for full text. You are free to use, modify, and distribute this software for personal, educational, and research purposes.

---

## Disclaimer

This tool sends raw packets that may trigger IDS/IPS alerts and be logged by target hosts. Only use it against:
- Your own machines
- Dedicated lab environments (e.g. HackTheBox, TryHackMe, DVWA)
- Systems where you hold explicit written authorisation

The author is not responsible for any illegal use of this software.