# Recon Framework — Technical Documentation

## Executive Summary

Recon Framework is a raw-packet network reconnaissance tool built in Python with Scapy, designed to teach offensive security fundamentals through hands-on packet crafting and analysis. It implements nine distinct reconnaissance techniques — from classical TCP SYN scans to OS fingerprinting via TTL analysis and TCP window size inference.

This document provides the technical depth required for understanding the framework's architecture, scan mechanics, packet-level implementation, and the signals used for OS detection.

---

## Table of Contents

1. Architecture & Design
2. TCP/IP Scan Mechanics
3. OS Fingerprinting Logic
4. Implementation Details
5. Performance & Limitations
6. Security Considerations

---

## Architecture & Design

### Module Organization

```
recon-framework/
├── core/                    # Shared analysis and I/O
│   ├── banner.py           # Service version detection via banners
│   ├── evasion.py          # IDS/IPS evasion techniques
│   ├── fingerprint.py      # OS detection via passive signals
│   ├── output.py           # JSON serialisation
│   └── utils.py            # DNS resolution, port parsing
│
├── scanner/                # Individual scan implementations
│   ├── syn_scan.py         # Half-open TCP scanning
│   ├── ack_scan.py         # Firewall rule mapping
│   ├── fin_scan.py         # RFC 793 edge-case detection
│   ├── xmas_scan.py        # FIN+PSH+URG flag combination
│   ├── udp_scan.py         # ICMP-based UDP state inference
│   ├── ping_sweep.py       # ICMP-based host discovery (threaded)
│   └── arp_sweep.py        # Layer-2 ARP-based discovery
│
└── main.py                 # CLI orchestration
```

### Design Principles

- **Modularity**: Each scan type is independent; easy to add new techniques
- **Layered I/O**: Scapy abstracts raw sockets; no OS-specific code in scan logic
- **Evasion by design**: Timing and source-port randomisation built into the core loop
- **Signal correlation**: OS fingerprinting combines four independent signals before output
- **Operational discipline**: Results saved to JSON for post-processing, not stdout-only

---

## TCP/IP Scan Mechanics

### 1. SYN Scan (Half-Open / Stealth Scan)

**Concept**: The three-way handshake's first message (SYN) is sent without completing the connection.

**Packet flow:**
```
Attacker                          Target (port 22)
  |                                   |
  |-------- TCP SYN -------->         |
  |                                   |
  |   <------ TCP SYN-ACK ------      | (port is OPEN)
  |                                   |
  |-------- TCP RST -------->         | (tear down)
  |                                   |
```

**Implementation** (`syn_scan.py`):
```python
packet = IP(dst=target, ttl=random_ttl()) / TCP(
    sport=spoofed_source_port(),
    dport=port,
    flags="S"  # SYN flag only
)
response = sr1(packet, timeout=1, verbose=0)

if response[TCP].flags == 0x12:  # SYN-ACK (0x12 = 0b00010010)
    state = "OPEN"
    # Send RST to avoid full connection
    send(IP(dst=target) / TCP(..., flags="R", seq=response[TCP].ack))
elif response[TCP].flags == 0x14:  # RST-ACK (0x14 = 0b00010100)
    state = "CLOSED"
else:
    state = "FILTERED"
```

**Why "stealth"?** The connection is never logged by most traditional firewalls/IDS because the three-way handshake never completes. Modern stateful inspection still sees the SYN + RST pattern.

**State interpretation:**
- `OPEN`: SYN-ACK received → application is listening
- `CLOSED`: RST-ACK received → port exists but no application
- `FILTERED`: No response → firewall is dropping packets or host is unreachable

---

### 2. ACK Scan (Firewall Rule Mapping)

**Concept**: Send an ACK packet to a port with no prior SYN — this violates the TCP state machine and reveals how the firewall behaves.

**Packet flow:**
```
Attacker                          Firewall / Target
  |                                   |
  |-------- TCP ACK -------->         |
  |                                   |
  | Compliant firewall (stateful):    | (drops silently)
  |   <------ (no response) ------    |
  |                                   |
  | Stateless firewall:               |
  |   <------ TCP RST ------          | (responds to any packet)
  |                                   |
```

**Implementation** (`ack_scan.py`):
```python
packet = IP(dst=target, ttl=random_ttl()) / TCP(
    sport=spoofed_source_port(),
    dport=port,
    flags="A"  # ACK flag only
)
response = sr1(packet, timeout=1, verbose=0)

if response and response[TCP].flags == 0x4:  # RST (0x4)
    state = "UNFILTERED"  # Firewall let it through
else:
    state = "FILTERED"  # Firewall dropped it
```

**Interpretation:**
- `UNFILTERED`: RST received → port is reachable (stateless rule or no firewall)
- `FILTERED`: No response → stateful firewall is blocking

**Use case**: Map which ports a firewall is willing to forward traffic to, regardless of whether services are listening.

---

### 3. FIN Scan (RFC 793 Exploitation)

**Concept**: Exploit RFC 793 Section 3.9, which states that packets with unexpected flags (like a FIN on a port with no active connection) should be silently ignored by **open** ports but answered with RST by **closed** ports.

**Packet flow:**
```
Attacker                          Target (port 22 OPEN)
  |                                   |
  |-------- TCP FIN -------->         |
  |   (violates RFC 793)              |
  |   <------ (no response) ------    | (silently ignores)
  |                                   |
```

vs.

```
Attacker                          Target (port 23 CLOSED)
  |                                   |
  |-------- TCP FIN -------->         |
  |                                   |
  |   <------ TCP RST ------          | (sends reset)
  |                                   |
```

**Implementation** (`fin_scan.py`):
```python
packet = IP(dst=target, ttl=random_ttl()) / TCP(
    sport=spoofed_source_port(),
    dport=port,
    flags="F"  # FIN flag only
)
response = sr1(packet, timeout=1, verbose=0)

if response and response[TCP].flags == 0x14:  # RST-ACK
    state = "CLOSED"
else:
    state = "OPEN|FILTERED"
```

**Interpretation:**
- `CLOSED`: RST received → port is closed (host is reachable)
- `OPEN|FILTERED`: No response → either open (ignored FIN) or filtered (firewall dropped it)

**Caveat**: Windows deviates from RFC 793 and sends RST regardless of port state, making this scan unreliable against Windows targets.

---

### 4. Xmas Scan (FIN+PSH+URG)

**Concept**: Similar to FIN scan but sets three flags (FIN, PSH, URG) — the lights-on-everywhere analogy.

**Packet structure:**
```python
flags="FPU"  # FIN (0x01) | PSH (0x08) | URG (0x20) = 0x29
```

**Behaviour**: Identical interpretation to FIN scan (RFC 793 edge case).

**Why multiple variants?** Different combinations may evade certain filters:
- FIN alone: Some IDS rules specifically block FIN scans
- PSH+URG: Less common, may bypass aged filters
- All three: Maximum visibility into RFC 793 compliance

---

### 5. UDP Scan (ICMP-Based State Inference)

**Concept**: Send an empty UDP datagram and interpret the ICMP response.

**Packet flow:**
```
Attacker                          Target (port 53 OPEN)
  |                                   |
  |-------- UDP (empty) -------->     |
  |                                   |
  |   <------ UDP response ------     | (port is OPEN)
  |                                   |
```

vs.

```
Attacker                          Target (port 9999 CLOSED)
  |                                   |
  |-------- UDP (empty) -------->     |
  |                                   |
  |   <------ ICMP Port Unreachable --|
  |           (type 3, code 3)        |
  |                                   |
```

**Implementation** (`udp_scan.py`):
```python
packet = IP(dst=target, ttl=random_ttl()) / UDP(dport=port)
response = sr1(packet, timeout=2, verbose=0)

if response is None:
    state = "OPEN|FILTERED"
elif response.haslayer(ICMP) and response[ICMP].type == 3 and response[ICMP].code == 3:
    state = "CLOSED"
else:
    state = "OPEN"  # UDP response received
```

**Interpretation:**
- `OPEN`: UDP response received (host is listening on the port)
- `CLOSED`: ICMP Port Unreachable (type 3, code 3)
- `OPEN|FILTERED`: No response (port may be open or firewall is rate-limiting ICMP)

**Challenges**: UDP scanning is slow because:
- ICMP responses are rate-limited (typically 1/second per port)
- Many firewalls suppress ICMP Port Unreachable
- Timeout must be longer (2s vs 1s for TCP)

---

### 6. Ping Sweep (ICMP Host Discovery)

**Concept**: Send ICMP Echo Request (ping) to a range of IPs and collect Echo Reply responses.

**Implementation** (`ping_sweep.py`):
```python
packet = IP(dst=str(ip)) / ICMP()
response = sr1(packet, timeout=1, verbose=0)

if response:
    live_hosts.append(str(ip))  # Echo reply received
```

**Parallelisation**: Uses `ThreadPoolExecutor(max_workers=100)` to probe 100 hosts concurrently, reducing total scan time from O(n) to O(n/100).

**Limitations**: Many modern hosts/firewalls disable ICMP echo entirely, making this technique unreliable on the modern internet.

---

### 7. ARP Sweep (Layer-2 Discovery)

**Concept**: Broadcast an ARP request ("Who has IP X.X.X.X?") to the entire subnet and collect MAC address replies.

**Implementation** (`arp_sweep.py`):
```python
arp = ARP(pdst=network)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
packet = ether / arp

result = srp(packet, timeout=2, verbose=0)[0]  # Send and receive at Layer 2

for sent, received in result:
    host = {
        "ip": received.psrc,
        "mac": received.hwsrc
    }
```

**Why ARP?** ARP is typically NOT firewalled because it's Layer 2 and exists below IP routing. This makes it the most reliable host discovery method on LANs.

**Scope limitation**: Only works on the **local broadcast domain**. For hosts on different subnets, use ping sweep or router discovery (ICMP Router Advertisement).

---

## OS Fingerprinting Logic

### Concept

OS fingerprinting infers the target OS by analyzing four **passive signals** from a single SYN probe and one ICMP echo, all from Layer 3 & 4 headers. No additional interrogation is required.

### The Four Signals

#### Signal 1: TTL (Time To Live) Analysis

The IP header's TTL field is decremented by 1 at each router hop. Different OSes set different initial TTL values:

| Initial TTL | Final TTL (at scanner, 0 hops away) | OS |
|---|---|---|
| 64 | 64 | Linux/Unix (FreeBSD, macOS, etc.) |
| 128 | 128 | Windows (XP, Vista, 7, 10, 11) |
| 255 | 255 | Cisco, network gear |

**Implementation** (`fingerprint.py`):
```python
def ttl_analysis(ttl):
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Network Device"
    return "Unknown"
```

**Caveat**: If the target is multiple hops away (non-zero hop count), the TTL will be lower and misclassified. This method assumes a **direct (0-hop or few-hop) connection**.

---

#### Signal 2: TCP Window Size

The TCP header includes a 16-bit **window size** field indicating how many bytes the sender can receive. This value is OS-specific and predictable:

```python
def window_analysis(window):
    windows_map = {
        5840:  "Linux",
        29200: "Linux",
        64240: "Windows",
        65535: "FreeBSD",
    }
    return windows_map.get(window, "Unknown")
```

**Why does this work?** Different OSes hardcode different default window sizes when establishing connections. A value of 64240 is almost certainly Windows; 65535 suggests FreeBSD.

**Limitations**: Modern OSes (Linux 5.x+, Windows 10+) often negotiate window sizes dynamically, reducing the accuracy of this signal.

---

#### Signal 3: TCP Options

The TCP header can carry optional fields in a variable-length **options** section. Common options include:
- `MSS` (Maximum Segment Size) — negotiated window
- `Timestamp` — used for RTT estimation and sequence number validation
- `WScale` — window scaling (RFC 1323)
- `NOP` — no-operation padding
- `SackOK` — Selective Acknowledgement support

**Linux/Unix typically includes:**
- Timestamp + WScale (modern TCP stacks)

**Windows typically includes:**
- NOP (legacy stacks)

**Implementation**:
```python
option_names = [opt[0] for opt in response[TCP].options]

if "Timestamp" in option_names and "WScale" in option_names:
    signature_guess = "Linux/Unix"
elif "NOP" in option_names:
    signature_guess = "Windows"
else:
    signature_guess = "Unknown"
```

---

#### Signal 4: Banner Evidence

When `syn_scan` identifies open ports, the `banner.py` module connects and reads the first bytes (HTTP Server header, SSH version string, FTP welcome message). Version strings often reveal the OS explicitly:

```
SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13  ← Linux (Ubuntu)
Server: Microsoft-IIS/10.0                   ← Windows
Server: Apache/2.4.41 (Ubuntu 20.04)        ← Linux (Ubuntu)
```

---

### Signal Correlation Logic

The framework collects all signals and uses a **voting algorithm**:

```python
if ttl_guess == window_guess or ttl_guess == signature_guess:
    final_guess = ttl_guess
elif window_guess == signature_guess:
    final_guess = window_guess
else:
    final_guess = "Mixed/Unknown"

# In 'all' scan mode: if banner_os_guess matches any signal → High Confidence
# if banner_os_guess overrides a tie → Medium Confidence
# otherwise → Low Confidence
```

**Example 1 (High Confidence)**:
```
TTL: Linux/Unix
Window: Linux (29200)
Banner: Ubuntu SSH
→ Final: Linux/Unix (High Confidence)
```

**Example 2 (Mixed)**:
```
TTL: Linux/Unix
Window: Windows (64240)
Banner: Unknown (firewall blocked)
→ Final: Mixed/Unknown (Low Confidence)
```

**Example 3 (Banner Override)**:
```
TTL: Unknown (hop count > 0)
Window: Unknown
Banner: Windows IIS
→ Final: Windows (Medium Confidence)
```

---

## Implementation Details

### Packet Crafting with Scapy

**Raw IP packet:**
```python
from scapy.all import IP, TCP, ICMP, send, sr1

# Craft a packet
packet = IP(dst="192.168.1.10", ttl=50) / TCP(
    sport=1234,           # Source port
    dport=80,             # Destination port
    flags="S",            # SYN flag
    seq=1000              # Initial sequence number
)

# Send and wait for a single response (blocking)
response = sr1(packet, timeout=1, verbose=0)
```

**Layer structure**: Scapy uses `/` operator to stack layers (bottom-up: IP → TCP).

---

### Evasion Mechanisms

#### 1. Random Delay

```python
def random_delay():
    time.sleep(random.uniform(0.05, 0.3))
```

Called before every packet. Prevents IDS from correlating timing patterns. Typical IDS rules look for:
- Rapid-fire packets (signature of automated scanning)
- Exact inter-packet intervals (signature of tools like Nmap with `-T` timing template)

By inserting 50–300 ms jitter, the traffic becomes harder to distinguish from legitimate interactive traffic.

---

#### 2. Random TTL

```python
def random_ttl():
    return random.randint(50, 120)
```

Different from the target's initial TTL (which is 64 or 128). This prevents IDS fingerprinting the **scanner's OS** from the TTL in the sent packets.

**Why 50–120?** It avoids predictable values:
- Too low (< 30): packets expire before reaching distant targets
- Too high (> 128): Windows uses 128, standing out
- 50–120: overlaps Linux and Windows ranges, ambiguous

---

#### 3. Spoofed Source Port

```python
def spoofed_source_port():
    return random.choice([20, 53, 67, 123, 443])
```

Uses commonly allowed ports (FTP DATA, DNS, DHCP, NTP, HTTPS) to bypass ACLs that allow "trusted" services but block ephemeral ports (1024–65535).

---

### Multi-Threading in Ping Sweep

```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(ping_host, ip) for ip in network.hosts()]
    for future in futures:
        result = future.result()
        if result:
            live_hosts.append(result)
```

**Why 100 workers?** Balances:
- **Faster discovery**: 100 concurrent pings per second vs 1 sequential ping per second
- **Network saturation**: 100 is well below typical link capacity (1000s of Mbps)
- **Responsiveness**: Not overwhelming target or router ARP tables

---

### JSON Output

The `all` scan serialises results to `results.json` with a timestamp:

```json
{
    "timestamp": "2026-05-22 23:56:16.601293",
    "scan_results": {
        "target": "45.33.32.156",
        "open_ports": [22, 80],
        "os_fingerprint": { ... },
        "services": { ... },
        "correlated_os_guess": { ... }
    }
}
```

This format is:
- **Parseable** by downstream tools (post-processing, dashboards, reporting)
- **Timestamped** for audit logs
- **Flat enough** for grep/jq one-liners
- **Excluded from git** to avoid committing operational data

---

## Performance & Limitations

### Scan Speed

| Scan | Ports | Avg Time | Bottleneck |
|------|-------|----------|------------|
| SYN | 1000 | 1–2 min | Network timeout per closed port (1s × ~900 no-response) |
| ACK | 1000 | 1–2 min | Same |
| FIN | 1000 | 1–2 min | Same |
| UDP | 100  | 3–5 min | ICMP rate-limiting (1 response/sec) |
| Ping sweep | /24 (256 IPs) | 5–10 sec | Parallelised to 256 concurrent |
| ARP sweep  | /24 (256 IPs) | 1–2 sec | Layer-2 (no routing overhead) |

**Optimisations:**
- Increase timeout on distant networks (–t flag analog: currently hardcoded to 1s)
- Reduce port range (–p 80,443 is faster than –p 1-65535)
- Use ARP for LAN discovery instead of ping sweep

---

### Accuracy Concerns

**TTL fingerprinting fails if:**
- Target is multiple hops away (TTL decremented by routers)
- Target uses non-standard initial TTL (e.g., router with TTL=100)

**Window size fails if:**
- Target uses dynamic window sizing (modern OSes)
- Multiple OS versions use the same value

**Banner grabbing fails if:**
- Services are firewalled behind a reverse proxy (banner reveals proxy, not target)
- Target disables banners (hardened configurations)

**ARP sweep fails if:**
- Target is on a different subnet (no ARP broadcast reachability)
- Target doesn't respond to ARP (some VPN clients, containerised environments)

---

### Resource Usage

Typical single-scan impact:
- **CPU**: < 1% (I/O bound, waiting for responses)
- **Memory**: ~20 MB (Scapy packet buffers)
- **Bandwidth**: 
  - TCP scans: ~100 bytes/packet × 1000 ports = ~100 KB
  - UDP scans: ~50 bytes/packet × 100 ports + ICMP responses = ~5 KB
  - ARP sweep: ~28 bytes/packet × 256 IPs = ~7 KB

---

## Security Considerations

### Detection by IDS/IPS

Modern intrusion detection systems (Suricata, Snort) recognise:
- **SYN scans**: Rapid SYN packets followed by RST (rule: count SYN → RST pairs)
- **FIN/Xmas scans**: FIN/PSH/URG flags on unusual ports (rule: any non-establishment flag)
- **Ping sweeps**: ICMP Echo burst (rule: > 10 ICMP Echo in 10 sec from one source)
- **ARP scans**: ARP broadcast storm (rule: ARP requests to unused IPs)

**Mitigation attempts** (implemented):
- Random delay: Breaks rapid-fire detection
- Spoofed source ports: Makes traffic look like FTP/DNS/NTP
- Random TTL: Prevents scanner fingerprinting

**Modern IDS detects anyway** because:
- Random delay is still detectable as "too regular" vs human-interactive traffic
- Source port spoofing doesn't change packet structure (still ACK flag, still port scan signature)
- The only true stealth is *no scanning* — all reconnaissance is detectable with sufficient monitoring

---

### Legal & Ethical Boundaries

This tool **must only be used on:**
- Systems you own
- Systems where you hold written authorisation
- Dedicated lab environments (HackTheBox, TryHackMe, etc.)

Unauthorised port scanning is illegal under:
- **USA**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **UK**: Computer Misuse Act 1990, s.1
- **EU**: ePrivacy Directive (2002/58/EC)
- **Australia**: Computer Crimes Act 1900

---

### Responsible Disclosure

If scanning reveals vulnerabilities:
1. Document the findings (timestamps, CVE IDs, severity)
2. Contact the owner via official security contact (security.txt, bug bounty program)
3. Allow 90 days for patching before public disclosure
4. Do not exploit the vulnerability further without consent

---

## Conclusion

Recon Framework provides a complete implementation of fundamental reconnaissance techniques, suitable for:
- **Learning**: Understanding TCP/IP at the packet level
- **Penetration testing**: Initial reconnaissance on authorised targets
- **Security research**: Exploring evasion techniques and fingerprinting accuracy

The modular design allows easy extension with new scan types (e.g., decoy scanning, fragmentation, NULL scans), and the JSON output integrates with downstream analysis pipelines.

---

**Document Version**: 1.0  
**Last Updated**: May 2026  
**Author**: [Lynessa]