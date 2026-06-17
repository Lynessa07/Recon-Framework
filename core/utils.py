from scapy.all import *
import socket


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def common_port_list():
    return [
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        25,   # SMTP
        53,   # DNS
        80,   # HTTP
        110,  # POP3
        135,  # RPC
        139,  # NetBIOS
        143,  # IMAP
        443,  # HTTPS
        445,  # SMB
        3306, # MySQL
        3389  # RDP
    ]

def parse_ports(port_input):

    ports = []

    if "-" in port_input:

        start, end = port_input.split("-")

        ports = list(
            range(
                int(start),
                int(end) + 1
            )
        )

    elif "," in port_input:

        ports = [
            int(port.strip())
            for port in port_input.split(",")
        ]

    else:

        ports = [int(port_input)]

    return ports

def get_service_name(port):

    services = {

        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        135: "MSRPC",
        139: "NETBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MYSQL",
        3389: "RDP"

    }

    return services.get(
        port,
        "UNKNOWN"
    )