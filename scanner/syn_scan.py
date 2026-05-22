from scapy.all import *
from core.evasion import *
from core.utils import get_service_name

def syn_scan(target, ports):

    open_ports = []

    print(f"\n[+] Starting SYN Scan on {target}")

    print(
    f"\n{'PORT':<10}"
    f"{'STATE':<22}"
    f"{'SERVICE':<15}"
    )

    print("-" * 40)

    for port in ports:

        random_delay()

        packet = IP(
            dst=target,
            ttl=random_ttl()
        ) / TCP(
            sport=spoofed_source_port(),
            dport=port,
            flags="S"
        )

        response = sr1(
            packet,
            timeout=1,
            verbose=0
        )

        if response:

            if response.haslayer(TCP):

                # SYN-ACK = Open
                if response[TCP].flags == 0x12:

                    open_ports.append(port)

                    service = get_service_name(port)

                    print(
                        f"{str(port) + '/tcp':<10}"
                        f"{'OPEN':<22}"
                        f"{service:<15}"
                    )

                    # Send RST to avoid full connection
                    send(
                        IP(dst=target) /
                        TCP(
                             sport=response[TCP].dport,
                             dport=response[TCP].sport,
                             flags="R",
                             seq=response[TCP].ack
                        ),
                        verbose=0
                        )
                    

                # RST-ACK = Closed
                elif response[TCP].flags == 0x14:

                    service = get_service_name(port)

                    print(
                        f"{str(port) + '/tcp':<10}"
                        f"{'CLOSED':<22}"
                        f"{service:<15}"
                    )

        else:
            service = get_service_name(port)

            print(
                f"{str(port) + '/tcp':<10}"
                f"{'FILTERED/NO-RESPONSE':<22}"
                f"{service:<15}"
            )

    return open_ports

        