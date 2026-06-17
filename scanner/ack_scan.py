from scapy.all import *
from core.evasion import *
from core.utils import get_service_name

def ack_scan(target, ports):

    print(f"\n[+] Starting ACK Scan on {target}")

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
            flags="A"
        )

        response = sr1(packet, timeout=1, verbose=0)

        service = get_service_name(port)

        if response:

            if response.haslayer(TCP):

                if response[TCP].flags == 0x4:
                    print(
                        f"{str(port) + '/tcp':<10}"
                        f"{'UNFILTERED':<22}"
                        f"{service:<15}"
                    )

        else:
            print(
                f"{str(port) + '/tcp':<10}"
                f"{'FILTERED':<22}"
                f"{service:<15}"
            )