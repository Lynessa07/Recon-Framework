from scapy.all import *
from core.evasion import *
from core.utils import get_service_name


def xmas_scan(target, ports):

    print(f"\n[+] Starting Xmas Scan on {target}")

    print(
    f"\n{'PORT':<10}"
    f"{'STATE':<22}"
    f"{'SERVICE':<15}"
    )

    print("-" * 40)

    for port in ports:

        random_delay()

        service = get_service_name(port)

        packet = IP(
            dst=target,
            ttl=random_ttl()
        ) / TCP(
            sport=spoofed_source_port(),
            dport=port,
            flags="S"
        )

        response = sr1(packet, timeout=1, verbose=0)

        if response:

            if response.haslayer(TCP):

                if response[TCP].flags == 0x14:
                    print(
                        f"{str(port) + '/tcp':<10}"
                        f"{'CLOSED':<22}"
                        f"{service:<15}"
                    )

        else:
            print(
                f"{str(port) + '/tcp':<10}"
                f"{'OPEN|FILTERED':<22}"
                f"{service:<15}"
            )