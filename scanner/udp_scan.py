from scapy.all import *
from core.evasion import *
from core.utils import get_service_name


def udp_scan(target, ports):

    print(f"\n[+] Starting UDP Scan on {target}")

    print(
        f"\n{'PORT':<10}"
        f"{'STATE':<22}"
        f"{'SERVICE':<15}"
    )

    print("-" * 50)

    for port in ports:

        random_delay()

        service = get_service_name(port)

        packet = IP(
            dst=target,
            ttl=random_ttl()
        ) / UDP(
            dport=port
        )

        response = sr1(
            packet,
            timeout=2,
            verbose=0
        )

        # No response = Open|Filtered
        if response is None:

            print(
                f"{str(port) + '/udp':<10}"
                f"{'OPEN|FILTERED':<22}"
                f"{service:<15}"
            )

        # ICMP unreachable = Closed
        elif response.haslayer(ICMP):

            icmp_layer = response.getlayer(ICMP)

            if (
                int(icmp_layer.type) == 3
                and int(icmp_layer.code) == 3
            ):

                print(
                    f"{str(port) + '/udp':<10}"
                    f"{'CLOSED':<22}"
                    f"{service:<15}"
                )

        # UDP response = Open
        else:

            print(
                f"{str(port) + '/udp':<10}"
                f"{'OPEN':<22}"
                f"{service:<15}"
            )