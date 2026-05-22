from scapy.all import *


def arp_sweep(network):

    print(f"\n[+] Starting ARP Sweep on {network}")

    arp = ARP(
        pdst=network
    )

    ether = Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )

    packet = ether / arp

    result = srp(
        packet,
        timeout=2,
        verbose=0
    )[0]

    live_hosts = []

    for sent, received in result:

        host = {
            "ip": received.psrc,
            "mac": received.hwsrc
        }

        live_hosts.append(host)

        print(
            f"[LIVE] "
            f"IP: {received.psrc} "
            f"MAC: {received.hwsrc}"
        )

    print(
        f"\n[+] Total Hosts Found: "
        f"{len(live_hosts)}"
    )

    return live_hosts