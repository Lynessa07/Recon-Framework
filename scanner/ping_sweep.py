from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import ipaddress


def ping_host(ip):

    packet = IP(dst=str(ip)) / ICMP()

    response = sr1(
        packet,
        timeout=1,
        verbose=0
    )

    if response:

        print(f"[LIVE] {ip}")

        return str(ip)

    return None


def ping_sweep(network):

    print(f"\n[+] Starting Ping Sweep on {network}")

    live_hosts = []

    try:

        net = ipaddress.ip_network(
            network,
            strict=False
        )

    except ValueError:

        print("[-] Invalid network range")

        return []

    with ThreadPoolExecutor(max_workers=100) as executor:

        futures = [

            executor.submit(
                ping_host,
                ip
            )

            for ip in net.hosts()
        ]

        for future in futures:

            result = future.result()

            if result:
                live_hosts.append(result)

    print(
        f"\n[+] Total Live Hosts: "
        f"{len(live_hosts)}"
    )

    return live_hosts