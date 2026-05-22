import argparse

from scanner.syn_scan import syn_scan
from scanner.ack_scan import ack_scan
from scanner.fin_scan import fin_scan
from scanner.xmas_scan import xmas_scan
from scanner.udp_scan import udp_scan
from scanner.ping_sweep import ping_sweep
from scanner.arp_sweep import arp_sweep

from core.utils import *
from core.fingerprint import os_fingerprint
from core.banner import service_detection
from core.output import save_results

def main():

    parser = argparse.ArgumentParser(
        description="Recon Framework"
    )

    parser.add_argument(
        "-t",
        "--target",
        help="Target IP or domain"
    )

    parser.add_argument(
        "-n",
        "--network",
        help="Target network/subnet"
    )

    parser.add_argument(
        "-p",
        "--ports",
        help="Port range or list"
    )

    parser.add_argument(
        "-s",
        "--scan",
        required=True,
        choices=["syn","ack","fin","xmas","udp","os","banner","all","ping","arp"],
            help="Scan type"
    )

    args = parser.parse_args()

    target_scans = [
        "syn",
        "ack",
        "fin",
        "xmas",
        "udp",
        "os",
        "banner",
        "all"
    ]

    network_scans = [
        "ping",
        "arp"
    ]

    if args.scan in target_scans and not args.target:

        parser.error(
            f"{args.scan} scan requires --target"
        )

    if args.scan in network_scans and not args.network:

        parser.error(
            f"{args.scan} scan requires --network"
        )

    if args.scan == "ping":

        live_hosts = ping_sweep(
            args.network
        )

        print("\n[+] Live Hosts:")

        for host in live_hosts:
            print(host)

        return
        
    elif args.scan == "arp":

        arp_sweep(
            args.network
        )

        return

    target = resolve_target(args.target)

    if not target:
        print("[-] Invalid target")
        return

    if args.ports:

        ports = parse_ports(
            args.ports
        )

    else:

        ports = common_port_list()


    if args.scan == "syn":
        syn_scan(target, ports)

    elif args.scan == "ack":
        ack_scan(target, ports)

    elif args.scan == "fin":
        fin_scan(target, ports)

    elif args.scan == "xmas":
        xmas_scan(target, ports)

    elif args.scan == "udp":
        udp_scan(target, ports)

    elif args.scan == "os":
        os_fingerprint(target)

    elif args.scan == "banner":
        service_detection(target, ports)

    elif args.scan == "all":
            
        results = {}

        # SYN Scan
        open_ports = syn_scan(target, ports)

        results["target"] = target
        results["open_ports"] = open_ports

        # Additional Scans
        ack_scan(target, ports)
        fin_scan(target, ports)
        xmas_scan(target, ports)
        udp_scan(target, ports)

        # OS Fingerprinting
        os_results = os_fingerprint(target)

        final_os_guess = os_results["final_guess"]

        confidence = "Low"
            

        results["os_fingerprint"] = os_results

        # Banner Grabbing
        if open_ports:

            service_results = service_detection(
                target,
                open_ports
            )

            banner_os_guess = None

            for port_data in service_results.values():

                version = port_data.get(
                        "version",
                        ""
                    ).lower()

                # Linux indicators
                if (
                    "ubuntu" in version
                    or "debian" in version
                    or "centos" in version
                    or "linux" in version
                ):

                    banner_os_guess = "Linux/Unix"

                # Windows indicators
                elif (
                    "microsoft" in version
                    or "iis" in version
                    or "windows" in version
                ):

                    banner_os_guess = "Windows"

            results["services"] = service_results

            # Correlation Logic
            if (
                banner_os_guess
                and banner_os_guess
                == os_results["ttl_guess"]
            ):

                final_os_guess = banner_os_guess

                confidence = "High"

            elif (
                os_results["final_guess"]
                == "Mixed/Unknown"
                and banner_os_guess
            ):

                final_os_guess = banner_os_guess

                confidence = "Medium"
                
            print("\nCORRELATED OS ANALYSIS")
            print("-" * 40)

            print(
                f"Banner Evidence: "
                f"{banner_os_guess}"
            )

            print(
                f"Final OS Guess: "
                f"{final_os_guess}"
            )

            print(
                f"Confidence: "
                f"{confidence}"
            )
                
            results["correlated_os_guess"] = {

                "banner_guess": banner_os_guess,

                "final_guess": final_os_guess,

                "confidence": confidence
            }
            
            Save everything
            save_results(results)

if __name__ == "__main__":
    main()