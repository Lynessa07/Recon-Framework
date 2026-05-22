from scapy.all import *


def ttl_analysis(ttl):

    if ttl <= 64:
        return "Linux/Unix"

    elif ttl <= 128:
        return "Windows"

    elif ttl <= 255:
        return "Cisco/Network Device"

    return "Unknown"


def window_analysis(window):

    windows_map = {

        5840: "Linux",
        29200: "Linux",
        64240: "Windows",
        65535: "FreeBSD"
    }

    return windows_map.get(window, "Unknown")


def os_fingerprint(target):

    print(f"\n[+] Starting OS Fingerprinting on {target}")

    packet = IP(dst=target) / TCP(
        dport=80,
        flags="S"
    )

    response = sr1(packet, timeout=2, verbose=0)

    icmp_packet = IP(dst=target) / ICMP()

    icmp_response = sr1(
        icmp_packet,
        timeout=2,
        verbose=0
    )

    if not response:
        print("[-] No response received")
        return

    if response.haslayer(TCP):

        ttl = response.ttl
        window = response[TCP].window

        # TCP Signature Analysis
        options = response[TCP].options

        option_names = [

            option[0]

            for option in options
        ]

        ttl_guess = ttl_analysis(ttl)
        window_guess = window_analysis(window)
        signature_guess = "Unknown"
        
        if "Timestamp" in option_names and "WScale" in option_names:
            signature_guess = "Linux/Unix"
        elif "NOP" in option_names:
            signature_guess = "Windows"

        print("\nTTL ANALYSIS")
        print("-" * 40)

        print(f"TTL Value: {ttl}")
        print(f"Guess: {ttl_guess}")

        print("\nWINDOW ANALYSIS")
        print("-" * 40)

        print(f"Window Size: {window}")
        print(f"Guess: {window_guess}")

        print("\nICMP ANALYSIS")
        print("-" * 40)

        if icmp_response and icmp_response.haslayer(ICMP):

            print(
                f"ICMP Type: "
                f"{icmp_response[ICMP].type}"
            )

            print(
                f"ICMP Code: "
                f"{icmp_response[ICMP].code}"
            )

        else:

            print("[-] ICMP response not received")

        print("\nTCP SIGNATURE ANALYSIS")
        print("-" * 40)

        print("TCP Options:")

        for option in options:

            print(option)

        print(
            f"\nSignature Guess: "
            f"{signature_guess}"
        )

        print("\nFINAL OS GUESS")
        print("-" * 40)

        # Confidence logic
        if (
            ttl_guess == window_guess
            or ttl_guess == signature_guess
        ):

            final_guess = ttl_guess

        else:

            final_guess = "Mixed/Unknown"

        print(f"Likely OS: {final_guess}")

        return {

            "ttl": ttl,
            "window_size": window,

            "ttl_guess": ttl_guess,
            "window_guess": window_guess,

            "signature_guess": signature_guess,

            "tcp_options": options,

            "final_guess": final_guess
        }
