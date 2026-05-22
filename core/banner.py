import socket


def grab_banner(target, port):

    try:

        s = socket.socket()

        s.settimeout(2)

        s.connect((target, port))

        # HTTP-specific request
        if port == 80 or port == 8080:

            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n\r\n"
            )

            s.send(request.encode())

        banner = s.recv(4096).decode(
            errors="ignore"
        )

        banner = banner.split("\r\n\r\n")[0]

        s.close()

        return banner.strip()

    except:
        return None


def analyze_banner(port, banner):

    if not banner:
        return "Unknown Service"

    banner_lower = banner.lower()

    # HTTP FIRST
    if "http/" in banner_lower:

        if "apache" in banner_lower:
            return "Apache Web Server"

        elif "nginx" in banner_lower:
            return "Nginx Web Server"

        elif "iis" in banner_lower:
            return "Microsoft IIS"

        return "HTTP Service"

    # SSH
    elif banner_lower.startswith("ssh"):
        return "SSH Server"

    # FTP
    elif "ftp" in banner_lower:
        return "FTP Server"

    # SMTP
    elif "smtp" in banner_lower:
        return "SMTP Service"

    return "Unknown Service"

def service_detection(target, ports):

    print(f"\n[+] Starting Banner Grabbing on {target}")

    print(
        f"\n{'PORT':<10}"
        f"{'SERVICE':<20}"
        f"{'VERSION':<35}"
    )

    print("-" * 70)

    results = {}

    for port in ports:

        banner = grab_banner(target, port)

        if banner:

            service = analyze_banner(
                port,
                banner
            )

            version = "Unknown"

            # Extract Apache/Nginx/IIS version
            if "Server:" in banner:

                for line in banner.splitlines():

                    if line.lower().startswith("server:"):

                        version = (
                            line.replace(
                                "Server:",
                                ""
                            ).strip()
                        )

            # Extract SSH version
            elif banner.startswith("SSH"):

                version = banner.strip()

            print(
                f"{str(port) + '/tcp':<10}"
                f"{service:<20}"
                f"{version:<35}"
            )

            results[port] = {

                "service": service,
                "version": version,
                "banner": banner[:300]

            }

    return results