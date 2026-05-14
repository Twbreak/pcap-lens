import socket


def detect_local_ips() -> set[str]:
    """Best-effort local IPv4 detection for local-host-aware insights."""
    ips = {"127.0.0.1"}

    try:
        hostname = socket.gethostname()
        _name, _aliases, addresses = socket.gethostbyname_ex(hostname)
        ips.update(addresses)
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ips.add(sock.getsockname()[0])
    except OSError:
        pass

    return {ip for ip in ips if ip}
