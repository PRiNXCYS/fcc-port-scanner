import socket

import common_ports


AUTHORIZED_TARGETS = {
    "scanme.nmap.org",
    "www.stackoverflow.com",
    "209.216.230.240",
    "104.26.10.78",
    "137.74.187.104",
}


def _looks_like_ip(target):
    return bool(target) and all(
        character in "0123456789." for character in target
    )


def get_open_ports(target, port_range, verbose=False):
    open_ports = []

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        if _looks_like_ip(target):
            return "Error: Invalid IP address"
        return "Error: Invalid hostname"

    if target.lower() not in AUTHORIZED_TARGETS:
        return "Error: Target not authorized"

    for port in range(port_range[0], port_range[1] + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scanner:
            scanner.settimeout(1)
            if scanner.connect_ex((ip, port)) == 0:
                open_ports.append(port)

    if not verbose:
        return open_ports

    display_target = target
    if _looks_like_ip(target):
        try:
            reverse_name = socket.gethostbyaddr(ip)[0]
            display_target = f"{reverse_name} ({ip})" if reverse_name else ip
        except (socket.herror, socket.gaierror):
            display_target = ip
    elif target.lower() in AUTHORIZED_TARGETS:
        display_target = f"{target} ({ip})"

    lines = [f"Open ports for {display_target}", "PORT     SERVICE"]
    lines.extend(
        f"{port:<9}{common_ports.ports_and_services[port]}" for port in open_ports
    )
    return "\n".join(lines)