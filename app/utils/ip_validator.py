import ipaddress


def is_public_ip(ip):
    """Check if an IP is public (not private or loopback)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback)
    except ValueError:
        return False
