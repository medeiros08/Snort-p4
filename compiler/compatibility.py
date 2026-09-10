import ipaddress


SUPPORTED_PROTOCOLS = {
    "ip",
    "tcp",
    "udp",
    "icmp"
}


def analyze_protocol(value):
    value = str(value).lower()

    if value in SUPPORTED_PROTOCOLS:
        return {
            "supported": True,
            "restrictive": False,
            "reason": "supported protocol"
        }

    return {
        "supported": False,
        "restrictive": False,
        "reason": "protocol outside initial target profile"
    }


def analyze_ip(value):
    if isinstance(value, list):
        if not value:
            return {
                "supported": False,
                "restrictive": False,
                "reason": "empty address list"
            }

        for item in value:
            result = analyze_ip(item)

            if not result["supported"]:
                return {
                    "supported": False,
                    "restrictive": False,
                    "reason": "address list contains unsupported expression"
                }

        return {
            "supported": True,
            "restrictive": True,
            "reason": "address list supported"
        }

    value = str(value).strip()

    if value.lower() == "any":
        return {
            "supported": True,
            "restrictive": False,
            "reason": "wildcard address"
        }

    if value.startswith("$"):
        return {
            "supported": False,
            "restrictive": False,
            "reason": "Snort variable not resolved"
        }

    if value.startswith("!"):
        return {
            "supported": False,
            "restrictive": False,
            "reason": "negated address unsupported by initial prototype"
        }

    if value.startswith("[") or value.endswith("]"):
        return {
            "supported": False,
            "restrictive": False,
            "reason": "textual address list unsupported before resolution"
        }

    try:
        network = ipaddress.ip_network(
            value,
            strict=False
        )

        if network.version != 4:
            return {
                "supported": False,
                "restrictive": False,
                "reason": "only IPv4 is supported by initial target profile"
            }

        return {
            "supported": True,
            "restrictive": True,
            "reason": "IPv4 address/subnet supported"
        }

    except ValueError:
        return {
            "supported": False,
            "restrictive": False,
            "reason": "address expression not recognized"
        }


def analyze_single_port(value):
    value = str(value).strip()

    if value.lower() == "any":
        return {
            "supported": True,
            "restrictive": False,
            "reason": "wildcard port"
        }

    if value.startswith("$"):
        return {
            "supported": False,
            "restrictive": False,
            "reason": "Snort port variable not resolved"
        }

    if value.startswith("!"):
        return {
            "supported": False,
            "restrictive": False,
            "reason": "negated port unsupported by initial prototype"
        }

    if ":" in value:
        return {
            "supported": False,
            "restrictive": False,
            "reason": "port range unsupported by initial prototype"
        }

    try:
        port = int(value)

        if 0 <= port <= 65535:
            return {
                "supported": True,
                "restrictive": True,
                "reason": "numeric port supported"
            }

    except ValueError:
        pass

    return {
        "supported": False,
        "restrictive": False,
        "reason": "port expression not recognized"
    }


def analyze_port(value):
    if isinstance(value, list):
        if not value:
            return {
                "supported": False,
                "restrictive": False,
                "reason": "empty port list"
            }

        for item in value:
            result = analyze_single_port(item)

            if not result["supported"]:
                return {
                    "supported": False,
                    "restrictive": False,
                    "reason": "port list contains unsupported expression"
                }

        return {
            "supported": True,
            "restrictive": True,
            "reason": "numeric port list supported"
        }

    return analyze_single_port(value)


def analyze_direction(value):
    if value == "->":
        return {
            "supported": True,
            "restrictive": False,
            "reason": "forward direction supported"
        }

    return {
        "supported": False,
        "restrictive": False,
        "reason": "direction unsupported by initial prototype"
    }


def analyze_header(rule):
    return {
        "protocol": analyze_protocol(
            rule["protocol"]
        ),
        "src_ip": analyze_ip(
            rule["source"]["address"]
        ),
        "src_port": analyze_port(
            rule["source"]["port"]
        ),
        "direction": analyze_direction(
            rule["direction"]
        ),
        "dst_ip": analyze_ip(
            rule["destination"]["address"]
        ),
        "dst_port": analyze_port(
            rule["destination"]["port"]
        )
    }