
def detect_ssl_services(microservices: dict) -> dict:
    """Checks if services have ssl enabled.
    """

    for m in microservices.values():
        for prop in m["properties"]:
            if prop[0] == "ssl_enabled":
                m.setdefault("stereotype_instances",[]).append(
                    "ssl_enabled" if bool(prop[1]) else "ssl_disabled"
                )
            elif prop[0] == "ssl_protocol":
                m.setdefault("tagged_values",[]).append(("SSL Protocol", prop[1]))

    return microservices
