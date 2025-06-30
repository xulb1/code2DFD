import output_generators.traceability as traceability


def detect_consul(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects Consul server and clients (service discover, monitoring, configuration).
    """

    # Server
    consul_server = set()
    for value in microservices.values():
        if "consul:" in value["image"]:
            consul_server.add(value["name"])
            value.setdefault("stereotype_instances", []).append("service_discovery")
            value.setdefault("tagged_values", []).append(("Service Discovery", "Consul"))

    # Flows
    if consul_server:
        for m in microservices.values():
            for prop in m["properties"]:
                if prop[0] == "consul_server":
                    for consul in consul_server:
                        if consul == prop[1]:
                            newKey = max(information_flows.keys(), default=-1) + 1
                            
                            information_flows[newKey] = dict()
                            information_flows[newKey]["sender"] = consul
                            information_flows[newKey]["receiver"] = m["name"]
                            information_flows[newKey]["stereotype_instances"] = ["restful_http"]

                            trace = dict()
                            trace["item"] = f"{consul} ->  {m["name"]}"
                            trace["file"] = prop[2][0]
                            trace["line"] = prop[2][1]
                            trace["span"] = prop[2][2]

                            traceability.add_trace(trace)

    return microservices, information_flows
