import output_generators.traceability as traceability


def detect_zipkin_server(microservices: dict, information_flows: dict, iterative=False) -> dict:
    """Detects zipkin server and connections to it.
    """

    zipkin_server_exists, connections_exist = False, False

    for m in microservices:
        circuit_breaker, load_balancer = False, False
        tagged_values, load_balancer, circuit_breaker = False, False, False

        for prop2 in microservices[m]["properties"]:
            if prop2[0] == "load_balancer":
                load_balancer = prop2[1]
            elif prop2[0] == "circuit_breaker":
                circuit_breaker = prop2[1]

        # if load_balancer:
        #     load_balancer = True
        #     try:
        #         tagged_values.add(("Load Balancer", load_balancer))
        #     except Exception:
        #         tagged_values = {("Load Balancer", load_balancer)}

        # if circuit_breaker:
        #     circuit_breaker = True
        #     try:
        #         tagged_values.add(("Circuit Breaker", circuit_breaker))
        #     except Exception:
        #         tagged_values = {("Circuit Breaker", circuit_breaker)}

        zipkin_server = False
        for prop in microservices[m]["properties"]:
            if prop[0] == "zipkin_url":
                connections_exist = prop[1]
                zipkin_url = prop[1]
                parts = zipkin_url.split("/")
                for m2 in microservices.keys():
                    for part in parts:
                        if part.split(":")[0] == microservices[m2]["name"]:
                            zipkin_server = microservices[m2]["name"]
                        if not zipkin_server \
                            and ":" in part  \
                            and part.split(":")[1] in [b for (a, b, c) in microservices[m2]["properties"] if (a == "port")]:
                                zipkin_server = microservices[m2]["name"]
                        if zipkin_server:
                            correct_id = m2
                            
                            key = max(information_flows.keys(), default=-1) + 1
                            information_flows[key] = {
                                "sender": microservices[m]["name"],
                                "receiver": zipkin_server,
                                "stereotype_instances": ["restful_http"]
                            }
                            # if tagged_values:
                            #     information_flows[key]["tagged_values"] = tagged_values
                            if circuit_breaker:
                                information_flows[key]["stereotype_instances"].append("circuit_breaker_link")
                            if load_balancer:
                                information_flows[key]["stereotype_instances"].append("load_balanced_link")

                            traceability.add_trace({
                                "item": f"{microservices[m]["name"]} -> {zipkin_server}",
                                "file": prop[2][0],
                                "line": prop[2][1],
                                "span": prop[2][2]
                            })


        # Si pas de server zipkin : 
        if not zipkin_server and "openzipkin/zipkin" in microservices[m]["image"]:
            zipkin_server = microservices[m]["name"]
            correct_id = m
        
        if zipkin_server:
            zipkin_server_exists = True
            microservices[correct_id].setdefault("stereotype_instances",[]).append("tracing_server")
            microservices[correct_id].setdefault("tagged_values",[]).append(("Tracing Server", "Zipkin"))
            # TODO: verify usefullness of break
            break

    if not zipkin_server_exists and connections_exist:
        if "http:" in connections_exist:
            port = connections_exist.split("http:")[1]
            if ":" in port:
                port = port.split(":")[1].strip("/ ")
        
        key = max(microservices.keys(), default=-1) + 1
        microservices[key] = {
            "name": "zipkin-server",
            "image": "placeholder_image",
            "properties": [("port", port, ("file", "line", "span"))],
            "stereotype_instances": ["tracing_server"],
            "tagged_values": [("Tracing Server", "Zipkin")]
        }


        if not iterative:
            microservices, information_flows = detect_zipkin_server(microservices, information_flows, True)

    return microservices, information_flows
