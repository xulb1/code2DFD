import output_generators.traceability as traceability


def detect_logstash(microservices: dict, information_flows: dict, external_components: dict, dfd) -> dict:
    """Detects logstash services.
    """

    # Service
    logstash = False
    trace_info = False
    for m in microservices.values():
        if "logstash:" in m["image"]:
            logstash = m["name"]
            m.setdefault("stereotype_instances",[]).append("logging_server")
            m.setdefault("tagged_values",[]).append(("Logging Server", "Logstash"))

    if not logstash:
        for m in microservices.values():
            if "properties" in m:
                for prop in m["properties"]:
                    if prop[0] == "logstash_server":
                        trace_info = dict()
                        trace_info[0] = prop[2][0]
                        trace_info[1] = prop[2][1]
                        trace_info[2] = prop[2][2]

                        logstash_server = prop[1].strip().strip("-").strip()
                        if ":" in logstash_server:
                            # internal via name
                            logstash_host = logstash_server.split(":")[0]
                            for mi in microservices.values():
                                if logstash_host == mi["name"]:
                                    logstash = mi["name"]
                                    mi.setdefault("stereotype_instances",[]).append("logging_server")
                                    mi.setdefault("tagged_values",[]).append(("Logging Server", "Logstash"))

                            # internal via port
                            if not logstash:
                                logstash_port = int(logstash_server.split(":")[1].strip())
                                print("logstash_port: ",logstash_port,int(logstash_server.split(":")[1].strip().strip("")))
                                
                                for mi in microservices.values():
                                    for prop2 in mi["properties"]:
                                        if prop2[0] == "Port" and int(prop2[1]) == logstash_port:
                                            logstash = mi["name"]
                                            mi.setdefault("stereotype_instances",[]).append("logging_server")
                                            mi.setdefault("tagged_values",[]).append(("Logging Server", "Logstash"))

                            # external
                            if not logstash:
                                logstash_port = int(logstash_server.split(":")[1].strip())
                                print("logstash_port",logstash_port, int(logstash_server.split(":")[1].strip().strip("")))

                                key = max(external_components.keys(), default=-1) + 1

                                external_components[key] = {
                                    "name": "logstash",
                                    "type": "external_component",
                                    "stereotype_instances": ["logging_server", "exitpoint"],
                                    "tagged_values": [("Logging Server", "Logstash"), ("Port", logstash_port)]
                                }

                                traceability.add_trace({
                                    "item": "logstash",
                                    "file": trace_info[0],
                                    "line": trace_info[1],
                                    "span": trace_info[2]
                                })

                                key = max(information_flows.keys(), default=-1) + 1
                                information_flows[key] = {
                                    "sender": m["name"],
                                    "receiver": "logstash",
                                    "stereotype_instances": ["restful_http"]
                                }

                                traceability.add_trace({
                                    "item": f"{m['name']} -> {logstash}",
                                    "file": trace_info[0],
                                    "line": trace_info[1],
                                    "span": trace_info[2]
                                })



        # Flow to elasticsearch
    if logstash:
        if trace_info:
            traceability.add_trace({
                "item": logstash,
                "file": trace_info[0],
                "line": trace_info[1],
                "span": trace_info[2]
            })

        elasticsearch = False
        for m in microservices.values():
            if ("Search Engine", "Elasticsearch") in m["tagged_values"]:
                elasticsearch = m["name"]
        if elasticsearch:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": logstash,
                "receiver": elasticsearch,
                "stereotype_instances": ["restful_http"]
            }
            
            traceability.add_trace({
                "item": f"{logstash} -> {elasticsearch}",
                "file": "implicit",
                "line": "implicit",
                "span": "implicit"
            })

        # Flow from services
        for m in microservices.values():
            for prop in m["properties"]:
                if (prop[0] == "logstash_server")  and  (logstash in prop[1]):
                    key = max(information_flows.keys(), default=-1) + 1
                    information_flows[key] = {
                        "sender": m["name"],
                        "receiver": logstash,
                        "stereotype_instances": ["restful_http"]
                    }

                    traceability.add_trace({
                        "item": m["name"] + " -> " + logstash,
                        "file": prop[2][0],
                        "line": prop[2][1],
                        "span": prop[2][2]
                    })


    return microservices, information_flows, external_components
