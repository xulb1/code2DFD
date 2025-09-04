import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability


def detect_spring_admin_server(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects Spring Admin Servers.
    """

    results = fi.search_keywords("@EnableAdminServer", file_extension=["*.java", "*.kt"])
    admin_server = False
    for r in results.values():
        admin_server = tech_sw.detect_microservice(r["path"], dfd)
        for m in microservices.values():
            if m["name"] == admin_server:
                m.setdefault("stereotype_instances",[]).append("administration_server")
                m.setdefault("tagged_values",[]).append(("Administration Server", "Spring Boot Admin"))
                
                admin_server = m["name"]

                # Traceability
                traceability.add_trace({
                    "parent_item": admin_server,
                    "item": "administration_server",
                    "file": r["path"],
                    "line": r["line_nr"],
                    "span": r["span"]
                })


    for m in microservices.values():
        host = False
        reverse = False
        config_reverse = False
        for prop in m["properties"]:
            if prop[0] == "admin_server_url":
                trace_info = dict()
                trace_info[0] = prop[2][0]
                trace_info[1] = prop[2][1]
                trace_info[2] = prop[2][2]
                if "://" in prop[1]:
                    host = prop[1].split("://")[1].split(":")[0]
        if "stereotype_instances" in m and "service_registry" in m["stereotype_instances"]:
            reverse = True
        if "stereotype_instances" in m and "configuration_server" in m["stereotype_instances"]:
            config_reverse = True
        if host and host == admin_server:
            if reverse: # flow admin -> service-registry
                information_flows = ensure_flow_server_to_service(True ,admin_server, trace_info, m, information_flows)
            elif config_reverse:
                information_flows = ensure_flow_server_to_service(False,admin_server, trace_info, m, information_flows)
            else:
                key = max(information_flows.keys(), default=-1) + 1
                information_flows[key] = {
                    "sender": admin_server,
                    "receiver": m["name"],
                    "stereotype_instances": ["restful_http"]
                }
                traceability.add_trace({
                    "item": f"{admin_server} -> {m["name"]}",
                    "file": trace_info[0],
                    "line": trace_info[1],
                    "span": trace_info[2]
                })


    return microservices, information_flows


def ensure_flow_server_to_service(reverse, admin_server, trace_info, microservice: dict, information_flows: dict)-> dict:
    """Ensures an information flow exists from the admin server to the microservice or vice versa.

    If a matching flow exists, its direction is reversed. Otherwise, a new flow is created in the desired direction and the change is traced.
    """

    if reverse : 
        sender = admin_server
        receiver = microservice["name"]
    else:
        sender = microservice["name"]
        receiver = admin_server
    
    found = False
    for flow in information_flows.values():
        if flow["sender"] == sender and flow["receiver"] == receiver:
            found = True
            flow["sender"] = receiver
            flow["receiver"] = sender

            traceability.add_trace({
                "item": f"{receiver} -> {sender}",
                "file": trace_info[0],
                "line": trace_info[1],
                "span": trace_info[2]
            })

    if not found:
        key = max(information_flows.keys(), default=-1) + 1
        information_flows[key] = {
            "sender": receiver,
            "receiver": sender,
            "stereotype_instances": ["restful_http"]
        }

        traceability.add_trace({
            "item": f"{receiver} -> {sender}",
            "file": trace_info[0],
            "line": trace_info[1],
            "span": trace_info[2]
        })
        
    return information_flows