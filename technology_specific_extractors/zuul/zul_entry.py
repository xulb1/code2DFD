import core.external_components as ext
import core.file_interaction as fi
import core.technology_switch as tech_sw
import tmp.tmp as tmp
import output_generators.traceability as traceability


def detect_zuul(microservices: dict, information_flows: dict, external_components: dict, dfd) -> dict:
    """Detects Zuul gateway if there is one.
    """

    # Server (/microservice classification)
    results = fi.search_keywords("@EnableZuulServer")
    new_results = fi.search_keywords("@EnableZuulProxy")

    for r in new_results.keys():
        key = max(results.keys(), default=-1) + 1
        results[key] = dict()
        results[key] = new_results[r]
    
    zuul_server = str()
    for r in results.keys():
        zuul_server = tech_sw.detect_microservice(results[r]["path"], dfd)
        for m in microservices.values():
            if m["name"] == zuul_server:    # this is the Zuul server
                # FIXME: insertion un peu étrange
                m["stereotype_instances"] = m.get("stereotype_instances", []) + ["gateway", "load_balancer"]
                m["tagged_values"] = m.get("tagged_values", []) + [("Gateway", "Zuul"), ("Load Balancer", "Ribbon")]

                # Traceability
                traceability.add_trace({
                    "parent_item": zuul_server,
                    "item": "gateway",
                    "file": results[r]["path"],
                    "line": results[r]["line_nr"],
                    "span": results[r]["span"]
                })

                # Reverting direction of flow to service discovery, if found
                discovery_server = False
                for m2 in microservices.values():
                    for s in m2["stereotype_instances"]:
                        if s == "service_discovery":
                            discovery_server = m2["name"]
                            break
                if discovery_server:
                    traceability.revert_flow(zuul_server, discovery_server)
                    for flow in information_flows.values():
                        if flow["sender"] == zuul_server and flow["receiver"] == discovery_server:
                            flow["sender"] = discovery_server
                            flow["receiver"] = zuul_server

                # Adding user
                external_components = ext.add_user(external_components)

                # Adding connection user to gateway
                information_flows = ext.add_user_connections(information_flows, zuul_server)

                # Adding flows to other services if routes are in config
                load_balancer = False
                circuit_breaker = False
                for prop in m["properties"]:
                    if prop[0] == "load_balancer":
                        load_balancer = prop[1]
                    elif prop[0] == "circuit_breaker":
                        circuit_breaker = prop[1]
                for prop in m["properties"]:
                    if prop[0] in ["zuul_route", "zuul_route_serviceId", "zuul_route_url"]:
                        receiver = False
                        if prop[0] in ["zuul_route","zuul_route_serviceId"]:
                            for m2 in microservices.values():
                                for part in prop[1].split("/"):
                                    if m2["name"] in part.casefold():
                                        receiver = m2["name"]
                        else:
                            for m2 in microservices.values():
                                for part in prop[1].split("://"):
                                    if m2["name"] in part.split(":")[0].casefold():
                                        receiver = m2["name"]
                        if receiver:
                            key = max(information_flows.keys(), default=-1) + 1
                            information_flows[key] = {
                                "sender": zuul_server,
                                "receiver": receiver,
                                "stereotype_instances": ["restful_http"]
                            }

                            traceability.add_trace({
                                "item": f"{zuul_server} -> {receiver}",
                                "file": prop[2][0],
                                "line": prop[2][1],
                                "span": prop[2][2]
                            })

                            if circuit_breaker:
                                information_flows[key]["stereotype_instances"].append("circuit_breaker_link")
                                information_flows[key].setdefault("tagged_values",[]).append(("Circuit Breaker", circuit_breaker))
                            if load_balancer:
                                information_flows[key]["stereotype_instances"].append("load_balanced_link")
                                information_flows[key].setdefault("tagged_values",[]).append(("Load Balancer", load_balancer))

    tmp.tmp_config.set("DFD", "external_components", str(external_components).replace("%", "%%"))
    return microservices, information_flows, external_components
