import core.external_components as ext
import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability


def detect_spring_cloud_gateway(microservices: dict, information_flows: dict, external_components: dict, dfd) -> dict:
    """Detetcs Spring Cloud Gateway.
    """

    server = False
    results = fi.search_keywords("spring-cloud-starter-gateway", file_extension=["*.xml","*.gradle"])
    for r in results.values():
        microservice = tech_sw.detect_microservice(r["path"], dfd)
        if microservice:
            for m in microservices.values():
                if m["name"] == microservice:
                    server = microservice
                    m.setdefault("stereotype_instances",[]).append("gateway")
                    m.setdefault("tagged_values",[]).append(("Gateway", "Spring Cloud Gateway"))

                    # Traceability
                    traceability.add_trace({
                        "parent_item": microservice,
                        "item": "gateway",
                        "file": r["path"],
                        "line": r["line_nr"],
                        "span": r["span"]
                    })

    if server:
        # Reverting direction of flow to service registry, if found
        registry_server = False
        for m in microservices.values():
            for s in m["stereotype_instances"]:
                if s == "service_registry":
                    registry_server = m["name"]
                    break
        if registry_server:
            for flow in information_flows.values():
                if flow["sender"] == server and flow["receiver"] == registry_server:
                    flow["sender"] = registry_server
                    flow["receiver"] = server

                    traceability.revert_flow(server, registry_server)

        # Adding user
        external_components = ext.add_user(external_components)

        # Adding connection user to gateway
        information_flows = ext.add_user_connections(information_flows, server)

        # Clients
        for m in microservices.values():
            for prop in m["properties"]:
                target_service = False
                if prop[0] == "spring_cloud_gateway_route":
                    for m2 in microservices.values():
                        if m2["name"] == prop[1]:
                            target_service = prop[1]
                if target_service:
                    key = max(information_flows.keys(), default=-1) + 1
                    information_flows[key] = {
                        "sender": server,
                        "receiver": target_service,
                        "stereotype_instances": ["restful_http"]
                    }
                    
                    traceability.add_trace({
                        "item": f"{server} -> {target_service}",
                        "file": prop[2][0],
                        "line": prop[2][1],
                        "span": prop[2][2]
                    })

    return microservices, information_flows, external_components
