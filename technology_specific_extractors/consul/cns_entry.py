import output_generators.traceability as traceability
import core.technology_switch as tech_sw
import core.file_interaction as fi

def detect_consul(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detect Consul servers and clients (service discovery, monitoring, configuration)."""

    SERVER_KEYWORDS = [
        "spring-cloud-starter-consul-server",
        "consul:"
    ]
    CLIENT_KEYWORDS = [
        # "@EnableDiscoveryClient", # -> motclé attribué à eureka donc pourrait créer des doublons
        "spring-cloud-starter-consul-discovery",
        "spring.cloud.consul.host",
        "spring.cloud.consul.port"
    ]

    consul_servers = set()

    # --- Detect servers via image + dependencies + imports ---
    for m in microservices.values():
        # Docker & Maven/Gradle detection
        for keyword in SERVER_KEYWORDS:
            results = fi.search_keywords(keyword, file_extension=["*.conf","*.properties","*.xml","*.gradle","*.sh","*.json","*.yml","*.yaml"])
            for r, res in results.items():
                
                if (keyword=="consul:" and "docker" not in res['name'])\
                    or ( len(res["path"].split("/"))>1 and "xml" in res["name"]):
                    continue

                service_name = tech_sw.detect_microservice(res["path"], dfd)
                if service_name == m["name"]:
                    consul_servers.add(service_name)
                    m.setdefault("stereotype_instances", []).append("service_registry")
                    m.setdefault("tagged_values", []).append(("Service Registry", "Consul"))
                    traceability.add_trace({
                        "parent_item": service_name,
                        "item": "service_registry",
                        "file": res["path"],
                        "line": res["line_nr"],
                        "span": res["span"]
                    })

    if not consul_servers:
        return microservices, information_flows

    # --- Detect clients via annotations, imports, config ---
    participants = set()
    for keyword in CLIENT_KEYWORDS:
        results = fi.search_keywords(keyword, file_extension=["*.xml","*.gradle","*.sh","*.json","*.yml","*.yaml", "*.properties","*.conf"])
        for r, res in results.items():
            service_name = tech_sw.detect_microservice(res["path"], dfd)
            participants.add((service_name, res["path"], res["line_nr"], res["span"]))

    # --- Add flows from clients to servers ---
    if information_flows is None:
        information_flows = dict()

    for participant_name, file_path, line_nr, span in participants:
        for server_name in consul_servers:
            if participant_name != server_name:
                flow_id = max(information_flows.keys(), default=-1) + 1
                information_flows[flow_id] = {
                    "sender": participant_name,
                    "receiver": server_name,
                    "stereotype_instances": ["restful_http"]
                }
                traceability.add_trace({
                    "item": f"{participant_name} -> {server_name}",
                    "file": file_path,
                    "line": line_nr,
                    "span": span
                })

    return microservices, information_flows
