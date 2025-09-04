import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability

# --- Keywords pour Eureka (annotations, imports et config) ---
SERVER_KEYWORDS = [
    "@EnableEurekaServer",
    "spring-cloud-starter-netflix-eureka-server",
    "eureka:",
    "eureka.server"
]
CLIENT_KEYWORDS = [
    "@EnableEurekaClient",
    "@EnableDiscoveryClient",
    "spring-cloud-starter-netflix-eureka-client",
    "eureka.client.serviceUrl.defaultZone",
    "eureka.instance",
    "eureka.client"
]

def detect_eureka(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects Eureka servers and clients using annotations, imports, dependencies, and YAML keywords."""
    eureka_servers = set()

    # --- Detect servers via annotations / imports / dependencies ---
    for keyword in SERVER_KEYWORDS:
        # print("\n\n================================================================================================")
        results = fi.search_keywords(keyword, file_extension=["*.java", "*.kt","*.conf","*.sh","*.xml","*.gradle","*.json","*.yml","*.yaml","*.properties"])
        for res in results.values():
            if (keyword=="eureka:" and "docker" not in res['name'])\
                or (len(res["path"].split("/"))>1 and any(ext in res["name"] for ext in ["yml","xml"])):
                    continue
            if all(keyword not in r for r in res["content"]):
                continue
            if any(any((word in r and keyword in r) for word in ["defaultZone","ENTRYPOINT"]) for r in res["content"]):
                continue
            
            server_name = tech_sw.detect_microservice(res["path"], dfd)
            eureka_servers.add(server_name)
            serverFound = False
            
            # Ajouter stéréotype et tagged values
            for m in microservices.values():
                if m["name"] == server_name:
                    m.setdefault("stereotype_instances", []).append("service_registry")
                    m.setdefault("tagged_values", []).append(("Service Registry", "Eureka"))
                    # print(m["name"],"rrrr<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< afjsaklmf")
                    # print(keyword,res["path"])
                    # Traceability
                    traceability.add_trace({
                        "parent_item": server_name,
                        "item": "service_registry",
                        "file": res["path"],
                        "line": res["line_nr"],
                        "span": res["span"]
                    })
                    serverFound = True
            if not serverFound:
                print("\033[91m Il existe un server Eureka, mais le microservice associé n'a pas été trouvé -------\033[0m")
                
    # print("eurekaservers",eureka_servers)
    if not eureka_servers:
        return microservices, information_flows

    # --- Detect clients via annotations / dependencies / config ---
    client_results = set()
    for keyword in CLIENT_KEYWORDS:
        results = fi.search_keywords(keyword, file_extension=["*.java", "*.kt","*.conf","*.sh","*.xml","*.gradle","*.json","*.yml","*.yaml","*.properties"])
        for r, res in results.items():
            client_results.add((res["path"], res["line_nr"], res["span"]))

    participants = set()
    for file_path, line_nr, span in client_results:
        service_name = tech_sw.detect_microservice(file_path, dfd)
        for m in microservices.values():
            if m["name"] == service_name:
                participants.add((service_name, file_path, line_nr, span))

    # --- Ajouter les participants signalés via propriété custom ---
    for m in microservices.values():
        for prop in m.get("properties", []):
            if prop[0] == "eureka_connected" and m["name"] not in [p[0] for p in participants]:
                participants.add((m["name"], prop[2][0], prop[2][1], prop[2][2]))

    # --- Ajouter les flows des clients vers les serveurs Eureka ---
    if information_flows is None:
        information_flows = dict()

    for participant in participants:
        participant_name, file_path, line_nr, span = participant
        for server_name in eureka_servers:
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


def detect_eureka_v0(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detect Eureka servers and clients, enrich microservices and flows."""
    
    # --- Detect Eureka servers ---
    server_results = fi.search_keywords("@EnableEurekaServer", file_extension=["*.java", "*.kt"])
    eureka_servers = []

    for result in server_results.values():
        server_name = tech_sw.detect_microservice(result["path"], dfd)
        eureka_servers.append(server_name)

        # Add stereotype and tagged values
        for m in microservices.values():
            if m["name"] == server_name:
                m.setdefault("stereotype_instances", []).append("service_registry")
                m.setdefault("tagged_values", []).append(("Service Registry", "Eureka"))

                # Traceability
                traceability.add_trace({
                    "parent_item": server_name,
                    "item": "service_registry",
                    "file": result["path"],
                    "line": result["line_nr"],
                    "span": result["span"]
                })

    if not eureka_servers:
        return microservices, information_flows

    # --- Detect Eureka clients ---
    result_paths = set()
    results = fi.search_keywords(["@EnableEurekaClient","@EnableDiscoveryClient"], file_extension=["*.java", "*.kt"])
    for res in results.values():
        result_paths.add((res["path"], res["line_nr"], res["span"]))
    
    results = fi.search_keywords("spring-cloud-starter-netflix-eureka-client", file_extension=["*.conf","*.xml","*.gradle","*.json","*.yml","*.yaml","*.properties"])
    for res in results.values():
        result_paths.add((res["path"], res["line_nr"], res["span"]))

    if information_flows is None:
        information_flows = dict()

    # Build participants
    participants = set()
    for file_path, line_nr, span in result_paths:
        service_name = tech_sw.detect_microservice(file_path, dfd)
        for m in microservices.values():
            if m["name"] == service_name:
                participants.add((service_name, file_path, line_nr, span))

    # Add participants marked via properties
    for m in microservices.values():
        for prop in m.get("properties", []):
            if prop[0] == "eureka_connected" and m["name"] not in [p[0] for p in participants]:
                participants.add((m["name"], prop[2][0], prop[2][1], prop[2][2]))

    # --- Add flows from clients to Eureka servers ---
    for participant in participants:
        participant_name, file_path, line_nr, span = participant
        for server_name in eureka_servers:
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


def is_eureka(microservice: tuple) -> bool:
    """Checks if a microservice is a Eureka server.
    Input tuple: (servicename, image, type)
    """

    files = fi.search_keywords("@EnableEurekaServer", file_extension=["*.java", "*.kt"])
    for file in files.keys():
        f = files[file]
        if microservice["pom_path"] in f["path"]:
            return True

    return False


def detect_eureka_server_only(microservices: dict, dfd):

    results = fi.search_keywords("@EnableEurekaServer", file_extension=["*.java", "*.kt"])
    eureka_servers = set()
    for r in results.keys():
        eureka_servers.add(tech_sw.detect_microservice(results[r]["path"], dfd))

    for e in eureka_servers:
        for m in microservices.values():
            if m["name"] == e:        # this is the eureka server
                m.setdefault("stereotype_instances",[]).append("service_registry")
                m.setdefault("tagged_values",[]).append(("Service Registry", "Eureka"))

    return microservices
