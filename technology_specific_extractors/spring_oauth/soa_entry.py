import core.file_interaction as fi
import technology_specific_extractors.environment_variables as env
import core.technology_switch as tech_sw
import output_generators.traceability as traceability


def detect_spring_oauth(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detect Spring OAuth Server and connections to it.
    """

    microservices = detect_authorization_server(microservices, dfd)
    microservices = detect_resource_servers(microservices, dfd)
    microservices, information_flows = detect_token_server(microservices, information_flows, dfd)
    microservices = detect_preauthorized_methods(microservices, dfd)

    return microservices, information_flows


def detect_authorization_server(microservices: dict, dfd) -> dict:
    """Detects an authorization server.
    """

    results = fi.search_keywords("@EnableAuthorizationServer", file_extension=["*.java", "*.kt"])

    authorization_server = str()
    for r in results.values():
        authorization_server = tech_sw.detect_microservice(r["path"], dfd)
        for m in microservices.values():
            if m["name"] == authorization_server:
                m.setdefault("stereotype_instances",[]).append("authorization_server")
                m.setdefault("tagged_values",[]).append(("Authorization Server", "Spring OAuth2"))

                # Traceability
                traceability.add_trace({
                    "parent_item": authorization_server,
                    "item": "authorization_server",
                    "file": r["path"],
                    "line": r["line_nr"],
                    "span": r["span"]
                })

    return microservices


def detect_resource_servers(microservices: dict, dfd) -> dict:
    """Detects resource servers.
    """
    
    results = fi.search_keywords("@EnableResourceServer", file_extension=["*.java", "*.kt"])

    resource_server = str()
    for r in results.values():
        resource_server = tech_sw.detect_microservice(r["path"], dfd)
        for m in microservices.values():
            if m["name"] == resource_server:
                m.setdefault("stereotype_instances",[]).append("resource_server")

                # Traceability
                traceability.add_trace({
                    "parent_item": resource_server,
                    "item": "resource_server",
                    "file": r["path"],
                    "line": r["line_nr"],
                    "span": r["span"]
                })

    return microservices


def detect_token_server(microservices: dict, information_flows: dict, dfd) -> dict:
    """Goes thorugh properties of services and detects if one of them is tokenserver for the others.
    """

    for m in microservices.values():
        token_server = False
        client_secret = False
        for prop in m["properties"]:
            if prop[0] == "oauth_client_secret":
                client_secret = env.resolve_env_var(prop[1])
        if client_secret:
            stereotypes = ["authentication_with_plaintext_credentials", "auth_provider", "restful_http", "plaintext_credentials_link"]
            tagged_values = [("Password", client_secret)]
        else:
            stereotypes = ["auth_provider", "restful_http"]
            tagged_values = []
        for prop in m["properties"]:
            if prop[0] == "oauth_tokenuri":
                token_server_uri = prop[1]
                token_server = fi.resolve_url(token_server_uri, False, dfd)
                if token_server:
                    for m2 in microservices.values():
                        if m2["name"] == token_server:
                            if "stereotype_instances" in m2:
                                m2.setdefault("stereotype_instances",[]).append("token_server")
                                
                            traceability.add_trace({
                                "parent_item": m2["name"],
                                "item": "token_server",
                                "file": prop[2][0],
                                "line": prop[2][1],
                                "span": prop[2][2]
                            })

                    key = max(information_flows.keys(), default=-1) + 1
                    information_flows[key] = {
                        "sender": token_server,
                        "receiver": m["name"],
                        "stereotype_instances": stereotypes,
                        "tagged_values": tagged_values
                    }

                    traceability.add_trace({
                        "item": f"{token_server} -> {m["name"]}",
                        "file": prop[2][0],
                        "line": prop[2][1],
                        "span": prop[2][2]
                    })

    return microservices, information_flows


def detect_preauthorized_methods(microservices: dict, dfd) -> dict:
    """Detects methods annotated as pre-authroized.
    """

    results = fi.search_keywords("@PreAuthorize", file_extension=["*.java", "*.kt"])

    for r in results.values():
        microservice = tech_sw.detect_microservice(r["path"], dfd)
        if "readme" not in r["path"].casefold() and \
            "test" not in r["path"].casefold():
            # Try extracting endpoints
            tagged_values = set()
            endpoints = extract_endpoints(r["content"])
            if endpoints:
                tagged_values = ("Pre-authorized Endpoints", endpoints)

            for m in microservices.values():
                if m["name"] == microservice:
                    m.setdefault("stereotype_instances",[]).append("pre_authorized_endpoints")

                    if tagged_values:
                        m.setdefault("tagged_values",[]).append(tagged_values)

                    # Traceability
                    traceability.add_trace({
                        "parent_item": microservice,
                        "item": "pre_authorized_endpoints",
                        "file": r["path"],
                        "line": r["line_nr"],
                        "span": r["span"]
                    })

    return microservices


def extract_endpoints(file_as_lines):
    """Extracts the endpoints that are pre-authorized.
    """

    endpoints = set()
    mappings = ["RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping"]

    for line_nr in range(len(file_as_lines)):
        line = file_as_lines[line_nr]
        if "@PreAuthorize" in line:
            endpoint = False
            for mapping in mappings:
                if mapping in file_as_lines[line_nr + 1]:
                    endpoint = extract_endpoint_part(file_as_lines[line_nr + 1])

            if endpoint:
                endpoints.add(endpoint)
    # print("-===================-----------------")
    # print(endpoints)
    # print("-===================-----------------")
    
    # nested mappings not considered here
    return list(endpoints)


def extract_endpoint_part(line: str) -> str:
    endpoint_part = str()
    if "path" in line:          # not found in documentation, but used in piggy to name endpoint
        endpoint_part = line.split("path")[1].split(",")[0].split('\"')[1]
    elif "value" in line:       # usual keyword to describe path
        endpoint_part = line.split("value")[1].split(",")[0].split('\"')[1]
    elif "," not in line and "/" in line:       # only for the "/" endpoint
        endpoint_part = line.split('\"')[1]
    return endpoint_part
