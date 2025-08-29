import os.path

import core.file_interaction as fi
import core.parse_files as parse
import technology_specific_extractors.environment_variables as env
import core.technology_switch as tech_sw
import tmp.tmp as tmp
import output_generators.traceability as traceability


def detect_spring_config(microservices: dict, information_flows: dict, external_components: dict, dfd) -> dict:
    """Detects Spring Cloud Config server and connections to it. And parses config files.
    """

    config_server, config_path = False, False
    microservices, config_server, config_path, config_file_path, config_repo_uri, config_server_ports, config_file_path_local = detect_config_server(microservices, dfd)
    if config_file_path or config_repo_uri or config_file_path_local:
        microservices, information_flows, external_components = parse_config_files(config_server, config_file_path, config_file_path_local, config_repo_uri, microservices, information_flows, external_components)
    microservices, information_flows = detect_config_clients(microservices, information_flows, config_server, config_server_ports)

    return microservices, information_flows, external_components


def detect_config_server(microservices: dict, dfd):
    """Finds config server and sets needed variables
    """

    results = fi.search_keywords("@EnableConfigServer", file_extension=["*.java"])
    config_server = False
    config_path = False
    config_file_path = False
    config_repo_uri = False
    config_server_ports = []
    config_file_path_local = False

    if len(results) > 1:
        print("More than one config server. Picking first one found.")
    for r in results.values():
        config_server = tech_sw.detect_microservice(r["path"], dfd)

        for m in microservices.values():
            if m["name"] == config_server:
                m.setdefault("stereotype_instances",[]).append("configuration_server")
                m.setdefault("tagged_values",[]).append(("Configuration Server", "Spring Cloud Config"))

                # Traceability
                traceability.add_trace({
                    "parent_item": config_server,
                    "item": "configuration_server",
                    "file": r["path"],
                    "line": r["line_nr"],
                    "span": r["span"]
                })

                try:
                    config_path = os.path.dirname(m["pom_path"])
                except Exception:
                    pass

                for prop in m["properties"]:
                    if prop[0] == "config_file_path":
                        config_file_path = prop[1]
                    elif prop[0] == "config_repo_uri":
                        config_repo_uri = prop[1]

                        traceability.add_trace({
                            "item": f"github-repository -> {config_server}",
                            "file": prop[2][0],
                            "line": prop[2][1],
                            "span": prop[2][2]
                        })

                    elif prop[0] == "config_file_path_local":
                        config_file_path_local = prop[1]
                    elif prop[0] == "port":
                        config_server_ports.append(prop[1])
    return microservices, config_server, config_path, config_file_path, config_repo_uri, config_server_ports, config_file_path_local


def detect_config_clients(microservices: dict, information_flows: dict, config_server: str, config_server_ports: list) -> dict:
    """Detect microservices that access config server.
    """

    config_id = False
    trace_file = False

    for m in microservices.keys():
        if microservices[m]["name"] == config_server:
            config_id = m
        config_uri, config_connected, config_username, config_password = False, False, False, False
        for prop in microservices[m]["properties"]:
            trace_file = prop[2][0]
            trace_line = prop[2][1]
            trace_span = prop[2][2]
            if prop[0] == "config_uri":
                config_uri = prop[1]
            elif prop[0] == "config_connected":
                config_connected = True
            elif prop[0] == "config_username":
                config_username = env.resolve_env_var(prop[1])
            elif prop[0] == "config_password":
                config_password = env.resolve_env_var(prop[1])
            else:
                trace_file = False
        # pw & user

        if not config_connected and config_uri:
            parts = config_uri.split("/")
            for part in parts:
                try:
                    if str(part.split(":")[0]) == str(config_server):
                        config_connected = True
                    elif ":" in part and int(part.split(":")[1]) in config_server_ports:
                        config_connected = True
                except Exception:
                    pass
        if not config_connected and config_uri:
            for port in config_server_ports:
                if "localhost:" + str(port) in config_uri:
                    config_connected = True
        if config_connected:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": config_server,
                "receiver": microservices[m]["name"],
                "stereotype_instances": ["restful_http"]
            }

            if trace_file and config_server:
                traceability.add_trace({
                    "item": config_server + " -> " + microservices[m]["name"],
                    "file": trace_file,
                    "line": trace_line,
                    "span": trace_span
                })

            if config_username:
                information_flows[key]["stereotype_instances"].append("plaintext_credentials_link")
                if config_id:
                    microservices[config_id].setdefault("stereotype_instances",[]).append("plaintext_credentials")
                    microservices[config_id].setdefault("tagged_values",[]).append(("Username", config_username))

                    if trace_file:
                        traceability.add_trace({
                            "parent_item": microservices[config_id]["name"],
                            "item": "plaintext_credentials",
                            "file": trace_file,
                            "line": trace_line,
                            "span": trace_span
                        })

            if config_password:
                information_flows[key]["stereotype_instances"].append("plaintext_credentials_link")
                if config_id:
                    microservices[config_id].setdefault("stereotype_instances",[]).append("plaintext_credentials")
                    microservices[config_id].setdefault("tagged_values",[]).append(("Password", config_password))

                    if trace_file:
                        traceability.add_trace({
                            "parent_item": microservices[config_id]["name"],
                            "item": "plaintext_credentials",
                            "file": trace_file,
                            "line": trace_line,
                            "span": trace_span
                        })

    return microservices, information_flows


def parse_config_files(config_server: str, config_file_path: str, config_file_path_local: str, config_repo_uri: str, microservices: dict, information_flows: dict, external_components: dict) -> dict:
    """Parses config files from locally or other GitHub repository.
    """

    if not config_file_path:
        config_file_path = ""
    if config_repo_uri:
        information_flows, external_components = set_repo(information_flows, external_components, config_repo_uri, config_server)
    gh_contents = False
    contents = set()

    if config_file_path:
        new_contents = fi.get_repo_contents_local(config_file_path)
        contents.update(new_contents)

    else:
        new_contents = fi.get_repo_contents_local(False)
        contents.update(new_contents)

    # external (other github repository) didn't work, look locally
    if config_file_path_local:

        local_path = tmp.tmp_config["Repository"]["local_path"]
        config_file_path_local = os.path.relpath(config_file_path_local, start=local_path)

        new_contents = fi.get_repo_contents_local(config_file_path_local)
        contents.update(new_contents)


    if not gh_contents and not contents:
        new_contents = fi.get_repo_contents_local(config_file_path)
        contents.update(new_contents)

    if gh_contents:
        for file in gh_contents:
            contents.add((file.name, file.path))

    if contents:
        for file in contents:
            ending = False
            microservice = False
            properties = set()
            for m in microservices.keys():
                if file[0].split(".")[0] == microservices[m]["name"]:
                    microservice = microservices[m]["name"]
                    correct_id = m
                    if "." in file[0]:
                        ending = file[0].split(".")[1]
                    break
            if not microservice:
                for m in microservices.keys():
                    if  microservices[m]["name"] in file[0].split(".")[0]:
                        microservice = microservices[m]["name"]
                        correct_id = m
                        if "." in file[0]:
                            ending = file[0].split(".")[1]
                        break
            if microservice and ending:
                if ending in ["yml", "yaml"]:
                    name, properties = parse.parse_yaml_file(file[1])
                    name = name[0]
                elif ending == "properties":
                    name, properties = parse.parse_properties_file(file[1])
                    name = name[0]
                
                microservices[correct_id].setdefault("properties",set()).update(properties)

    return microservices, information_flows, external_components


def set_repo(information_flows: dict, external_components: dict, config_repo_uri: str, config_server: str) -> dict:
    """Adds a repo to the external components.
    """

    key = max(information_flows.keys(), default=-1) + 1
    information_flows[key] = {
        "sender": "github-repository",
        "receiver": config_server,
        "stereotype_instances": ["restful_http"]
    }

    key = max(external_components.keys(), default=-1) + 1
    external_components[key] = {
        "name": "github-repository",
        "type": "external_component",
        "stereotype_instances": ["github_repository", "entrypoint"],
        "tagged_values": [("URL", config_repo_uri)]
    }

    return information_flows, external_components
