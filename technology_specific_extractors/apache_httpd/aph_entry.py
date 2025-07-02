import re
import os

import core.external_components as ext
import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability


def detect_apachehttpd_webserver(microservices: dict, information_flows: dict, external_components: dict, dfd) -> dict:
    """Detects apachehttpd webservers and routes if possible.
    """

    microservices, information_flows, external_components = detect_via_docker(microservices, information_flows, external_components, dfd)
    microservices, information_flows, external_components = detect_via_proxypass(microservices, information_flows, external_components, dfd)

    return microservices, information_flows, external_components


def detect_via_docker(microservices: dict, information_flows: dict, external_components: dict, dfd):
    """Looks for Dockerfile that starts Apache httpd. Then Extracts server and routes.
    """

    docker_path = False

    results = fi.search_keywords("apache2ctl")     # content, name, path
    for r in results.keys():
        microservice = tech_sw.detect_microservice(results[r]["path"], dfd)
        trace_info = (results[r]["path"], results[r]["line_nr"], results[r]["span"])

        for line_nr in range(len(results[r]["content"])):
            line = results[r]["content"][line_nr]
            if "apache2ctl" in line and line.strip()[:3] == "CMD":
                docker_path = results[r]["path"]
                mark_server(microservices, microservice)

                # Trace
                trace = dict()
                trace["item"] = "web_server"
                trace["file"] = docker_path
                trace["line"] = line_nr
                trace["span"] = re.search("apache2ctl", line).span()
                traceability.add_trace(trace)

        information_flows, external_components = add_user(information_flows, external_components, microservice, trace_info)
        microservices, information_flows = add_connections_docker(microservices, information_flows, results[r]["content"], docker_path, microservice, results[r]["path"])

    return microservices, information_flows, external_components


def detect_via_proxypass(microservices: dict, information_flows: dict, external_components: dict, dfd):
    """Searches for keyword ProxyPass to detect server. For cases where config file has to be handled manually by user, detection is still possible this way.
    """

    results = fi.search_keywords("ProxyPass")     # content, name, path
    for r in results.keys():
        microservice = tech_sw.detect_microservice(results[r]["path"], dfd)
        trace_info = (results[r]["path"], results[r]["line_nr"], results[r]["span"])
        mark_server(microservices, microservice)
        information_flows, external_components = add_user(information_flows, external_components, microservice, trace_info)
        microservices, information_flows = add_connections(microservices, information_flows, results[r]["content"], microservice, results[r]["path"])

    return microservices, information_flows, external_components


def add_user(information_flows: dict, external_components: dict, microservice: str, trace_info) -> dict:
    """Adds user and connections to external components.
    """

    if not microservice:
        microservice = "apache-server"

        trace = dict()
        trace["item"] = microservice
        trace["file"] = trace_info[0]
        trace["line"] = trace_info[1]
        trace["span"] = trace_info[2]
        traceability.add_trace(trace)

    # External component user
    external_components = ext.add_user(external_components)

    # connection user to webserver
    information_flows = ext.add_user_connections(information_flows, microservice)

    return information_flows, external_components


def mark_server(microservices: dict, microservice: str) -> dict:
    """Marks the correct microservice as apacha server or adds a new service if none fits.
    """

    if not microservice:
        newKey = max(microservices.keys(), default=-1) + 1
        
        microservices[newKey] = dict()
        microservices[newKey]["name"] = "apache-server"
        microservices[newKey]["stereotype_instances"] = ["web_server"]
        microservices[newKey]["tagged_values"] = [("Web Server", "Apache httpd")]
    else:
        for m in microservices.values():
            if m["name"] == microservice: # this is the service
                m.setdefault("stereotype_instances", []).append("web_server")
                m.setdefault("tagged_values", []).append(("Web Server", "Apache httpd"))
                
    return microservices


def add_connections_docker(microservices: dict, information_flows: dict, file, docker_path: str, microservice: str, file_name):
    """Adds connections to other services based on ProxyPass keyword.
    """

    config_file_path = False
    config_file = False
    for line in file:
        if "COPY" in line and ".conf" in line:
            config_file_path = line.strip().split(" ")[1]
    
    if config_file_path and docker_path:
        complete_config_file_path = os.path.join(os.path.dirname(docker_path), config_file_path)
        config_file_name = os.path.basename(complete_config_file_path)
        files = fi.get_file_as_lines(config_file_name)
        for f in files:
            if files[f]["path"] == complete_config_file_path:
                config_file = files[f]
        if config_file:
            microservices, information_flows = add_connections(microservices, information_flows, files[f]["content"], microservice, file_name)

    return microservices, information_flows


def add_connections(microservices: dict, information_flows: dict, file, microservice: str, file_name) -> dict:
    """Adds connections to other services based on ProxyPass keyword.
    """

    if not microservice:
        microservice = "apache-server"
    
    for line_nr, line in enumerate(file):
        if "ProxyPass " not in line:
            continue
        
        parts = line.split(" ")
        for part in parts:
            if "http" in part and "://" in part:
                target_service = False
                host = part.split("://")[1].split(":")[0]
                if host == "localhost":
                    port = part.split("://")[1].split(":")[1].strip().strip("\"").strip("/")
                    for value in microservices.values():
                        try:
                            for prop in value["tagged_values"]:
                                if (prop[0] == "Port" and str(prop[1]) == str(port)):
                                    target_service = value["name"]
                        except Exception:
                            pass
                else:
                    for value in microservices.values():
                        if value["name"] == host:
                            target_service = host
                
                if target_service:
                    newKey = max(information_flows.keys(), default=-1) + 1
                    
                    information_flows[newKey] = dict()
                    information_flows[newKey]["sender"] = microservice
                    information_flows[newKey]["receiver"] = target_service
                    information_flows[newKey]["stereotype_instances"] = ["restful_http"]

                    traceability.add_trace({
                        "item": f"{microservice} -> {target_service}",
                        "file": file_name,
                        "line": line_nr,
                        "span": "span"
                    })

        line_nr += 1
    return microservices, information_flows
