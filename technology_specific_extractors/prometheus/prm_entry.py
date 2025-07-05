import os

import core.file_interaction as fi
import core.technology_switch as tech_sw
import tmp.tmp as tmp
import output_generators.traceability as traceability


def detect_prometheus_server(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects prometheus server and adds information flows.
    """

    microservices, information_flows = detect_server_docker(microservices, information_flows, dfd)

    return microservices, information_flows


def detect_server_docker(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects prometheus servers via dockerfiles.
    """

    prometheus_server = str()
    results = fi.search_keywords("prom/prometheus")

    for r in results.keys():
        found = False
        prometheus_server = tech_sw.detect_microservice(results[r]["path"], dfd) # check if any of the builds correspond to this path. If yes, that's the service

        for m in microservices.values():
            if m["name"] == prometheus_server:
                m.setdefault("stereotype_instances",[]).append("metrics_server")
                m.setdefault("tagged_values",[]).append(("Metrics Server", "Prometheus"))
                found = True
        if not found:
            prometheus_server = "prometheus-server"
            # add service
            key = max(microservices.keys(), default=-1) + 1
            microservices[key] = {
                "name": "prometheus-server",
                "image": results[r]["path"],
                "stereotype_instances": ["metrics_server"],
                "tagged_values": [("Metrics Server", "Prometheus")]
            }

        information_flows = detect_connections(microservices, information_flows, results[r], prometheus_server)

    return microservices, information_flows


def detect_connections(microservices: dict, information_flows: dict, dockerfile, prometheus_server: str) -> dict:
    """Parses config file to find connections to prometheus.
    """

    local_repo_path = tmp.tmp_config["Repository"]["local_path"]

    for line in dockerfile["content"]:
        if "ADD" in line:
            ini_file_path = line.split(" ")[1]

            ini_file_path = os.path.join(local_repo_path, os.path.dirname(dockerfile["path"]), ini_file_path)

            ini_file = None
            if os.path.isfile(ini_file_path):
                with open(ini_file_path, "r") as file:
                    ini_file = [l.strip() for l in file.readlines()]

            if ini_file:
                for line_nr, line in enumerate(ini_file):
                    target_service = None

                    if "targets" in line:
                        parts = line.split(":")
                        for part in parts:
                            part = part.strip().strip("[]\'\" ")
                            for m in microservices.values():
                                if "localhost" in line:
                                    try:
                                        for prop in m["tagged_values"]:
                                            if prop[0] == "Port" and str(prop[1]) == str(part):
                                                target_service = m["name"]
                                    except Exception as e:
                                        print(f"failed tagged_values for {m["name"]}")
                                elif m["name"] == part:
                                    target_service = m["name"]
                    
                    if target_service:
                        key = max(information_flows.keys(), default=-1) + 1
                        information_flows[key] = {
                            "sender": target_service,
                            "receiver": prometheus_server,
                            "stereotype_instances": ["restful_http"]
                        }

                        traceability.add_trace({
                            "item": f"{target_service} -> {prometheus_server}",
                            "file": dockerfile["path"],
                            "line": line_nr,
                            "span": "span"
                        })

    return information_flows
