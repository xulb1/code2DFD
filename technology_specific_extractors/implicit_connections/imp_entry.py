import ast
import os

import yaml

import core.file_interaction as fi
from output_generators.logger import logger
import core.technology_switch as tech_sw
import tmp.tmp as tmp
import output_generators.traceability as traceability


def set_information_flows(dfd) -> dict:
    """Adds connections based on parsed config files.
    """

    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])
    else:
        information_flows = dict()

    microservices = tech_sw.get_microservices(dfd)

    # Weavescope
    new_information_flows = weavescope(microservices)
    # merge old and new flows
    for ni in new_information_flows.keys():
        key = max(information_flows.keys(), default=-1) + 1
        information_flows[key] = new_information_flows[ni]

    # Zuul
    new_information_flows = zuul(microservices)
    for ni in new_information_flows.keys():
        key = max(information_flows.keys(), default=-1) + 1
        information_flows[key] = new_information_flows[ni]

    tmp.tmp_config.set("DFD", "information_flows", str(information_flows).replace("%", "%%"))
    return information_flows


def weavescope(microservices):
    """
    Generates information flows for microservices monitored by Weave Scope.
    """
    new_information_flows = dict()
    if microservices != None:
        for m in microservices.values():
            if ("Monitoring Dashboard", "Weave Scope") in m["tagged_values"]:
                for mi in microservices.values():
                    if mi["name"] != m["name"]:
                        key = max(new_information_flows.keys(), default=-1) + 1
                        new_information_flows[key] = {
                            "sender": mi["name"],
                            "receiver": m["name"],
                            "stereotype_instances": ["restful_http"]
                        }
                        
                        traceability.add_trace({
                            "item": f"{mi["name"]} -> {m["name"]}",
                            "file": "implicit for weavescope",
                            "line": "implicit for weavescope",
                            "span": "implicit for weavescope",
                        })

    return new_information_flows


def zuul(microservices):
    new_information_flows = dict()
    for m in microservices.values():
        if ("Gateway", "Zuul") in m["tagged_values"]:
            try:
                path = os.path.dirname(m["pom_path"])
            except:
                break

            contents = fi.get_repo_contents_local(path)
            while contents:
                c = contents.pop()
                path = c[1]
                if os.path.isdir(c):
                    contents.update(fi.get_repo_contents_local(path))
                else:
                    filename = os.path.basename(path)
                    if filename.casefold() == "application.properties":
                        logger.info(f"Found application.properties here: {path}")
                        new_information_flows = extract_routes_properties(c.path, microservices[m]["servicename"])
                    elif filename.casefold() == "application.yaml" or filename == "application.yml" or filename == "bootstrap.yml" or filename == "bootstrap.yaml":
                        logger.info(f"Found properteis file here: {path}")
                        new_information_flows = extract_routes_yaml(path, microservices[m]["servicename"])

    return new_information_flows


def extract_routes_properties(path, service):
    try:
        file = fi.file_as_lines(path)
        for line in file:
            new_information_flows = dict()
            if "spring.application.name" in line:
                microservice = str()
                if "=" in line:
                    microservice = line.split("=")[1].strip()
                if microservice:
                    key = max(new_information_flows.keys(), default=-1) + 1
                    new_information_flows[key] = {
                        "sender": service,
                        "receiver": microservice,
                        "stereotype_instances": ["restful_http"]
                    }
            return new_information_flows
    except Exception as e:
        print(f"\033[91m ERROR: {e}\033[0m")
        return False
    return

#FIXME:
def extract_routes_yaml(path, service):
    try:
        with open(path, 'r') as f:
            text = f.read()
        new_information_flows = dict()
        for document in yaml.load(text, Loader=yaml.FullLoader):
            routes = document.get("zuul").get("routes")

            key = max(new_information_flows.keys(), default=-1) + 1
            new_information_flows[key] = {
                "sender": service,
                "receiver": str(routes),
                "stereotype_instances": ["restful_http"]
            }
        return new_information_flows
    except:
        return False
