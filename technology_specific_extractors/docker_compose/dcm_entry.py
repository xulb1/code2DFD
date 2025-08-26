import ast
import os

import core.file_interaction as fi
from output_generators.logger import logger
import core.technology_switch as tech_sw
import technology_specific_extractors.docker_compose.dcm_parser as dcm_parser
import tmp.tmp as tmp
import output_generators.traceability as traceability

docker_compose_content = False

def set_microservices(dfd) -> None:
    """Reads microservices out of a .yml file, only returns ones defined in this repo.
    """

    global docker_compose_content

    microservices_set = set()

    # Download docker-compose file
    if not docker_compose_content:
        possible_filenames = ["docker-compose.yml", "docker-compose.yaml", "docker-compose*"]

        for filename in possible_filenames:
            raw_files = fi.get_file_as_yaml(filename)
            if raw_files:
                break

        if len(raw_files) == 0:
            microservices = tech_sw.get_microservices(dfd)
            microservices = clean_pom_names(microservices)
            tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))
            return
        docker_compose_content = raw_files[0]["content"]

    microservices_set, properties_dict = dcm_parser.extract_microservices(docker_compose_content, raw_files[0]["path"])

    if not microservices_set:
        microservices = tech_sw.get_microservices(dfd)
        microservices = clean_pom_names(microservices)
        tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))
        return
    microservices = dictionarify(microservices_set, properties_dict)
    microservices = clean_pom_names(microservices)

    tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))


def clean_pom_names(microservices: dict) -> dict:
    """Deletes "pom_" from microservice names. Needed in specific cases.
    """

    for m in microservices:
        microservices[m]["name"] = microservices[m]["name"].replace("pom_", "")

    return microservices


def dictionarify(elements_set: set, properties_dict: dict) -> dict:
    """Turns set of services into dictionary.
    """

    if tmp.tmp_config.has_option("DFD", "microservices"):
        elements = ast.literal_eval(tmp.tmp_config["DFD"]["microservices"])
    else:
        elements = dict()

    for e in elements_set:
        try:
            properties = properties_dict[e[0]]
        except Exception:
            properties = set()
        
        imageInfo = check_image(e[1])
        if imageInfo:
            stereotypes = imageInfo[0]
            tagged_values = imageInfo[1]
        else:
            stereotypes = []
            tagged_values = []
        if e[3]:
            try:
                tagged_values.append(("Port", str(list(e[3][0]))))
            except TypeError:
                tagged_values.append(("Port", str(e[3][0])))
            except Exception as ex:
                print(ex,"\n",list(e[3]))
                
            traceability.add_trace({
                "parent_item": e[0],#.replace("pom_", "")
                "item": "Port",
                "file": e[3][1],
                "line": e[3][2],
                "span": e[3][3]
            })
            
        newKey = max(elements.keys(), default=-1) + 1
        elements[newKey] = {
            "name": e[0],
            "image": e[1],
            "type": e[2],
            "properties": properties,
            "stereotype_instances": stereotypes,
            "tagged_values": tagged_values
        }
        
        traceability.add_trace({
            "item": e[0],#.replace("pom_", "")
            "file": e[4][0],
            "line": e[4][1],
            "span": e[4][2]
        })

    return elements


def set_information_flows(dfd) -> dict:
    """Adds information flows based on "links" parameter in docker-compose.
    """

    global docker_compose_content

    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])
    else:
        information_flows = dict()

    microservices = tech_sw.get_microservices(dfd)

    # Download docker-compose file
    if not docker_compose_content:
        possible_filenames = ["docker-compose.yml", "docker-compose.yaml", "docker-compose*"]

        for filename in possible_filenames:
            raw_files = fi.get_file_as_yaml(filename)
            if raw_files:
                docker_compose_content = raw_files[0]["content"]
                break
        
        if not docker_compose_content:
            return information_flows
            
    information_flows = dcm_parser.extract_information_flows(docker_compose_content, microservices, information_flows)

    tmp.tmp_config.set("DFD", "information_flows", str(information_flows).replace("%", "%%"))
    return information_flows


def get_environment_variables(docker_compose_file_URL: str) -> set:
    environment_variables = set()
    try:
        env_files = fi.get_file_as_lines(".env")
        for env in env_files.keys():
            e = env_files[env]
            env_file_content = e["content"].decode('UTF-8')
        env_file_lines = env_file_content.split("\n")
        for line in env_file_lines:
            try:
                environment_variables.add((line.split("=")[0].strip(), line.split("=")[1].strip()))
            except Exception as e:
                print(e)
                logger.debug("error splitting line in dco_entry.set_microservices")
    except Exception as e:
        print(e)
        logger.info("No .env file exists",e)
    return environment_variables


def check_image(image: str) -> list:
    """Check image for some specific technologies.
    """

    if "weaveworks/scope" in image:
        return [["monitoring_dashboard"], [("Monitoring Dashboard", "Weave Scope")]]
    return []


def detect_microservice(file_path: str, dfd) -> str:
    """Detects, which service a file belongs to based on image given in docker-compose file and dockerfile belonging to file given as input.
    """

    microservices = tech_sw.get_microservices(dfd)
    microservice = False
    dockerfile_path = False

    local_repo_path = tmp.tmp_config["Repository"]["local_path"]

    # Find corresponding dockerfile
    dirs = []
    found_docker = False

    path = os.path.dirname(file_path)
    while not found_docker and path != "":
        dirs.append(os.scandir(os.path.join(local_repo_path, path)))
        while dirs:
            directory = dirs.pop()
            for entry in directory:
                if entry.is_file() and entry.name.casefold() == "dockerfile":
                        dockerfile_path = os.path.relpath(entry.path, start=local_repo_path).strip("/")
                        found_docker = True
        path = os.path.dirname(path)


    # find docker-compose path
    try:
        possible_filenames = ["docker-compose.yml", "docker-compose.yaml", "docker-compose*"]

        for filename in possible_filenames:
            raw_files = fi.get_file_as_lines(filename)
            if raw_files:
                break
        if len(raw_files) == 0:
            return microservice
        docker_compose_path = raw_files[0]["path"]          # path in the repo (w/0 "analysed_...")
        docker_compose_location = os.path.dirname(docker_compose_path)
    except Exception as e:
        print(e)

    # path of dockerfile relative to docker-compose file
    # if dockerfile is in same branch in file structure as docker-compose-file:
    if dockerfile_path:
        dockerfile_location = os.path.dirname(dockerfile_path)
    
    try:
        docker_image = os.path.relpath(dockerfile_location, start=docker_compose_location).strip("/")
        # go through microservices to see if dockerfile_image fits an image
        for m in microservices.values():
            if m["image"] == docker_image:
                microservice = m["name"]
    except Exception as e:
        pass
        # print(e)


    return microservice
