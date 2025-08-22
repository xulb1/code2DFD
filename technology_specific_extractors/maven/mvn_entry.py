import ast
import os
import re

import core.file_interaction as fi
from output_generators.logger import logger
import core.parse_files as parse
import core.technology_switch as tech_sw
import technology_specific_extractors.docker.dcr_entry as dcr
import tmp.tmp as tmp
import output_generators.traceability as traceability

try:
    from lxml import etree
    XML_BACKEND = "LXML"
except ImportError:
    import xml.etree.ElementTree as etree
    XML_BACKEND = "PYTHON"
NAMESPACE = {"mvn": "http://maven.apache.org/POM/4.0.0"}


def set_microservices(dfd) -> dict:
    """Extracts the list of services from pom.xml files and sets the variable in the tmp-file.
    """

    if tmp.tmp_config.has_option("DFD", "microservices"):
        microservices = ast.literal_eval(tmp.tmp_config["DFD"]["microservices"])
    else:
        microservices = dict()
    microservices_set = set()

    pom_files = fi.get_file_as_lines("pom.xml")
    module_dict = dict()

    image = "image_placeholder"
    for pf in pom_files.keys():
        pom_file = pom_files[pf]
        modules = extract_modules(pom_file)
        if modules:
            module_dict[(pom_file["name"])] = modules
        else:
            microservice, properties = parse_configurations(pom_file)
            
            print("Dépendences maven de :",microservice[0])
            properties = extract_dependencies(properties, pom_file)
            if microservice[0]:
                port = dcr.detect_port(pom_file["path"])
                # create microservice in dict
                key = max(microservices.keys(), default=-1) + 1
                microservices[key] = {
                    "name": microservice[0],
                    "image": image,
                    "type": "internal",
                    "pom_path": pom_file["path"],
                    "properties": properties,
                    "stereotype_instances": list()
                }
                if port:
                    microservices[key]["tagged_values"] = [("Port", port)]
                else:
                    microservices[key]["tagged_values"] = list()
                
                traceability.add_trace({
                    "item": microservice[0].replace("pom_", ""),
                    "file": microservice[1][0],
                    "line": microservice[1][1],
                    "span": microservice[1][2]
                })

    nested_microservices = check_nested_modules(module_dict)
    microservices_set.update(nested_microservices)

    tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))   # Need to escape single percentage signs for ConfigParser

    return microservices


def extract_dependencies(properties: set, pom_file) -> set:
    """Parses pom_file to check for dependencies.
    """

    file_name = pom_file["path"]
    pom_path = os.path.join(tmp.tmp_config.get("Repository", "local_path"), file_name)
    tree = etree.parse(pom_path)
    root = tree.getroot()


    dependencies = root.find('mvn:dependencies', NAMESPACE)

    if dependencies is not None:
        for dependency in dependencies.findall('mvn:dependency', NAMESPACE):
            groupId = dependency.find('mvn:groupId', NAMESPACE)
            artifactId = dependency.find('mvn:artifactId', NAMESPACE)

            
            if artifactId is not None:
                aid = artifactId.text.strip()
                print("-",aid)
                
                # Hystrix
                if aid == "spring-cloud-starter-netflix-hystrix":
                    properties.add(("circuit_breaker", "Hystrix", ("file", "line", "span")))

                # Resilience4j (Spring Boot Starter or modules)
                if aid.startswith("resilience4j-") or aid == "spring-boot-starter-resilience4j":
                    properties.add(("circuit_breaker", "Resilience4j", ("file", "line", "span")))

                # MicroProfile Fault Tolerance
                if aid == "microprofile-fault-tolerance-api":
                    properties.add(("circuit_breaker", "MicroProfile FT", ("file", "line", "span")))

                # Failsafe
                if aid == "failsafe":
                    properties.add(("circuit_breaker", "Failsafe", ("file", "line", "span")))
                    
                # print("<<<<<<<<<<>>>>><<<<<<<<< CICUIT BREAKER found in dependencies >>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
                
    return properties

#TODO add detect dependencies and properties for Load Ballencer, security, ...


def extract_modules(pom_file: dict) -> list:
    """Extracts modules of a Maven project based on the <module> </module>-tag.
    """

    file_name = pom_file["path"]
    pom_path = os.path.join(tmp.tmp_config.get("Repository", "local_path"), file_name)
    tree = etree.parse(pom_path)
    root = tree.getroot()

    modules_list = set()
    modules = root.find('mvn:modules', NAMESPACE)
    if modules is not None:
        modules_list = {module.text.strip() for module in modules.findall('mvn:module', NAMESPACE)}

    return modules_list


def check_nested_modules(module_tuples: dict) -> set:
    """Takes list of tuples of the form [(component, [modules])] and checks for links between them.
    If yes, returns list of components = services that need to be added to the list.
    """

    modules = set(*module_tuples.values())
    components = set(module_tuples.keys())
    microservices = components & modules

    return microservices


def parse_configurations(pom_file) -> str:
    """Extracts servicename and properties for a given file. Tries properties file first, then pom file.
    """

    microservice, properties = parse_properties_file(pom_file["path"])
    if not microservice[0]:
        microservice = extract_servicename_pom_file(pom_file)
    if not microservice[0]:
        return (False, False), set()

    return microservice, properties


def parse_properties_file(pom_path: str):
    """Goes down folder structure to find properties file. Then tries to extract servicename. Else returns False.
    """

    properties = set()
    microservice = [False, False]
    # find properties file
    path = os.path.dirname(pom_path)

    local_repo_path = tmp.tmp_config["Repository"]["local_path"]

    dirs = list()
    dirs.append(os.scandir(os.path.join(local_repo_path, path)))

    while dirs:
        dir = dirs.pop()
        for entry in dir:
            if entry.is_file() and "test" not in entry.path:
                filename = os.path.basename(entry.path)
                new_microservice, new_properties = None, None
                if filename in ["application.properties", "bootstrap.properties"]:
                    logger.info(f"Found application.properties here: {entry.path}")
                    file_path = entry.path
                    new_microservice, new_properties = parse.parse_properties_file(file_path)
                elif filename in ["application.yaml", "application.yml", "bootstrap.yml", "bootstrap.yaml", "filebeat.yml", "filebeat.yaml"]:
                    logger.info(f"Found properties file here: {entry.path}")
                    file_path = entry.path
                    new_microservice, new_properties = parse.parse_yaml_file(file_path)

                if new_microservice and new_microservice[0]:
                    microservice = new_microservice
                if new_properties:
                    properties = properties.union(new_properties)

            elif entry.is_dir():
                dirs.append(os.scandir(entry.path))

    return microservice, properties


def extract_servicename_pom_file(pom_file) -> str:
    """Extracts the name of a Maven-module based on the <finalName> tag if existing, else the <artifactIf>.
    """

    microservice = [False, False]
    file_name = pom_file["path"]
    pom_path = os.path.join(tmp.tmp_config.get("Repository", "local_path"), file_name)
    tree = etree.parse(pom_path)
    root = tree.getroot()

    artifactId = root.find('mvn:build/mvn:finalName', NAMESPACE)
    if artifactId is None:
        artifactId = root.find('mvn:artifactId', NAMESPACE)
    if artifactId is None:
        return microservice

    microservice[0] = artifactId.text.strip()

    # tracing
    if XML_BACKEND == "LXML":
        line_nr = artifactId.sourceline - 1
        line = pom_file["content"][line_nr]
        length_tuple = re.search(microservice[0], line).span()
        span = "[" + str(length_tuple[0]) + ":" + str(length_tuple[1]) + "]"
    else:
        line_nr = None
        span = "[?:?]"
    trace = (file_name, line_nr, span)

    microservice[0] = "pom_" + microservice[0]
    microservice[1] = trace

    return microservice


def detect_microservice(file_path, dfd):
    """Detects which microservice a file belongs to by looking for next pom.xml.
    """

    microservice = [False, False]
    microservices = tech_sw.get_microservices(dfd)

    found_pom = False

    local_repo_path = tmp.tmp_config["Repository"]["local_path"]
    dirs = []
    path = file_path
    path = os.path.dirname(path)
    
    while not found_pom and path != "":
        dirs.append(os.scandir(os.path.join(local_repo_path, path)))
        while dirs and not found_pom:
            dir = dirs.pop()
            for entry in dir:
                if entry.is_file():
                    if entry.name.casefold() == "pom.xml":
                        pom_path = os.path.relpath(entry.path, start=local_repo_path)
                        logger.info("Found pom.xml here: " + str(entry.path))
                        found_pom = True
        path = os.path.dirname(path)

    if found_pom:
        pom_file = dict()
        pom_file["path"] = pom_path
        for m in microservices.keys():
            try:
                if microservices[m]["pom_path"] == pom_path:
                    microservice[0] = microservices[m]["name"]
            except:
                pass
        if not microservice[0]:
            pom_file["content"] = fi.file_as_lines(pom_path)
            microservice, properties = parse_configurations(pom_file)
    else:
        logger.info("Did not find microservice")

    if not microservice[0]:

        for m in microservices.keys():
            try:
                image = microservices[m]["image"]
                path = os.path.dirname(file_path)
                if image in path:
                    microservice[0] = microservices[m]["name"]
            except:
                pass

    return microservice[0]
