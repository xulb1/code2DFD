import ast
import os
import re

import output_generators.traceability as traceability
from output_generators.logger import logger
import core.technology_switch as tech_sw
import core.file_interaction as fi
import core.parse_files as parse
import technology_specific_extractors.docker.dcr_entry as dcr
from technology_specific_extractors.xml_var import resolve_pom, substitute
import tmp.tmp as tmp

try:
    from lxml import etree
    XML_BACKEND = "LXML"
except ImportError:
    import xml.etree.ElementTree as etree
    XML_BACKEND = "PYTHON"

NAMESPACE = {"mvn": "http://maven.apache.org/POM/4.0.0"}

# Cache XML
_POM_CACHE = {}


def parse_pom_file_once(pom_file_path):
    """Parse un pom.xml et garde le résultat en cache."""
    if pom_file_path in _POM_CACHE:
        return _POM_CACHE[pom_file_path]
    try:
        if XML_BACKEND == "LXML":
            parser = etree.XMLParser(recover=True)  # tolérant aux erreurs
            tree = etree.parse(pom_file_path, parser)
        else:
            tree = etree.parse(pom_file_path)
        root = tree.getroot()
        _POM_CACHE[pom_file_path] = root
        return root
    except etree.XMLSyntaxError as e:
        print(f"\033[91mERROR in {pom_file_path}: {e}\033[0m")
        return None


# -------------------------------
# Utilitaires XML factorisés
# -------------------------------

def get_dependencies(root):
    return root.find('mvn:dependencies', NAMESPACE)

def get_modules(root):
    return root.find('mvn:modules', NAMESPACE)

def get_artifact_or_final_name(root):
    artifactId = root.find('mvn:build/mvn:finalName', NAMESPACE)
    if artifactId is None:
        artifactId = root.find('mvn:artifactId', NAMESPACE)
    return artifactId


# -------------------------------
# Fonctions principales
# -------------------------------

def set_microservices(dfd) -> dict:
    """Extracts the list of services from pom.xml files and sets the variable in the tmp-file."""
    if tmp.tmp_config.has_option("DFD", "microservices"):
        microservices = ast.literal_eval(tmp.tmp_config["DFD"]["microservices"])
    else:
        microservices = {}
    microservices_set = set()

    pom_files = fi.get_file_as_lines("pom.xml")
    module_dict = {}

    image = "image_placeholder"
    for _, pom_file in pom_files.items():
        modules = extract_modules(pom_file)
        if modules:
            module_dict[pom_file["name"]] = modules
        else:
            microservice, properties = parse_configurations(pom_file)
            # print("Dépendences maven de :", microservice[0])
            properties = extract_dependencies(properties, pom_file)
            if microservice[0]:
                port = dcr.detect_port(pom_file["path"])
                key = max(microservices.keys(), default=-1) + 1
                microservices[key] = {
                    "name": microservice[0],
                    "image": image,
                    "type": "internal",
                    "pom_path": pom_file["path"],
                    "properties": properties,
                    "stereotype_instances": []
                }
                microservices[key]["tagged_values"] = [("Port", port)] if port else []
                traceability.add_trace({
                    "item": microservice[0].replace("pom_", ""),
                    "file": microservice[1][0],
                    "line": microservice[1][1],
                    "span": microservice[1][2]
                })

    nested_microservices = check_nested_modules(module_dict)
    microservices_set.update(nested_microservices)

    tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))
    return microservices


def extract_dependencies(properties: set, pom_file) -> set:
    pom_path = os.path.join(tmp.tmp_config.get("Repository", "local_path"), pom_file["path"])
    root = parse_pom_file_once(pom_path)
    if root is None:
        return properties

    dependencies = get_dependencies(root)
    if dependencies is not None:
        for dependency in dependencies.findall('mvn:dependency', NAMESPACE):
            artifactId = dependency.find('mvn:artifactId', NAMESPACE)
            if artifactId is not None:
                aid = artifactId.text.strip()
                # print("-", aid)

                if aid == "spring-cloud-starter-netflix-hystrix":
                    properties.add(("circuit_breaker", "Hystrix", ("file", "line", "span")))
                if aid.startswith("resilience4j-") or aid == "spring-boot-starter-resilience4j":
                    properties.add(("circuit_breaker", "Resilience4j", ("file", "line", "span")))
                if aid == "microprofile-fault-tolerance-api":
                    properties.add(("circuit_breaker", "MicroProfile FT", ("file", "line", "span")))
                if aid == "failsafe":
                    properties.add(("circuit_breaker", "Failsafe", ("file", "line", "span")))
    return properties


def extract_modules(pom_file: dict) -> set:
    pom_path = os.path.join(tmp.tmp_config.get("Repository", "local_path"), pom_file["path"])
    root = parse_pom_file_once(pom_path)
    if root is None:
        return set()

    modules = get_modules(root)
    return {m.text.strip() for m in modules.findall('mvn:module', NAMESPACE)} if modules is not None else set()


def check_nested_modules(module_tuples: dict) -> set:
    modules = set(*module_tuples.values())
    components = set(module_tuples.keys())
    microservices = components & modules
    return microservices


def parse_configurations(pom_file) -> str:
    """Extracts servicename and properties for a given file. Tries properties file first, then pom file."""
    microservice, properties = parse_properties_file(pom_file["path"])
    if not microservice[0]:
        microservice = extract_servicename_pom_file(pom_file)
    if not microservice[0]:
        return (False, False), set()
    return microservice, properties


def parse_properties_file(pom_path: str):
    """Goes down folder structure to find properties file. Then tries to extract servicename. Else returns False."""
    properties = set()
    microservice = [False, False]

    path = os.path.dirname(pom_path)
    local_repo_path = tmp.tmp_config["Repository"]["local_path"]

    dirs = [os.scandir(os.path.join(local_repo_path, path))]
    while dirs:
        dir = dirs.pop()
        for entry in dir:
            if entry.is_file() and "test" not in entry.path:
                filename = os.path.basename(entry.path)
                new_microservice, new_properties = None, None
                if filename in ["application.properties", "bootstrap.properties"]:
                    logger.info(f"Found application.properties here: {entry.path}")
                    new_microservice, new_properties = parse.parse_properties_file(entry.path)
                elif filename in ["application.yaml", "application.yml", "bootstrap.yml", "bootstrap.yaml",
                                  "filebeat.yml", "filebeat.yaml"]:
                    logger.info(f"Found properties file here: {entry.path}")
                    new_microservice, new_properties = parse.parse_yaml_file(entry.path)

                if new_microservice and new_microservice[0]:
                    microservice = new_microservice
                if new_properties:
                    properties |= new_properties
            elif entry.is_dir():
                dirs.append(os.scandir(entry.path))

    return microservice, properties


def extract_servicename_pom_file(pom_file) -> str:
    """Extracts the name of a Maven-module based on the <finalName> tag if existing, else the <artifactId>."""
    local_path = os.path.join(tmp.tmp_config.get("Repository", "local_path"), pom_file["path"])
    _, props = resolve_pom(local_path)

    microservice = [False, False]
    root = parse_pom_file_once(local_path)
    if root is None:
        return microservice

    artifactId = get_artifact_or_final_name(root)
    if artifactId is None:
        return microservice

    text = artifactId.text.strip()
    microservice[0] = substitute(text, props) if "$" in text else text

    # tracing
    file_name = pom_file["path"]
    if XML_BACKEND == "LXML":
        line_nr = artifactId.sourceline - 1
        line = pom_file["content"][line_nr]
        try:
            length_tuple = re.search(microservice[0], line).span()
            span = f"[{length_tuple[0]}:{length_tuple[1]}]"
        except Exception:
            span = "None"
    else:
        line_nr, span = None, "[?:?]"
    trace = (file_name, line_nr, span)

    microservice[0] = f"pom_{microservice[0]}"
    microservice[1] = trace
    return microservice


def detect_microservice(file_path, dfd):
    """Detects which microservice a file belongs to by looking for next pom.xml."""
    microservice = [False, False]
    microservices = tech_sw.get_microservices(dfd)

    found_pom = False
    pom_path = None
    local_repo_path = tmp.tmp_config["Repository"]["local_path"]
    path = os.path.dirname(file_path)

    while not found_pom:
        try:
            with os.scandir(os.path.join(local_repo_path, path)) as entries:
                for entry in entries:
                    if entry.is_file() and entry.name.casefold() == "pom.xml":
                        pom_path = os.path.relpath(entry.path, start=local_repo_path)
                        logger.info(f"Found pom.xml here: {entry.path}")
                        found_pom = True
                        break
        except FileNotFoundError:
            break

        if found_pom:
            break

        # Remonter d'un niveau
        parent_path = os.path.dirname(path)
        if parent_path == local_repo_path or parent_path == path:  # racine ?
            break
        path = parent_path


    if found_pom:
        pom_file = {"path": pom_path}
        for m in microservices.keys():
            try:
                if microservices[m]["pom_path"] == pom_path:
                    microservice[0] = microservices[m]["name"]
            except Exception:
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
            except Exception:
                pass

    return microservice[0]
