import ast
import re
from pathlib import Path
import traceback

import ruamel.yaml

import output_generators.traceability as traceability
import technology_specific_extractors.environment_variables as env
import tmp.tmp as tmp


# The following is taken from ruamel.yaml's authro as a workaround for getting line count for str objects
# https://stackoverflow.com/questions/45716281/parsing-yaml-get-line-numbers-even-in-ordered-maps/45717104#45717104
class Str(ruamel.yaml.scalarstring.ScalarString):
    __slots__ = ('lc')

    style = ""

    def __new__(cls, value):
        return ruamel.yaml.scalarstring.ScalarString.__new__(cls, value)

class MyPreservedScalarString(ruamel.yaml.scalarstring.PreservedScalarString):
    __slots__ = ('lc')

class MyDoubleQuotedScalarString(ruamel.yaml.scalarstring.DoubleQuotedScalarString):
    __slots__ = ('lc')

class MySingleQuotedScalarString(ruamel.yaml.scalarstring.SingleQuotedScalarString):
    __slots__ = ('lc')

class MyConstructor(ruamel.yaml.constructor.RoundTripConstructor):
    def construct_scalar(self, node):

        if not isinstance(node, ruamel.yaml.nodes.ScalarNode):
            raise ruamel.yaml.constructor.ConstructorError(
                None, None,
                f"expected a scalar node, but found {node.id}",
                node.start_mark)

        if node.style == '|' and isinstance(node.value, ruamel.yaml.compat.text_type):
            ret_val = MyPreservedScalarString(node.value)
        elif bool(self._preserve_quotes) and isinstance(node.value, ruamel.yaml.compat.text_type):
            if node.style == "'":
                ret_val = MySingleQuotedScalarString(node.value)
            elif node.style == '"':
                ret_val = MyDoubleQuotedScalarString(node.value)
            else:
                ret_val = Str(node.value)
        else:
            ret_val = Str(node.value)
        ret_val.lc = ruamel.yaml.comments.LineCol()
        ret_val.lc.line = node.start_mark.line
        ret_val.lc.col = node.start_mark.column
        return ret_val
# end of external code


def extract_microservices(file_content, file_name) -> set:
    """ Extracts the list of microservices from the docker-compose file autonomously,
    i.e. without asking for user-input in case of errors.
    """

    yaml = ruamel.yaml.YAML()
    yaml.Constructor = MyConstructor

    file = yaml.load(file_content)
    print("===========================================")

    image = False
    build = False
    if tmp.tmp_config.has_option("DFD", "microservices"):
        microservices_dict =  ast.literal_eval(tmp.tmp_config["DFD"]["microservices"])
    else:
        microservices_dict= dict()
    
    microservices_set = set()
    properties_dict = dict()

    if "services" in file.keys():
        print("SERVICES ----------------------------------")
        data  = file.get("services", {})
        
        for s in data:
            print(s)
            microservices_set, microservices_dict = extract_service_from_file(s, file_content,file_name,data, microservices_dict, microservices_set, properties_dict, image, build)
            
    else:
        print("NO SERVICES -------------------------------")
        data = file
        
        for s in file.keys():
            print(s)
            microservices_set, microservices_dict = extract_service_from_file(s, file_content, file_name, data, microservices_dict, microservices_set, properties_dict, image, build)


    tmp.tmp_config.set("DFD", "microservices", str(microservices_dict).replace("%", "%%"))
    return microservices_set, properties_dict


def extract_service_from_file(s, file_content, file_name, data, microservices_dict: dict, microservices_set: set, properties_dict: dict, image=False, build=False) -> tuple[set,dict]:
    properties = set()
    correct_id = False
    exists = False
    port = False

    print("___________________________________")

    # Traceability
    lines = file_content.splitlines()
    line_number = data[s].lc.line - 1
    length_tuple = re.search(s, lines[line_number])
    if length_tuple:
        length_tuple = length_tuple.span()
        span = f"[{str(length_tuple[0])}:{str(length_tuple[1])}]"
        trace = (file_name, line_number + 1, span)


    
    if s == "networks":
        exists = True
    for id_ in microservices_dict:
        if microservices_dict[id_]["name"] == s:
            microservices_dict[id_]["stereotype_instances"].append("isContainerised")
            exists = True
            correct_id = id_

    ports = data.get(s).get("ports")
    if ports :
        portList = []
        for i in range(len(ports)):
            try:
                port_nr = ports[i].split(":")[0].strip("\" -")
            except AttributeError:
                port_nr = str(ports[i])
                
            if type(port_nr) == list:
                port_nr = port_nr[0]
            portList.append(port_nr)
        
        line_number = data[s]["ports"].lc.line - 1
        length_tuple = re.search(portList[0], lines[line_number])
        if not length_tuple:
            line_number = line_number + 1
            length_tuple = re.search(portList[0], lines[line_number])
        length_tuple = length_tuple.span()
        span = f"[{length_tuple[0]}:{length_tuple[1]}]"
        port = (tuple(portList), file_name, line_number + 1, span)
    
    new_image = data.get(s).get("image")
    new_build = data.get(s).get("build")
    if new_image or new_build:
        try:
            new_build = f"{new_build['context']}"
        except TypeError:
            pass
        
        image = new_image
        build = new_build
        
        for m in microservices_dict.values():
            try:
                pom_path = Path(m["pom_path"])
            except KeyError:
                continue
            
            if pom_path:
                if (new_image) and (new_image.split("/")[-1] == pom_path.parts[-2]):
                    exists = True
                    if "pom_" in m["name"]:
                        m["name"] = s
                if (new_build) and (new_build.split("/")[-1] == pom_path.parts[-2]):
                    exists = True
                    if "pom_" in m["name"]:
                        m["name"] = s

    # Environment properties
    try:
        port, properties = extract_environment_props(data, s, lines, port, properties, file_name)
    except Exception:
        print(f"\033[91m")
        traceback.print_exc()
        print("\033[0m")

    # Port via "Expose" (overrules "ports")
    ports = data.get(s).get("expose")
    print("\033[34m",s,ports,"\033[0m")
    if ports:
        port_nr = []
        for i in range(len(ports)):
            port_nr.append(ports[i].split(":")[0].strip("\" -"))
            
        line_number = data[s]["expose"].lc.line - 1
        length_tuple = re.search(port_nr[0], lines[line_number])
        if not length_tuple:
            line_number = line_number + 1
            length_tuple = re.search(port_nr[0], lines[line_number])
        if length_tuple:
            length_tuple = length_tuple.span()
            span = f"[{length_tuple[0]}:{length_tuple[1]}]"
            port = (tuple(port_nr), file_name, line_number + 1, span)
        print("\033[32m",s, port,"\033[0m")


    if not image:
        image = build or "image"

    if not exists:
        # Have to filter here and only add those with a known image.
        # Otherwise, many dublicates will occur when developers call the services different in docker-compose than in Spring.application.name
        known_images = ["elasticsearch","kibana","logstash","grafana","kafka","rabbit","zookeeper","postgres","zipkin","prometheus","mongo","consul","mysql","scope","postgres","apache","nginx"]
        isImage = False
        for ki in known_images:
            if ki in image:
                properties_dict[s] = properties
                microservices_set.add((s, image, "type", port, trace))
                print("\033[31m",s, image, port,"\033[0m")
                isImage=True
                break
        
        if not isImage:
            properties_dict[s] = properties
            microservices_set.add((s, image, "type", port, trace))
            print("\033[31m",s, image, port,"--------->>>>>\033[0m")

    # add additional information
    if exists and correct_id:
        microservices_dict[correct_id].setdefault("properties", set()).update(properties)

    return microservices_set, microservices_dict


# FIXME: detection du même port plusieurs fois -> optimiser
def extract_environment_props(data, s, lines: list, port: tuple, properties: set,file_name: str) -> tuple[tuple,set]:
    """Extracts environment variable properties and port information from a service definition.

    This function scans the environment variables of a given service for database credentials and port settings,
    and adds relevant properties to the provided set along with their file location information.
    """
    value = None # password or username
    environment_entries = data.get(s).get("environment")
    
    if not environment_entries:
        return port, properties
        
    for line_number, entry in enumerate(environment_entries):
        # looking for databases creds : 
        if any(keyword in entry.upper() for keyword in ["USER", "PASS"]) and \
           any(db in entry.upper() for db in ["MONGODB", "MYSQL", "POSTGRES"]):
            value = environment_entries.get(entry)
            line_number = data[s]["environment"][entry].lc.line
            escaped_value = value.replace("$", "\\$")
            escaped_line = lines[line_number].replace("$", "\\$")
            length_tuple = re.search(escaped_value, escaped_line).span()
            span = f"[{length_tuple[0]}:{length_tuple[1]}]"
            if "$" in value:
                value = env.resolve_env_var(value)
            if value != None:
                key_type = "datasource_username" if "USER" in entry.upper() else "datasource_password"
                properties.add((key_type, value, (file_name, line_number + 1, span)))

        # port (kafka) -> KAFKA_ADVERTISED_PORT
        if ("KAFKA" in entry.upper() and
            "PORT"  in entry.upper()):
            port_nr = environment_entries.get(entry)
            line_number = data[s]["environment"].lc.key(entry)[0]
            length_tuple = re.search(str(port_nr), lines[line_number]).span()
            span = f"[{str(length_tuple[0])}:{str(length_tuple[1])}]"
            port = (port_nr, file_name, line_number + 1, span)
        # print(value, port)
    
    return port, properties


def extract_information_flows(file_content:  str, microservices: dict, information_flows: dict) -> dict:
    """Adds information flows based on "links" and on "depends_on".
    """
    
    yaml = ruamel.yaml.YAML()
    yaml.Constructor = MyConstructor

    registry_server, config_server = False, False
    for m in microservices.values():
        if "stereotype_instances" in m:
            if "service_registry" in m["stereotype_instances"]:
                registry_server = m["name"]
            if "configuration_server" in m["stereotype_instances"]:
                config_server = m["name"]

    file = yaml.load(file_content)

    if "services" in file:
        for s in file.get("services"):
            try:
                links = file.get("services", {}).get(s).get("links")
                information_flows = get_flows(s,links, microservices, information_flows, registry_server, config_server)
            except:
                pass
    else:
        for s in file.keys():
            try:
                links = file.get(s).get("links")
                information_flows = get_flows(s,links, microservices, information_flows, registry_server, config_server)
            except:
                pass
    
    if "services" in file:
        for s in file.get("services"):
            try:
                depends_on = file.get("services", {}).get(s).get("depends_on")
                information_flows = get_flows(s,depends_on, microservices, information_flows, registry_server, config_server)
            except:
                pass
    else:
        for s in file.keys():
            try:
                depends_on = file.get(s).get("depends_on")
                information_flows = get_flows(s,depends_on, microservices, information_flows, registry_server, config_server)
            except:
                pass
    
    return information_flows

def get_flows(s: str, links: str, microservices: dict, information_flows: dict, registry_server: bool, config_server: bool) -> dict:
    if not links:
        return information_flows
    
    for link in links:
        for m in microservices.values():
            if  m["name"] == link:
                if link not in {registry_server, config_server}:
                    newKey = max(information_flows.keys(), default=-1) + 1
                    information_flows[newKey] = {
                        "sender": s,
                        "receiver": link,
                        "stereotype_instances": ["restful_http"]
                    }
    
    return information_flows