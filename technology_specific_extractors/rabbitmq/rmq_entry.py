import ast
import re

import yaml

import core.file_interaction as fi
import core.technology_switch as tech_sw
import tmp.tmp as tmp
import output_generators.traceability as traceability
from output_generators.logger import logger


def set_information_flows(dfd) -> set:
    """Connects incoming endpoints, outgoing endpoints, and routings to information flows
    """

    if not used_in_application():
        return

    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])
    else:
        information_flows = dict()

    new_information_flows = dict()

    routings = get_routings()
    incoming_endpoints = get_incoming_endpoints(dfd)
    outgoing_endpoints = get_outgoing_endpoints(routings, dfd)
    new_information_flows = match_incoming_to_outgoing_endpoints(incoming_endpoints, outgoing_endpoints, dfd)

    # merge old and new flows
    for ni in new_information_flows.keys():
        key = max(information_flows.keys(), default=-1) + 1
        information_flows[key] = new_information_flows[ni]

    tmp.tmp_config.set("DFD", "information_flows", str(information_flows).replace("%", "%%"))
    return information_flows


def used_in_application():
    return len(fi.search_keywords("RabbitTemplate", file_extension=["*.java", "*.kt"])) > 0


def get_routings() -> set:
    """Finds routings defined via RabbitListenerConfigurer
    """

    routings = set()
    files = fi.search_keywords("@RabbitListenerConfigurer", file_extension=["*.java", "*.kt"])
    for file in files.keys():
        f = files[file]
        for line in range(len(f["content"])):
            if "RabbitListenerConfigurer" in f["content"][line]:
                line_in_configurer = line
                while "}" not in f["content"][line_in_configurer]:
                    line_in_configurer += 1
                    if "exchangeName" in f["content"][line_in_configurer]:
                        exchange = f["content"][line_in_configurer].split("exchangeName")[1].split(";")[0].strip().strip("=").strip().strip("\"")
                    if "routingKeyName" in f["content"][line_in_configurer]:
                        routingKey = f["content"][line_in_configurer].split("routingKeyName")[1].split(";")[0].strip().strip("=").strip().strip("\"")
                routings.add((exchange, routingKey))
    return routings


def get_incoming_endpoints(dfd) -> set:
    """Finds Incoming queues, i.e. instances of RabbitListener
    """

    files = fi.search_keywords("@RabbitListener", file_extension=["*.java", "*.kt"])
    incoming_queues = set()
    for file in files.keys():
        f = files[file]
        if "README" not in f["name"]:
            microservice = tech_sw.detect_microservice(f["path"], dfd)
            
            for line in range(len(f["content"])):
                l = f["content"][line]
                if all(exp in l for exp in ["@RabbitListener", "queues", "="]):
                    new_incoming_queue = f["content"][line].split("queues")[1].split("=")[1].strip().strip(")")
                    new_incoming_queue = fi.find_variable(new_incoming_queue, f)

                    span = re.search("@RabbitListener", f["content"][line])
                    trace = (f["name"], line, span)

                    incoming_queues.add((new_incoming_queue, microservice, trace))
    return incoming_queues


def get_outgoing_endpoints(routings: set, dfd) -> set:
    """Finds points where messages are sent to exchanges via rabbitTemplate.exchange
    """
    
    outgoing_endpoints = set()
    sending_commands = ["convertAndSend", "convertSendAndReceive", "convertSendAndReceiveAsType", "doSend", "doSendAndReceive", "doSendAndReceiveWithFixed", "doSendAndReceiveWithTemporary", "send", "sendAndReceive"]
    rabbitTemplates = fi.find_instances("RabbitTemplate")
    
    for template in rabbitTemplates:
        for command in sending_commands:
            files = fi.search_keywords(f"{template}.{command}", file_extension=["*.java", "*.kt"])
            for file in files.keys():
                f = files[file]
                if "README" not in f["name"]:
                    microservice = tech_sw.detect_microservice(f["path"], dfd)
                    for line in range(len(f["content"])):
                        line_content = f["content"][line]
                        if (f"rabbitTemplate.{command}") in line_content: #found correct (starting) line
                            exchange, routingKey = None, None
                            complete_command = line_content
                            if ";" not in complete_command:   # i.e., multi-line command -> search for next line with a semicolon
                                # TODO: also need to increment line ?
                                for i in range(line+1, len(f["content"])):
                                    complete_command += f["content"][i]
                                    if ";" in complete_command:
                                        break
                            
                            parameters = "".join(complete_command.split(command)[1]).split(",")
                            for p in range(len(parameters)): #strip and find correct variables
                                parameters[p] = parameters[p].strip().strip(";").strip().strip(")").strip().strip("(").strip()
                                parameters[p] = fi.find_variable(parameters[p], f)
                            
                            for i in range(len(parameters)):
                                for r in routings:
                                    if r[0] in parameters[i] or parameters[i] in r[0]:
                                        try:
                                            exchange = parameters[i]
                                            routingKey = parameters[i + 1]
                                        except Exception:
                                            print("\033[91mCould not extract exchange and routing key from sending-statement\033[0m")
                                        break

                            span = re.search(f"rabbitTemplate.{command}", line_content)
                            trace = (f["name"], line, span)

                            outgoing_endpoints.add((exchange, routingKey, microservice, trace))
    return outgoing_endpoints


def match_incoming_to_outgoing_endpoints(incoming_endpoints: set, outgoing_endpoints: set, dfd) -> dict:
    """Finds information flows by regexing routing keys of outgoing endpoints to queues of incoming endpoints.
    """
    
    # outgoing: (exchange, routingkey, microservice, (file, line, span))
    # incoming: (queue, microservice, (file, line, span))

    information_flows = dict()
    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])
    
    
    microservices = tech_sw.get_microservices(dfd)
    rabbit_server = False
    for m in microservices.keys():
        if ("Message Broker", "RabbitMQ") in microservices[m]["tagged_values"]:
            rabbit_server = microservices[m]["name"]
            rabbit_id = m

    if rabbit_server:
        for i in incoming_endpoints:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": rabbit_server,
                "receiver": i[1],
                "stereotype_instances": ["restful_http", "message_consumer_rabbitmq"],
                "tagged_values": [("Queue", str(i[0]))]
            }

            # Traceability
            traceability.add_trace({
                "item": f"{rabbit_server} -> {i[1]}",
                "file": i[2][0],
                "line": i[2][1],
                "span": i[2][2]
            })
            traceability.add_trace({
                "parent_item": f"{rabbit_server} -> {i[1]}",
                "item": "message_consumer_rabbitmq",
                "file": i[2][0],
                "line": i[2][1],
                "span": i[2][2]
            })

        for o in outgoing_endpoints:
            username, password, plaintext_credentials = False, False, False
            for m in microservices.values():
                if m["name"] == o[2]  and  "properties" in m:
                    for prop in m["properties"]:
                        if prop[0] == "rabbit_username":
                            username = prop[1]
                            plaintext_credentials = True
                            microservices[rabbit_id].setdefault("stereotype_instances",[]).append("plaintext_credentials")
                            microservices[rabbit_id].setdefault("tagged_values",[]).append(("Username", username))

                        elif prop[0] == "rabbit_password":
                            password = prop[1]
                            plaintext_credentials = True
                            microservices[rabbit_id].setdefault("stereotype_instances",[]).append("plaintext_credentials")
                            microservices[rabbit_id].setdefault("tagged_values",[]).append(("Password", password))

            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": o[2],
                "receiver": rabbit_server,
                "stereotype_instances": ["restful_http", "message_producer_rabbitmq"],
                "tagged_values": [("Producer Exchange", str(o[0])), ("Routing Key", str(o[1]))]
            }
            if plaintext_credentials:
                information_flows[key]["stereotype_instances"].append("plaintext_credentials_link")

            # Traceability
            traceability.add_trace({
                "item": f"{o[2]} -> {rabbit_server}",
                "file": o[3][0],
                "line": o[3][1],
                "span": o[3][2]
            })
            traceability.add_trace({
                "parent_item": f"{o[2]} -> {rabbit_server}",
                "item": "message_producer_rabbitmq",
                "file": o[3][0],
                "line": o[3][1],
                "span": o[3][2]
            })

    else:
        information_flows_set = set()
        information_flows = dict()
        for o in outgoing_endpoints:
            try:
                regex = re.compile(o[1])
                for i in incoming_endpoints:
                    if re.search(regex, i[0]):
                        information_flows_set.add((o[2], i[1], o[0], i[0], o[1], i[2], o[3]))
            except (TypeError, re.error) as e:
                logger.info(f"Error in regex compiling {o[1]}: {e}")
        
        for i in information_flows_set:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": i[0],
                "receiver": i[1],
                "exchange": i[2],
                "queue": i[3],
                "stereotype_instances": ["message_producer_rabbitmq"],
                "tagged_values": {"Producer Exchange": i[2], "Queue": i[3], "Routing Key": i[4]}
            }

            # Traceability
            traceability.add_trace({
                "item": f"{i[0]} -> {i[1]}",
                "file": i[4][0],
                "line": i[4][1],
                "span": i[4][2]
            })
            ## Twice because there are two evidences
            traceability.add_trace({
                "item": f"{i[0]} -> {i[1]}",
                "file": i[5][0],
                "line": i[5][1],
                "span": i[5][2]
            })

    tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))
    return information_flows


def detect_rabbitmq_server(microservices: dict) -> dict:
    """Detects RabbitMQ server.
    """

    possible_filenames = ["docker-compose.yml", "docker-compose.yaml", "docker-compose*"]
    raw_files = ""
    for filename in possible_filenames:
        raw_files = fi.get_file_as_yaml(filename)
        if raw_files:
            break

    if len(raw_files) == 0:
        return microservices

    try:
        file = yaml.load(raw_files[0]["content"], Loader=yaml.FullLoader)
    except yaml.YAMLError as e:
        print(f"\033[91mERROR extracting microservice from docker-compose file : {raw_files[0]["path"]}\033[0m")
        return microservices
    
    
    if "services" in file.keys():
        for s in file.get("services"):
            try: image = file.get("services", {}).get(s).get("image")
            except Exception: pass
            try: build = file.get("services", {}).get(s).get("build")
            except Exception: pass
            
            image = image or "/"
            build = build or ""
            
            if "rabbitmq:" in image.split("/")[-1] or "rabbitmq" in build or "rabbit-mq" in build:
                for m in microservices.values():
                    if m["name"] == s:
                        tag_service_with_rabbitQM(m,"heuristic, based on image in Docker Compose")
    else:
        for s in file.keys():
            try: image = file.get(s).get("image")
            except Exception: pass
            try: build = file.get(s).get("build")
            except Exception: pass
            
            image = image or "/"
            build = build or ""
            
            if "rabbitmq:" in image.split("/")[-1] or "rabbitmq" in build or "rabbit-mq" in build:
                for m in microservices.values():
                    if m["name"] == s:
                        tag_service_with_rabbitQM(m, "heuristic")

    return microservices


def tag_service_with_rabbitQM(m: dict, message: str):
    """Tags a microservice as a RabbitMQ message broker.
    Adds the 'message_broker' stereotype and RabbitMQ tagged value to the microservice, and records traceability information.
    """
    
    m["stereotype_instances"].append("message_broker")
    m["tagged_values"].append(("Message Broker", "RabbitMQ"))

    traceability.add_trace({
        "parent_item": m["name"],
        "item": "message_broker",
        "file": message,
        "line": message,
        "span": message
    })