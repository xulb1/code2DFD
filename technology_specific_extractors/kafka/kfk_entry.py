import ast
import re

import yaml

import core.file_interaction as fi
import core.technology_switch as tech_sw
import tmp.tmp as tmp
import output_generators.traceability as traceability
from output_generators.logger import logger

kafka_server = str()


def set_information_flows(dfd) -> set:
    """Connects incoming endpoints, outgoing endpoints, and routings to information flows
    """

    information_flows = dict()
    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])

    microservices = tech_sw.get_microservices(dfd)

    incoming_endpoints = get_incoming_endpoints(dfd)
    outgoing_endpoints = get_outgoing_endpoints(dfd)
    if incoming_endpoints or outgoing_endpoints:
        print("((((((((((((((((((((((((((()))))))))))))))))))))))))))")
        print("in:",incoming_endpoints)
        print("out:",incoming_endpoints)
    new_information_flows = match_incoming_to_outgoing_endpoints(microservices, incoming_endpoints, outgoing_endpoints)

    # merge old and new flows
    for ni in new_information_flows.keys():
        key = max(information_flows.keys(), default=-1) + 1
        information_flows[key] = new_information_flows[ni]

    information_flows = detect_stream_binders(microservices, information_flows, dfd)

    tmp.tmp_config.set("DFD", "information_flows", str(information_flows).replace("%", "%%"))

    return information_flows


def get_incoming_endpoints(dfd) -> set:
    """Finds incoming streams, i.e. instances of KafkaListener
    """

    listening_topics = set()
    files = fi.search_keywords("@KafkaListener", file_extension=["*.java"])

    for f in files.keys():
        file = files[f]
        if "README" in file["name"]:
            pass
        else:
            for line in range(len(file["content"])):
                if "@KafkaListener" in file["content"][line] and "topics" in file["content"][line]:
                    new_listening_topic = file["content"][line].split("topics")[1]
                    if "," in new_listening_topic:
                        new_listening_topic = new_listening_topic.split(",")[0]
                    new_listening_topic = new_listening_topic.strip().strip("=").strip(")").strip()

                    if is_list(new_listening_topic):
                        new_listening_topics = ast.literal_eval(new_listening_topic)
                        for topic in new_listening_topics:
                            new_listening_topic = fi.find_variable(new_listening_topic, f)
                            microservice = tech_sw.detect_microservice(file["path"], dfd)
                            listening_topics.add((new_listening_topic, microservice))
                    else:
                        new_listening_topic = fi.find_variable(new_listening_topic, f)
                        microservice = tech_sw.detect_microservice(file["path"], dfd)

                        span = re.search("@KafkaListener", file["content"][line])
                        trace = (file["name"], line, span)
                        listening_topics.add((new_listening_topic, microservice, trace))

    return listening_topics


def is_list(variable: str) -> bool:
    var_type = ast.literal_eval(variable)
    
    return var_type in  [set, list, tuple]


def get_outgoing_endpoints(dfd) -> set:
    """Finds points where messages are sent to exchanges via kafkatemplate.send
    """

    kafkatemplates = fi.find_instances("KafkaTemplate")
    commands = ["send"]
    outgoing_endpoints = set()
    asset = str()
    for template in kafkatemplates:
        for command in commands:
            files = fi.search_keywords(f"{template}.{command}", file_extension=["*.java"])
            for file in files.keys():
                f = files[file]
                if "README" not in f["name"]:
                    microservice = tech_sw.detect_microservice(f["path"], dfd)
                    for line in range(len(f["content"])):
                        if (f"{template}.{command}") in f["content"][line]:    #found correct (starting) line
                            topic = str()

                            # look for semicolon indicating end of command -> ´complete_call´ contains whole command
                            complete_call = f["content"][line]
                            if ";" not in f["content"][line]:
                                i = line + 1
                                while i < len(f["content"]):
                                    if ";" in f["content"][i]:
                                        break
                                    complete_call += f["content"][i]
                                    i += 1

                            # extract topic
                            topic = complete_call.split(command)[1].strip().strip("(").split(",")[0].strip()
                            topic = fi.find_variable(topic, f)

                            # extract data / asset
                            asset = extract_asset(complete_call, command)
                            if asset_is_input(asset, f, line):
                                asset = f"Function input {asset}"
                            else:
                                asset = fi.find_variable(asset, f)

                            span = re.search(f"{template}.{command}", f["content"][line])
                            trace = (f["path"], line, span)
                            outgoing_endpoints.add((topic, microservice, asset, trace))

    return outgoing_endpoints


def extract_asset(kafkatemplate_call: str, command: str) -> str:
    """Takes a code line that sends via KafkaTemplate and extracts the asset.
    """

    asset = str()

    if command == "send":
        arguments = kafkatemplate_call.split("send")[1].split(";")[0].strip()[1:-1].split(",")
        if len(arguments) > 1:
            asset = arguments[-1]

    return asset


def asset_is_input(variable: str, file, line_nr: int) -> bool:
    """Detects if a string in a given line is an input parameter.
    """

    open_curly_brackets = 0
    while open_curly_brackets != 1 and line_nr > 0:
        line = file["content"][line_nr]
        if "{" in line:
            open_curly_brackets += 1
        if "}" in line:
            open_curly_brackets -= 1
        if open_curly_brackets == 1:
            if "if" in line or "else" in line or "else if" in line:
                open_curly_brackets -= 1
            else:
                inputs = line.split("{")[0].strip().split("(")[-1].strip().strip(")").strip().split(",")
                for i in inputs:
                    if variable in i:
                        return True
        line_nr -= 1
    return False


def match_incoming_to_outgoing_endpoints(microservices: dict, incoming_endpoints: set, outgoing_endpoints: set) -> dict:
    """Finds information flows by regexing routing keys of outgoing endpoints to queues of incoming endpoints.
    """
    # incoming: (topic, microservice, (file, line, span))
    # outgoing: (topic, microservice, asset, (file, line, span))

    information_flows = dict()
    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])

    kafka_server = False
    for m in microservices.values():
        if ("Message Broker", "Kafka") in m["tagged_values"]:
            kafka_server = m["name"]

    if kafka_server:
        for i in incoming_endpoints:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": kafka_server,
                "receiver": i[1],
                "stereotype_instances": ["message_consumer_kafka", "restful_http"],
                "tagged_values": [("Consumer Topic", str(i[0]))]
            }

            # Traceability
            traceability.add_trace({
                "item": f"{kafka_server} -> {i[1]}",
                "file": i[2][0],
                "line": i[2][1],
                "span": i[2][2]
            })

            traceability.add_trace({
                "parent_item": f"{kafka_server} -> {i[1]}",
                "item": "message_consumer_kafka",
                "file": i[2][0],
                "line": i[2][1],
                "span": i[2][2]
            })

        for o in outgoing_endpoints:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": o[1],
                "receiver": kafka_server,
                "stereotype_instances": ["message_producer_kafka", "restful_http"],
                "tagged_values": [("Producer Topic", str(o[0]))]
            }

            # Traceability
            traceability.add_trace({
                "item": f"{o[1]} -> {kafka_server}",
                "file": o[3][0],
                "line": o[3][1],
                "span": o[3][2]
            })

            traceability.add_trace({
                "parent_item": f"{o[1]} -> {kafka_server}",
                "item": "message_producer_kafka",
                "file": o[3][0],
                "line": o[3][1],
                "span": o[3][2]
            })

    else:
        information_flows_set = set()
        for i in incoming_endpoints:
            try:
                regex = re.compile(i[0])
                for o in outgoing_endpoints:
                    if re.search(regex, o[0]):
                        information_flows_set.add((o[1], i[1], i[0], o[2], i[2], o[3]))
            except (TypeError, re.error) as e:
                logger.info(f"Error in regex compiling {i[0]}: {e}")

        # this next block is because i don't know if one can put regex as topic when sending as well. Since it's a set, this doesn't hurt
        for o in outgoing_endpoints:
            try:
                regex = re.compile(o[0])
                for i in incoming_endpoints:
                    if re.search(regex, i[0]):
                        information_flows_set.add((o[1], i[1], i[0], o[2], i[2], o[3]))
            except (TypeError, re.error) as e:
                logger.info(f"Error in regex compiling {o[0]}: {e}")

        # turn it into a dictionary
        for i in information_flows_set:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": i[0],
                "receiver": i[1],
                "topic": i[2],
                "asset": i[3]
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

    return information_flows


def detect_kafka_server(microservices: dict) -> dict:
    """Detects and marks kafka server.
    """

    global kafka_server

    possible_filenames = ["docker-compose.yml", "docker-compose.yaml", "docker-compose*"]

    for filename in possible_filenames:
        raw_files = fi.get_file_as_yaml(filename)
        if raw_files:
            break
    if len(raw_files) == 0:
        return microservices
    
    file = yaml.load(raw_files[0]["content"], Loader = yaml.FullLoader)

    if "services" in file:
        for s in file.get("services"):
            try:
                image = file.get("services", {}).get(s).get("image")
                microservices = check_and_tag_kafka_microservice(image, microservices)
            except Exception:
                continue
    else:
        for s in file.keys():
            try:
                image = file.get(s).get("image")
                microservices = check_and_tag_kafka_microservice(image, microservices)
            except Exception:
                continue
    return microservices

def check_and_tag_kafka_microservice(image, microservices: dict) -> dict:
    global kafka_server
    
    if "kafka" in image.split("/")[-1].casefold():
        for m in microservices.values():
            if m["name"] == s:
                kafka_server = m["name"]
                m.setdefault("stereotype_instances",[]).append("message_broker")
                m.setdefault("tagged_values",[]).append(("Message Broker", "Kafka"))

                traceability.add_trace({
                    "parent_item": m["name"],
                    "item": "message_broker",
                    "file": "heuristic, based on image in Docker Compose",
                    "line": "heuristic, based on image in Docker Compose",
                    "span": "heuristic, based on image in Docker Compose"
                })
    return microservices


def detect_stream_binders(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects connections to kafka via stream bindings.
    """

    global kafka_server

    for m in microservices.values():
        connected = False
        out_topic = False
        in_topic = False

        for prop in m["properties"]:
            if prop[0] == "kafka_stream_binder" and prop[1] == kafka_server:
                connected = True
            elif prop[0] == "kafka_stream_topic_out":
                out_topic = prop[1]
            elif prop[0] == "kafka_stream_topic_in":
                in_topic = prop[1]

        if connected:
            # Outgoing
            topic = out_topic
            information_flows = add_kafka_information_flow(True, topic, m, information_flows, dfd)

            # Incoming
            topic = in_topic
            information_flows = add_kafka_information_flow(False, topic, m, information_flows, dfd)

    return information_flows


def add_kafka_information_flow(isProducer: bool, topic, m: dict, information_flows: dict, dfd) -> dict:
    """Adds information flow entries for Kafka producer or consumer microservices.

    Depending on whether the microservice is a producer or consumer, this function updates the information flows dictionary with the appropriate sender, receiver, and stereotype information. It also records traceability data for each detected flow.
    """

    if isProducer :
        sender = m["name"]
        receiver = kafka_server
        keyword = "@SendTo"
        texte = "producer"
    else :
        sender = kafka_server
        receiver = m["name"]
        keyword = "@StreamListener"
        texte = "consumer"
    
    results = fi.search_keywords(keyword, file_extension=["*.java"])
    for r in results.keys():
        if tech_sw.detect_microservice(results[r]["path"], dfd) == m["name"]:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": sender,
                "receiver": receiver,
                "stereotype_instances": [f"message_{texte}_kafka", "restful_http"]
            }
            if topic:
                information_flows[key]["tagged_values"] = {(f"{texte.capitalize()} Topic", topic)}

            # Traceability
            traceability.add_trace({
                "item": f"{sender} -> {receiver}",
                "file": results[r]["path"],
                "line": results[r]["line_nr"],
                "span": results[r]["span"]
            })
            
            traceability.add_trace({
                "parent_item": f"{sender} -> {receiver}",
                "item": f"message_{texte}_kafka",
                "file": results[r]["path"],
                "line": results[r]["line_nr"],
                "span": results[r]["span"]
            })
    return information_flows