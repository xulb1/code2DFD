import ast
import re
import os
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
    print("################ Resolve Kafka Relations (Topic) #################")
    information_flows = dict()
    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])

    microservices = tech_sw.get_microservices(dfd)

    incoming_endpoints = get_incoming_endpoints(dfd)
    outgoing_endpoints = get_outgoing_endpoints(dfd)
    if incoming_endpoints or outgoing_endpoints:
        print("((((((((((((((((((((((((((()))))))))))))))))))))))))))")
        print("in:",incoming_endpoints)
        print("out:",outgoing_endpoints)
    new_information_flows = match_incoming_to_outgoing_endpoints(microservices, incoming_endpoints, outgoing_endpoints)

    # merge old and new flows
    for ni in new_information_flows.keys():
        key = max(information_flows.keys(), default=-1) + 1
        information_flows[key] = new_information_flows[ni]

    information_flows = detect_stream_binders(microservices, information_flows, dfd)

    tmp.tmp_config.set("DFD", "information_flows", str(information_flows).replace("%", "%%"))

    return information_flows

def load_kafka_placeholders(root_dir=None) -> dict:
    """Load Kafka topic placeholders from YAML/properties files."""
    repo_folder = tmp.tmp_config["Repository"]["local_path"]
    if root_dir and repo_folder not in root_dir:
        root_dir = f"{repo_folder}/{root_dir.strip("/")}"
    else:
        root_dir = repo_folder
    # easier :   
    # if root_dir:
    #     repo_folder = os.path.join(repo_folder, root_dir)
    
    placeholders = {}
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            if fname.endswith((".yml", ".yaml", ".properties")):
                filepath = os.path.join(dirpath, fname)
                placeholders.update(parse_yaml_properties(filepath))
    return placeholders

def resolve_placeholder(value, placeholders) -> str:
    """Replace ${...} by real values from placeholders."""
    if not value or not isinstance(value, str):
        return value
    pattern = re.compile(r"\$\{(.+?)\}")
    return pattern.sub(lambda m: str(placeholders.get(m.group(1), m.group(0))), value)

def extract_topics_from_annotation(line, content, line_nr) -> list:
    """Extract topics from KafkaListener/StreamListener/SendTo annotation."""
    if "topics" not in line and "@SendTo" not in line:
        return []
            
    annotation_content = line.strip()
    i = line_nr + 1
    while "(" in annotation_content and ")" not in annotation_content and i < len(content):
        annotation_content += content[i].strip()
        i += 1
    
    m = re.search(
        r'topics\s*=\s*(\{[^}]*\}|\"[^\"]*\"|\'[^\']*\')|@SendTo\s*\(\s*(.*?)\s*\)',
        annotation_content,
        re.DOTALL
    )
    if not m:
        return []
    
    topics_str = m.group(1) or m.group(2) or ""
    topics_str = topics_str.strip(" {}")
    
    if not topics_str:
        return []

    topics = [t.strip().strip('"').strip("'") for t in topics_str.split(",")]
    
    return topics

def get_multiline_call(content, start_line) -> str:
    """Return the complete multi-line call starting from start_line until semicolon."""
    complete = content[start_line].strip()
    i = start_line + 1
    while ";" not in complete and i < len(content):
        complete += content[i].strip()
        i += 1
    return complete

def is_list(variable: str) -> bool:
    try:
        value = ast.literal_eval(variable)
        return isinstance(value, (list, set, tuple))
    except Exception:
        return False

def resolve_topic(expr: str, file, placeholders: dict, class_vars: dict) -> str:
    """
    Résout un topic Kafka depuis une expression
    """
    if not expr:
        return None

    expr = expr.strip('"').strip("'").strip()

    if expr in class_vars:
        return class_vars[expr]

    resolved = fi.find_variable(expr, file)
    if resolved:
        return resolve_placeholder(resolved, placeholders)

    return resolve_placeholder(expr, placeholders)

def get_incoming_endpoints(dfd) -> set:
    """Finds all Kafka consumers via @KafkaListener or @StreamListener."""
    incoming_endpoints = set()
    placeholders = load_kafka_placeholders()
    files = fi.search_keywords(["@KafkaListener", "@StreamListener"], file_extension=["*.java", "*.kt", "*.scala"])

    for fpath, file in files.items():
        microservice = tech_sw.detect_microservice(file["path"], dfd)

        # ---- 0. Mapping des variables injectées via @Value ----
        class_vars = {}
        for line in file["content"]:
            m = re.search(
                r'@Value\("(\$\{.+?\})"\)\s*(?:private|final)?\s*(?:[\w<>]+)?\s*(\w+)',
                line
            )
            if m:
                placeholder, varname = m.groups()
                class_vars[varname] = resolve_placeholder(placeholder, placeholders)

        # ---- 1. Annotations KafkaListener / StreamListener ----
        for line_idx, line in enumerate(file["content"]):
            for annotation in ["@KafkaListener", "@StreamListener"]:
                if annotation not in line:
                    continue

                topics = extract_topics_from_annotation(line, file["content"], line_idx)
                for t in topics:
                    # Résolution : variable locale, variable injectée ou placeholder
                    topic_resolved = resolve_topic(t, file, placeholders, class_vars)
                    span = re.search(annotation, line)
                    trace = (file["path"], line_idx+1, span)
                    incoming_endpoints.add((topic_resolved, microservice, trace))

    return incoming_endpoints

def get_outgoing_endpoints(dfd) -> set:
    """Find all Kafka producers via KafkaTemplate.send or @SendTo annotations."""
    outgoing_endpoints = set()
    placeholders = load_kafka_placeholders()
    kafkatemplates = fi.find_instances("KafkaTemplate")

    # 1. KafkaTemplate.send(
    for template in kafkatemplates:
        files = fi.search_keywords(f"{template}.send", file_extension=["*.java", "*.kt", "*.scala"])
        for fpath, file in files.items():
            # print(fpath)
            microservice = tech_sw.detect_microservice(file["path"], dfd)

            # 0. Mapping des variables injectées via @Value
            class_vars = {}
            for line in file["content"]:
                m = re.search(
                    r'@Value\("(\$\{.+?\})"\)\s*(?:private|final)?\s*(?:[\w<>]+)?\s*(\w+)',
                    line
                )
                if m:
                    placeholder, varname = m.groups()
                    class_vars[varname] = resolve_placeholder(placeholder, placeholders)

            for line_idx, line in enumerate(file["content"]):
                if f"{template}.send" not in line:
                    continue

                complete_call = get_multiline_call(file["content"], line_idx)

                # Regex pour extraire le 1er argument (topic)
                m = re.search(rf"{re.escape(template)}\.send\s*\(\s*([^,\s)]+)", complete_call)
                if not m:
                    continue

                topic_expr = m.group(1).strip()
                topic = resolve_topic(topic_expr, file, placeholders, class_vars)

                # Extraction du payload
                asset = extract_asset(complete_call)
                if asset and asset_is_input(asset, file, line_idx):
                    asset = f"Function input {asset}"
                elif asset:
                    asset = fi.find_variable(asset, file) or asset
                # print(asset,"------------=============-==========")
                span = re.search(rf"{re.escape(template)}\.send", line)
                trace = (fpath, line_idx, span)
                outgoing_endpoints.add((topic, microservice, asset, trace))

    # 2. Détection des annotations @SendTo
    files = fi.search_keywords("@SendTo", file_extension=["*.java", "*.kt", "*.scala"])
    for fpath, file in files.items():
        microservice = tech_sw.detect_microservice(file["path"], dfd)
        # Mapping des variables injectées via @Value
        class_vars = {}
        for line in file["content"]:
            m = re.search(
                r'@Value\("(\$\{.+?\})"\)\s*(?:private|final)?\s*(?:[\w<>]+)?\s*(\w+)',
                line
            )
            if m:
                placeholder, varname = m.groups()
                class_vars[varname] = resolve_placeholder(placeholder, placeholders)

        for line_idx, line in enumerate(file["content"]):
            if "@SendTo" not in line:
                continue

            topics = extract_topics_from_annotation(line, file["content"], line_idx)
            for t in topics:
                topic_resolved = resolve_topic(t, file, placeholders,class_vars)
                span = re.search("@SendTo", line)
                trace = (file["path"], line_idx, span)
                outgoing_endpoints.add((topic_resolved, microservice, "", trace))

    return outgoing_endpoints

def get_incoming_endpoints_v1(dfd) -> set:
    """Finds all Kafka consumers via @KafkaListener or @StreamListener."""
    files = fi.search_keywords(["@KafkaListener", "@StreamListener"], file_extension=["*.java", "*.kt", "*.scala"])
    placeholder_map = load_kafka_placeholders()
    incoming_endpoints = set()
    for _, f in files.items():
        incoming_endpoints.update(extract_kafka_endpoints(f, dfd, placeholder_map, endpoint_type="consumer"))
    
    return incoming_endpoints

def get_outgoing_endpoints_v1(dfd) -> set:
    """Find all Kafka producers via KafkaTemplate.send or @SendTo annotations."""
    outgoing_endpoints = set()
    placeholders = load_kafka_placeholders()
    kafkatemplates = fi.find_instances("KafkaTemplate")

    # ---- 1. KafkaTemplate.send(...) ----
    for template in kafkatemplates:
        files = fi.search_keywords(f"{template}.send", file_extension=["*.java", "*.kt", "*.scala"])
        for fpath, file in files.items():
            microservice = tech_sw.detect_microservice(file["path"], dfd)

            for line_idx, line in enumerate(file["content"]):
                if f"{template}.send" not in line:
                    continue

                # Reconstitue tout l'appel multi-lignes
                complete_call = get_multiline_call(file["content"], line_idx)

                # Regex plus robuste pour extraire le 1er argument de send(...)
                m = re.search(rf"{re.escape(template)}\.send\s*\(\s*([^,\s)]+)", complete_call)
                if not m:
                    continue

                topic_expr = m.group(1).strip()
                # Résolution de la variable ou du placeholder
                topic = fi.find_variable(topic_expr, file) or topic_expr
                topic = resolve_placeholder(topic, placeholders)

                # Extraction de la donnée envoyée (payload)
                asset = extract_asset(complete_call)
                if asset and asset_is_input(asset, file, line_idx):
                    asset = f"Function input {asset}"
                elif asset:
                    asset = fi.find_variable(asset, file) or asset

                # Trace pour la traçabilité
                span = re.search(rf"{re.escape(template)}\.send", line)
                trace = (fpath, line_idx, span)
                outgoing_endpoints.add((topic, microservice, "producer", asset, trace))
    # ---- 2. Détection des annotations @SendTo ----
    files = fi.search_keywords("@SendTo", file_extension=["*.java", "*.kt", "*.scala"])
    for fpath, f in files.items():
        outgoing_endpoints.update(
            extract_kafka_endpoints(f, dfd, placeholders, endpoint_type="producer")
        )

    return outgoing_endpoints

def extract_kafka_endpoints_v0(file, dfd, placeholders, endpoint_type="both") -> set:
    """
    Extract Kafka endpoints from a Java file.

    Returns a set of tuples:
        (topic, microservice, type, filepath, line_nr, span)
    """
    endpoints = set()
    microservice = tech_sw.detect_microservice(file["path"], dfd)
    class_vars = {}

    # 1. Détecter variables @Value("${...}")
    for line_nr, line in enumerate(file["content"]):
        m = re.search(
            r'@Value\("(\$\{.+?\})"\)\s*(?:private|final)?\s*(?:[\w<>]+)?\s*(\w+)',
            line
        )
        if m:
            placeholder, varname = m.groups()
            class_vars[varname] = resolve_placeholder(placeholder, placeholders)

    # 2. Consumers (@KafkaListener, @StreamListener)
    if endpoint_type in ("consumer", "both"):
        for line_nr, line in enumerate(file["content"]):
            for annotation in ["@KafkaListener", "@StreamListener"]:
                if annotation in line:
                    topics = extract_topics_from_annotation(line, file["content"], line_nr)
                    for t in topics:
                        topic_resolved = resolve_placeholder(t, placeholders)
                        span = re.search(annotation, line)
                        endpoints.add((topic_resolved, microservice, "consumer", file["path"], line_nr, span))

    # 3. Producers (@SendTo + KafkaTemplate.send)
    if endpoint_type in ("producer", "both"):
        for line_nr, line in enumerate(file["content"]):
            # @SendTo
            if "@SendTo" in line:
                topics = extract_topics_from_annotation(line, file["content"], line_nr)
                for t in topics:
                    topic_resolved = resolve_placeholder(t, placeholders)
                    span = re.search("@SendTo", line)
                    endpoints.add((topic_resolved, microservice, "producer", file["path"], line_nr, span))

            # KafkaTemplate.send
            if ".send(" in line:
                complete_call = get_multiline_call(file["content"], line_nr)
                m = re.search(r"\.send\s*\(\s*([^\s,]+)", complete_call)
                if m:
                    arg = m.group(1)
                    topic = class_vars.get(arg) or resolve_placeholder(arg.strip('"').strip("'"), placeholders)
                    asset = extract_asset(complete_call)
                    if asset_is_input(asset, file, line_nr):
                        asset = f"Function input {asset}"
                    else:
                        asset = fi.find_variable(asset, file)

                    span = re.search(r"\.send", line)
                    endpoints.add((topic, microservice, "producer", file["path"], line_nr, span))

    return endpoints


def extract_asset(call_line: str) -> str:
    """Takes a code line that sends via KafkaTemplate and extracts the asset.
    """
    try:
        arguments = call_line.split("send")[1].split(";")[0].strip()[1:-1].split(",")
        if len(arguments) > 1:
            return arguments[-1].strip()
    except Exception:
        pass
    return ""


def asset_is_input(variable: str, file, line_nr: int) -> bool:
    """Detect if a variable is a function input."""
    open_curly = 0
    while open_curly != 1 and line_nr > 0:
        line = file["content"][line_nr]
        open_curly += line.count("{")
        open_curly -= line.count("}")
        if open_curly == 1 and not any(kw in line for kw in ["if", "else", "else if"]):
            inputs = line.split("{")[0].strip().split("(")[-1].strip().strip(")").strip().split(",")
            if variable in inputs:
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
        if ("Message Broker", "Kafka") in m.get("tagged_values",[]):
            kafka_server = m["name"]
            break

    if kafka_server:
        for topic, consumer_ms, trace in incoming_endpoints:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": kafka_server,
                "receiver": consumer_ms,
                "stereotype_instances": ["message_consumer_kafka", "restful_http"],
                "tagged_values": [("Consumer Topic", str(topic))]
            }

            # Traceability
            traceability.add_trace({
                "parent_item": f"{kafka_server} -> {consumer_ms}",
                "item": "message_consumer_kafka",
                "file": trace[0],
                "line": trace[1],
                "span": trace[2]
            })

        for topic, producer_ms, _, trace in outgoing_endpoints:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": producer_ms,
                "receiver": kafka_server,
                "stereotype_instances": ["message_producer_kafka", "restful_http"],
                "tagged_values": [("Producer Topic", str(topic))]
            }

            # Traceability
            traceability.add_trace({
                "parent_item": f"{producer_ms} -> {kafka_server}",
                "item": "message_producer_kafka",
                "file": trace[0],
                "line": trace[1],
                "span": trace[2]
            })

    else:
        information_flows_set = set()
        for topic_i, consumer_ms, trace_i in incoming_endpoints:
            if not topic_i:
                continue
            try:
                regex = re.compile(str(topic_i))
                for topic_o, producer_ms, asset, trace_o in outgoing_endpoints:
                    if not topic_o:
                        continue
                    if re.search(regex, str(topic_o)):
                        information_flows_set.add((producer_ms, consumer_ms, topic_i, asset, trace_o, trace_i))
            except (TypeError, re.error) as e:
                logger.info(f"Error in regex compiling {topic_i} or {topic_o}: {e}")

        # this next block is because i don't know if one can put regex as topic when sending as well. Since it's a set, this doesn't hurt
        for topic_o, producer_ms, asset, trace_o in outgoing_endpoints:
            if not topic_o:
                continue
            try:
                regex = re.compile(str(topic_o))
                for topic_i, consumer_ms, trace_i in incoming_endpoints:
                    if re.search(regex, str(topic_i)):
                        information_flows_set.add((producer_ms, consumer_ms, topic_i, asset, trace_o, trace_i))
            except (TypeError, re.error) as e:
                logger.info(f"Error in regex compiling {topic_o} or {topic_i}: {e}")

        # turn it into a dictionary
        for producer_ms, consumer_ms, topic_i, asset, trace_o, trace_i in information_flows_set:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": producer_ms,
                "receiver": consumer_ms,
                "topic": topic,
                "asset": asset
            }

            # Traceability
            for fpath, line_nr, span in [trace_o, trace_i]:
                traceability.add_trace({
                    "item": f"{producer_ms} -> {consumer_ms}",
                    "file": fpath,
                    "line": line_nr,
                    "span": span
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
    
    try:
        file = yaml.load(raw_files[0]["content"], Loader=yaml.FullLoader)
    except yaml.YAMLError as e:
        print(f"\033[91mERROR extracting microservice from docker-compose file : {raw_files[0]["path"]}\033[0m")
        return microservices

    if "services" in file:
        for s in file.get("services"):
            try:
                image = file.get("services", {}).get(s).get("image")
                microservices = check_and_tag_kafka_microservice(image, s, microservices)
            except Exception:
                continue
    else:
        for s in file.keys():
            try:
                image = file.get(s).get("image")
                microservices = check_and_tag_kafka_microservice(image, s, microservices)
            except Exception:
                continue
    return microservices

def check_and_tag_kafka_microservice(image, s, microservices: dict) -> dict:
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
    
    results = fi.search_keywords(keyword, file_extension=["*.java", "*.kt", "*.scala"])
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


def parse_yaml_properties(filepath) -> dict:
    topics = {}
    if filepath.endswith((".yml", ".yaml")):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
                if config:
                    def extract(d, prefix=""):
                        for k, v in d.items():
                            key = f"{prefix}.{k}" if prefix else k
                            if isinstance(v, dict):
                                extract(v, key)
                            elif "topic" in key.lower():
                                topics[key] = v
                    extract(config)
        except Exception as e:
            logger.info(f"YAML parse error {filepath}: {e}")
    
    elif filepath.endswith(".properties"):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        if "topic" in k.lower():
                            topics[k.strip()] = v.strip()
        except Exception as e:
            logger.info(f"Properties parse error {filepath}: {e}")
    return topics


# # Regex patterns
# KAFKA_LISTENER_PATTERN = re.compile(r'@KafkaListener\s*\(.*topics\s*=\s*"?\{?([^"}]+)\}?')
# KAFKA_SEND_PATTERN = re.compile(r'kafkaTemplate\.send\s*\(\s*"([^"]+)"')
# KAFKA_STREAM_PATTERN = re.compile(r'builder\.(stream|table)\s*\(\s*"([^"]+)"')
# VALUE_PATTERN = re.compile(r'@Value\s*\(\s*"\$\{([^}]+)\}"\s*\)')




def get_incoming_endpoints_v0(dfd) -> set:
    """Finds incoming streams, i.e. instances of KafkaListener
    """

    listening_topics = set()
    files = fi.search_keywords("@KafkaListener", file_extension=["*.java", "*.kt", "*.scala"])

    for f in files.keys():
        file = files[f]
        
        for line in range(len(file["content"])):
            if "@KafkaListener" in file["content"][line] and "topics" in file["content"][line]:
                new_listening_topic = file["content"][line].split("topics")[1]
                if "," in new_listening_topic:
                    new_listening_topic = new_listening_topic.split(",")[0]
                new_listening_topic = new_listening_topic.strip().strip("=").strip(")").strip()

                if is_list(new_listening_topic):
                    new_listening_topics = ast.literal_eval(new_listening_topic)
                    for topic in new_listening_topics:
                        new_listening_topic = fi.find_variable(topic, f)
                        microservice = tech_sw.detect_microservice(file["path"], dfd)
                        listening_topics.add((new_listening_topic, microservice))
                else:
                    new_listening_topic = fi.find_variable(new_listening_topic, f)
                    microservice = tech_sw.detect_microservice(file["path"], dfd)

                    span = re.search("@KafkaListener", file["content"][line])
                    trace = (file["name"], line, span)
                    listening_topics.add((new_listening_topic, microservice, trace))
    
    return listening_topics

def get_outgoing_endpoints_v0(dfd) -> set:
    """Finds points where messages are sent to exchanges via kafkatemplate.send
    """

    kafkatemplates = fi.find_instances("KafkaTemplate")
    commands = ["send"]
    outgoing_endpoints = set()
    asset = str()
    for template in kafkatemplates:
        for command in commands:
            files = fi.search_keywords(f"{template}.{command}", file_extension=["*.java", "*.kt", "*.scala"])
            for file in files.keys():
                f = files[file]
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


# # 
# {('t_notification', 'notification', 'consumer', 'notification/src/main/java/com/sylleryum/notifications/NotificationApplication.java', 25, <re.Match object; span=(4, 18), match='@KafkaListener'>),
#  ('t_order', 'payment', 'consumer', 'payment/src/main/java/com/sylleryum/payment/PaymentApplication.java', 27, <re.Match object; span=(4, 18), match='@KafkaListener'>),
#  ('t_order', 'stock', 'consumer', 'stock/src/main/java/com/sylleryum/stock/StockApplication.java', 40, <re.Match object; span=(4, 18), match='@KafkaListener'>)}

# {('notificationTopic', 'order', 'producer', 'payload', (0, 33, <re.Match object; span=(8, 26), match='kafkaTemplate.send'>)),
#  ('kafkaTopicPayment', 'payment', 'producer', 'payload', (1, 29, <re.Match object; span=(8, 26), match='kafkaTemplate.send'>)),
#  ('kafkaTopicStock', 'stock', 'producer', 'payload', (2, 29, <re.Match object; span=(8, 26), match='kafkaTemplate.send'>)),
#  ('orderTopic', 'order', 'producer', 'payload', (0, 29, <re.Match object; span=(8, 26), match='kafkaTemplate.send'>))}