from itertools import combinations
from pydriller import Repository
from datetime import datetime
import ast
import os

import core.technology_switch as tech_sw
from core.DFD import CDFD

import tmp.tmp as tmp

import output_generators.json_architecture as json_architecture
import output_generators.codeable_model as codeable_model
import output_generators.traceability as traceability
import output_generators.json_mm_arch as json_mm_arch
import output_generators.json_edges as json_edges
import output_generators.visualizer as visualizer
import output_generators.plaintext as plaintext

from technology_specific_extractors.service_functionality_classification.itf_entry import classify_internal_infrastructural
from technology_specific_extractors.repository_rest_resource.rrr_entry import detect_endpoints
from technology_specific_extractors.plaintext_credentials.plc_entry import set_plaintext_credentials
from technology_specific_extractors.database_connections.dbc_entry import clean_database_connections
from technology_specific_extractors.spring_encryption.enc_entry import detect_spring_encryption
from technology_specific_extractors.circuit_breaker.cbr_entry import detect_circuit_breakers
from technology_specific_extractors.spring_gateway.sgt_entry import detect_spring_cloud_gateway
from technology_specific_extractors.http_security.hts_entry import detect_authentication_scopes
from technology_specific_extractors.load_balancer.lob_entry import detect_load_balancers
from technology_specific_extractors.elasticsearch.ela_entry import detect_elasticsearch
from technology_specific_extractors.local_logging.llo_entry import detect_local_logging
from technology_specific_extractors.spring_config.cnf_entry import detect_spring_config
from technology_specific_extractors.apache_httpd.aph_entry import detect_apachehttpd_webserver
from technology_specific_extractors.spring_admin.sad_entry import detect_spring_admin_server
from technology_specific_extractors.spring_oauth.soa_entry import detect_spring_oauth
from technology_specific_extractors.prometheus.prm_entry import detect_prometheus_server
from technology_specific_extractors.databases.dbs_entry import detect_databases
from technology_specific_extractors.zookeeper.zoo_entry import detect_zookeeper
from technology_specific_extractors.rabbitmq.rmq_entry import detect_rabbitmq_server
from technology_specific_extractors.logstash.log_entry import detect_logstash
from technology_specific_extractors.hystrix.hsx_entry import detect_hystrix_circuit_breakers, detect_hystrix_dashboard
from technology_specific_extractors.grafana.grf_entry import detect_grafana
from technology_specific_extractors.turbine.trb_entry import detect_turbine
from technology_specific_extractors.eureka.eur_entry import detect_eureka, detect_eureka_server_only
from technology_specific_extractors.etcd.etcd_entry import detect_etcd
from technology_specific_extractors.ribbon.rib_entry import detect_ribbon_load_balancers
from technology_specific_extractors.zipkin.zip_entry import detect_zipkin_server
from technology_specific_extractors.consul.cns_entry import detect_consul
from technology_specific_extractors.kibana.kib_entry import detect_kibana
from technology_specific_extractors.kafka.kfk_entry import detect_kafka_server
from technology_specific_extractors.nginx.ngn_entry import detect_nginx
from technology_specific_extractors.zuul.zul_entry import detect_zuul
from technology_specific_extractors.ssl.ssl_entry import detect_ssl_services

# R17
from technology_specific_extractors.secure_registry.check_secure_registry_entry import check_registry_security
# R7
from technology_specific_extractors.encrypted_com.external_communication_entry import check_external_encryption
# R8
from technology_specific_extractors.encrypted_com.internal_communication_entry import check_inter_service_encryption


def perform_analysis():
    """
    Entrypoint for the DFD extraction that initializes the repository
    """
    local_path = tmp.tmp_config.get("Repository", "local_path")
    url_path = tmp.tmp_config.get("Repository", "url")

    os.makedirs(local_path, exist_ok=True)
    repository = Repository(path_to_repo=url_path, clone_repo_to=local_path)
    with repository._prep_repo(url_path) as git_repo:
        tmp.tmp_config.set("Repository", "local_path", str(git_repo.path))
        head = git_repo.get_head().hash[:7]
        if tmp.tmp_config.has_option("Analysis Settings", "commit"):
            commit = tmp.tmp_config.get("Analysis Settings", "commit")
        else:
            commit = head
        repo_name = git_repo.project_name
        tmp.tmp_config.set("Analysis Settings", "output_path", os.path.join(os.getcwd(), "code2DFD_output", repo_name.replace("/", "--"), commit))
        git_repo.checkout(commit)
        print(f"\nStart extraction of DFD for {repo_name} on commit {commit} at {datetime.now().strftime('%H:%M:%S')}")
        codeable_models, traceability_content = DFD_extraction()
        print(f"Finished: {datetime.now().strftime('%H:%M:%S')}")

        git_repo.checkout(head)

    return codeable_models, traceability_content


def DFD_extraction():
    """Main function for the extraction, calling all technology-specific extractors, managing output etc.
    """
    dfd = CDFD("TestDFD")

    microservices1, information_flows, external_components = dict(), dict(), dict()

    microservices = tech_sw.get_microservices(dfd)
    if microservices == microservices1:
        print("\n/!\\ Aucun microservice détecté /!\\")
        return None,None
    
    microservices = detect_databases(microservices)
    microservices = overwrite_port(microservices)
    microservices = detect_ssl_services(microservices)
    print("Extracted services from build- and IaC-files")

    # Parse internal and external configuration files
    microservices, information_flows, external_components = detect_spring_config(microservices, information_flows, external_components, dfd)
    # print("a")
    microservices = detect_eureka_server_only(microservices, dfd)
    # print("b")
    microservices = overwrite_port(microservices)
    # print("c")
    # Classify brokers (needed for information flows)
    microservices = classify_brokers(microservices)
    # print("d")
    
    # Check authentication information of services
    microservices = detect_authentication_scopes(microservices, dfd)
    # print("e")
    tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))
    # print("f")

    # Get information flows
    tmp.tmp_config.set("DFD", "external_components", str(external_components).replace("%", "%%"))
    # print("g")

    new_information_flows = tech_sw.get_information_flows(dfd)
    # print("h")
    external_components = ast.literal_eval(tmp.tmp_config["DFD"]["external_components"])
    # print("i")

    # Merge old and new
    for new_flow in new_information_flows.keys():
        key = max(information_flows.keys(), default=-1) + 1
        information_flows[key] = dict()
        information_flows[key] = new_information_flows[new_flow]
    print("Extracted information flows from API-calls, message brokers, and database connections")

    # Detect everything else / execute all technology implementations
    print("Classifying all services")
    microservices = tech_sw.get_microservices(dfd)
    # print("k")
    # microservice
    # s1 = microservices
    
    # FIXME:
    microservices, information_flows, external_components = classify_microservices(microservices, information_flows, external_components, dfd)
    # print("l")
    # assert microservices1 != microservices, "Egalité"

    # Merging
    print("Merging duplicate items")
    merge_duplicate_nodes(microservices, information_flows)
    # print("m")
    merge_duplicate_nodes(external_components, information_flows)
    # print("n")
    merge_duplicate_flows(information_flows)
    # print("o")
    merge_duplicate_annotations(microservices)
    # print("p")
    merge_duplicate_annotations(information_flows)
    # print("q")
    merge_duplicate_annotations(external_components)
    # print("r")
    
    
    print("Cleaning database connections")
    clean_database_connections(microservices, information_flows)

    # Printing
    print("\nFinished extraction")

    # Saving
    tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))
    tmp.tmp_config.set("DFD", "information_flows", str(information_flows).replace("%", "%%"))
    tmp.tmp_config.set("DFD", "external_components", str(external_components).replace("%", "%%"))

    plaintext.write_plaintext(microservices, information_flows, external_components)
    codeable_models, codeable_models_path = codeable_model.output_codeable_model(microservices, information_flows, external_components)
    traceability_content = traceability.output_traceability()
    visualizer.output_png(codeable_models_path)
    json_edges.generate_json_edges(information_flows)
    json_architecture.generate_json_architecture(microservices, information_flows, external_components)
    # json_mm_arch.save_arch(microservices, information_flows, external_components)

    # sep = "\n\n================================ ======================================"
    # print(sep, microservices, sep, information_flows, sep, external_components )
    
    # calculate_metrics.calculate_single_system(repo_path)
    # check_traceability.check_traceability(microservices, information_flows, external_components, traceability_content)

    return codeable_models, traceability_content


def classify_brokers(microservices: dict) -> dict:
    """Classifies kafka and rabbitmq servers, because they are needed for the information flows.
    """

    microservices = detect_rabbitmq_server(microservices)
    microservices = detect_kafka_server(microservices)
    tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))
    return microservices


def classify_microservices(microservices: dict, information_flows: dict, external_components: dict, dfd) -> tuple[dict, dict, dict]:
    """Tries to determine the microservice's funcitonality.
    """

    microservices, information_flows = detect_eureka(microservices, information_flows, dfd)
    # The above code is a Python script that prints the string "aa" to the console.
    # print("aa")
    microservices, information_flows, external_components = detect_zuul(microservices, information_flows, external_components, dfd)
    # print("ab")
    microservices, information_flows, external_components = detect_spring_cloud_gateway(microservices, information_flows, external_components, dfd)
    # print("ac")
    microservices, information_flows = detect_spring_oauth(microservices, information_flows, dfd)
    # print("ad")
    microservices, information_flows = detect_consul(microservices, information_flows, dfd)
    # print("ae")
    microservices, information_flows = detect_hystrix_dashboard(microservices, information_flows, dfd)
    # print("af")
    microservices, information_flows = detect_turbine(microservices, information_flows, dfd)
    # print("ag")
    microservices, information_flows = detect_local_logging(microservices, information_flows, dfd)
    # print("ah")
    microservices, information_flows = detect_zipkin_server(microservices, information_flows, dfd)
    # print("ai")
    microservices, information_flows = detect_spring_admin_server(microservices, information_flows, dfd)
    # print("aj")
    microservices, information_flows = detect_prometheus_server(microservices, information_flows, dfd)
    # print("ak")
    microservices, information_flows = detect_circuit_breakers(microservices, information_flows, dfd)
    # print("al")
    microservices, information_flows = detect_load_balancers(microservices, information_flows, dfd)
    # print("aù")
    microservices = detect_ribbon_load_balancers(microservices, dfd)
    # print("an")
    microservices, information_flows = detect_hystrix_circuit_breakers(microservices, information_flows, dfd)
    # print("ao")
    microservices, information_flows = detect_zookeeper(microservices, information_flows, dfd)
    microservices, information_flows = detect_etcd(microservices, information_flows, dfd)
    # print("ap")
    microservices, information_flows = detect_kibana(microservices, information_flows, dfd)
    # print("aq")
    microservices, information_flows = detect_elasticsearch(microservices, information_flows, dfd)
    # print("ar")
    microservices, information_flows, external_components = detect_logstash(microservices, information_flows, external_components, dfd)
    # print("as")
    microservices, information_flows, external_components = detect_nginx(microservices, information_flows, external_components, dfd)
    # print("at")
    microservices, information_flows = detect_grafana(microservices, information_flows, dfd)
    # print("au")
    microservices, information_flows = detect_spring_encryption(microservices, information_flows, dfd)
    # print("av")
    microservices = detect_endpoints(microservices, dfd)
    # print("aw")

    microservices, information_flows, external_components = detect_miscellaneous(microservices, information_flows, external_components)
    # print("ax")
    microservices, information_flows, external_components = detect_apachehttpd_webserver(microservices, information_flows, external_components, dfd)
    # print("ay")
    microservices = classify_internal_infrastructural(microservices)
    # print("az")
    microservices = set_plaintext_credentials(microservices)
    
    # Check security rules
    microservices = check_registry_security(microservices)
    microservices = check_inter_service_encryption(microservices,information_flows)
    microservices = check_external_encryption(microservices)
    
    return microservices, information_flows, external_components


def overwrite_port(microservices: dict) -> dict:
    """Writes port from properties to tagged vallues.
    """

    for microservice in microservices.values():
        for prop in microservice.get("properties", []):
            if prop[0] == "port":
                # print(prop)
                port = None
                if isinstance(prop[1], str):
                    if "port" in prop[1].casefold() and ":" in prop[1]:
                        port = prop[1].split(":")[1].strip("}")
                    else:
                        try:
                            port = int(prop[1].strip())
                        except Exception:
                            port = None
                else:
                    port = prop[1]
                if port:
                    # Traceability
                    traceability.add_trace({
                        "parent_item": microservice["name"],
                        "item": "Port",
                        "file": prop[2][0],
                        "line": prop[2][1],
                        "span": prop[2][2]
                    })
                    
                    microservice["tagged_values"] = microservice.get("tagged_values", []) + [("Port", port)]

    return microservices


def detect_miscellaneous(microservices: dict, information_flows: dict, external_components: dict) -> tuple[dict, dict, dict]:
    """Goes through properties extracted for each service to check for some things that don't fit anywhere else (mail servers, external websites, etc.).
    """

    for microservice in microservices.values():
        for prop in microservice.get("properties", []):
            if "gateway" in prop[0]:
                microservice["stereotype_instances"].append("gateway")
            
            # external mail server
            if prop[0] == "mail_host":
                mail_username, mail_password = None, None
                for prop2 in microservice["properties"]:
                    if prop2[0] == "mail_password":
                        mail_password = prop2[1]
                    elif prop2[0] == "mail_username":
                        mail_username = prop2[1]
                # create external mail server
                key = max(external_components.keys(), default=-1) + 1
                external_components[key] = {
                    "name": "mail-server",
                    "stereotype_instances": ["mail_server", "entrypoint", "exitpoint"],
                    "tagged_values": [("Host", prop[1])]
                }
                if mail_password:
                    external_components[key]["tagged_values"].append(("Password", mail_password))
                    external_components[key]["stereotype_instances"].append("plaintext_credentials")
                if mail_username:
                    external_components[key]["tagged_values"].append(("Username", mail_username))

                traceability.add_trace({
                    "item": "mail-server",
                    "file": prop[2][0],
                    "line": prop[2][1],
                    "span": prop[2][2]
                })

                traceability.add_trace({
                    "parent_item": "mail-server",
                    "item": "entrypoint",
                    "file": "heuristic",
                    "line": "heuristic",
                    "span": "heuristic"
                })

                traceability.add_trace({
                    "parent_item": "mail-server",
                    "item": "exitpoint",
                    "file": "heuristic",
                    "line": "heuristic",
                    "span": "heuristic"
                })


                traceability.add_trace({
                    "parent_item": "mail-server",
                    "item": "mail_server",
                    "file": "heuristic",
                    "line": "heuristic",
                    "span": "heuristic"
                })

                # create connection
                id_ = max(information_flows.keys(), default=-1) + 1
                information_flows[id_] = {
                    "sender": microservice["name"],
                    "receiver": "mail-server",
                    "stereotype_instances": ["restful_http"]
                }
                if mail_password:
                    information_flows[id_]["stereotype_instances"].append("plaintext_credentials_link")

                traceability.add_trace({
                    "item": f"{microservice["name"]} -> mail-server",
                    "file": prop[2][0],
                    "line": prop[2][1],
                    "span": prop[2][2]
                })

            # external api rate website
            elif prop[0] == "rates_url":
                # create external component
                id_ = max(external_components.keys(), default=-1) + 1
                external_components[id_] = {
                    "name": "external-website",
                    "stereotype_instances": ["external_website", "entrypoint", "exitpoint"],
                    "tagged_values": [("URL", prop[1])]
                }
                
                traceability.add_trace({
                    "item": "external-website",
                    "file": prop[2][0],
                    "line": prop[2][1],
                    "span": prop[2][2]
                })

                traceability.add_trace({
                    "parent_item": "external-website",
                    "item": "entrypoint",
                    "file": "heuristic",
                    "line": "heuristic",
                    "span": "heuristic"
                })

                traceability.add_trace({
                    "parent_item": "external-website",
                    "item": "exitpoint",
                    "file": "heuristic",
                    "line": "heuristic",
                    "span": "heuristic"
                })

                traceability.add_trace({
                    "parent_item": "external-website",
                    "item": "external_website",
                    "file": "heuristic",
                    "line": "heuristic",
                    "span": "heuristic"
                })

                # create connection
                key = max(information_flows.keys(), default=-1) + 1
                information_flows[key] = {
                    "sender": "external-website",
                    "receiver": microservice["name"],
                    "stereotype_instances": ["restful_http"]
                }

                traceability.add_trace({
                    "item": f"external-website -> {microservice["name"]}",
                    "file": prop[2][0],
                    "line": prop[2][1],
                    "span": prop[2][2]
                })


            # connection config to services
            elif prop[0] == "config_connected":
                for m2 in microservices.values():
                    for stereotype in m2.get("stereotype_instances", []):
                        if stereotype == "configuration_server":
                            key = max(information_flows.keys(), default=-1) + 1
                            information_flows[key] = {
                                "sender": m2["name"],
                                "receiver": microservice["name"],
                                "stereotype_instances": ["restful_http"]
                            }
                            
                            traceability.add_trace({
                                "item": f"{m2["name"]} -> {microservice["name"]}",
                                "file": prop[2][0],
                                "line": prop[2][1],
                                "span": prop[2][2]
                            })


    return microservices, information_flows, external_components


def merge_duplicate_flows(information_flows: dict):
    """Multiple flows with the same sender and receiver might occur. They are merged here.
    """
    print("@@@@@@@@@@@@@@@@@@@@@@ DuplicatFlow @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    to_delete = set()
    for i, j in combinations(information_flows.keys(), 2):
        if i == j:
            continue
        
        flow_i = information_flows[i]
        if flow_i["sender"] and flow_i["receiver"]:
            flow_i["sender"] = flow_i["sender"].casefold()
            flow_i["receiver"] = flow_i["receiver"].casefold()
        else:
            to_delete.add(i)
            continue

        flow_j = information_flows[j]
        if flow_j["sender"] and flow_j["receiver"]:
            flow_j["sender"] = flow_j["sender"].casefold()
            flow_j["receiver"] = flow_j["receiver"].casefold()
        else:
            to_delete.add(j)
            continue

        if (flow_i["sender"],flow_i["receiver"]) == (flow_j["sender"],flow_j["receiver"]):
            # merge
            for field, j_value in flow_j.items():
                if field not in ["sender", "receiver"]:
                    print(" - ",flow_i,"\n",j_value)
                    try:
                        flow_i[field] = flow_i.get(field, []) + list(j_value)
                    except Exception:
                        try:
                            flow_i[field] = list(j_value).append(flow_i.get(field, []))
                        except TypeError:
                            pass
            to_delete.add(j)
    for k in to_delete:
        del information_flows[k]


def merge_duplicate_nodes(nodes: dict, information_flows: dict):
    """Merge duplicate nodes
    """

    # Microservices
    to_delete = set()
    print("@@@@@@@@@@@@@@@@@@@@@@ DuplicatNode @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    for i, j in combinations(nodes.keys(), 2):
        if i == j:
            continue
        
        keep = None
        delete = None
        
        node_i = nodes[i]
        node_i["name"] = node_i["name"].casefold()
        node_j = nodes[j]
        node_j["name"] = node_j["name"].casefold()
        
        node_i_clean = node_i["name"].replace("-","").replace("_","")
        node_j_clean = node_j["name"].replace("-","").replace("_","")
        
        if node_i_clean == node_j_clean:
            if len(node_i)>len(node_j):
                print("1.1",node_j['name'],"->",node_i['name'])
                keep = node_i
                delete = node_j
                to_delete.add(j)
            else:
                keep = node_j
                delete = node_i
                to_delete.add(i)
                print("1.2",node_i['name'],"->",node_j['name'])


        # FIXME:
        required_substrings = ["image_placeholder", "docker", ".", ":", "None"]
        
        try:
            image_i = node_i["image"].split("/")[-1] or "None"
        except Exception:
            image_i = "None"
        try:
            image_j = node_j["image"].split("/")[-1] or "None"
        except Exception:
            image_j = "None"
        
        if all(sub not in image_i for sub in required_substrings) \
            or all(sub not in image_j for sub in required_substrings):
            if node_i["name"] == image_j \
                and node_j_clean in node_i_clean:
                    keep=node_i
                    delete=node_j
                    to_delete.add(j)
                    print("2.1",node_j['name'],"->",node_i['name'])
            if node_j["name"] == image_i \
                and node_i_clean in node_j_clean:
                    keep=node_j
                    delete=node_i
                    to_delete.add(i)
                    print("2.2",node_i['name'],"->",node_j['name'])
        
        if keep and delete:
            for field, j_value in delete.items():
                if field not in ["name", "type"]:
                    try:
                        keep[field] = keep.get(field, []) + list(j_value)
                    except Exception:
                        keep[field] = list(j_value).append(keep.get(field, []))
            rename_information_flow_services(keep["name"],delete["name"], information_flows)
        
    for k in to_delete:
        del nodes[k]

def rename_information_flow_services(keep: str, delete: str, information_flows: dict):
    for flow in information_flows.values():
        if flow["sender"] == delete:
            flow["sender"] = keep
        
        if flow["receiver"] == delete:
            flow["receiver"] = keep


def merge_duplicate_annotations(collection: dict):
    """Merge annotations of all items
    """

    for item in collection.values():
        if "stereotype_instances" in item:
            item["stereotype_instances"] = list(set(item["stereotype_instances"]))

        if "tagged_values" in item:
            merged_tagged_values = {}
            
            for tag, tagged_value in item["tagged_values"]:
                if tag == "Port":
                    try:
                        tagged_value = ast.literal_eval(tagged_value)
                    except Exception:
                        pass
                    if type(tagged_value) != list:
                        tagged_value = [tagged_value]
                    
                    for i in range(len(tagged_value)):
                        if isinstance(tagged_value[i], str):
                            tagged_value[i] = tagged_value[i].split("/")[0]  # Could be a protocol like 3306/tcp
                        
                        if not isinstance(tagged_value[i], int):
                            try:
                                tagged_value[i] = int(tagged_value[i])
                            except ValueError:
                                continue
                
                # Easier to manipulate in dict (merging duplicate values, and values of same tags)
                elif not isinstance(tagged_value, list):
                    tagged_value = [tagged_value]

                # merge in dict()
                if tag in merged_tagged_values:
                    for val in tagged_value:
                        if val not in merged_tagged_values[tag]:
                            merged_tagged_values[tag].append(val)
                else:
                    merged_tagged_values[tag] = tagged_value
                
            # The above code is creating a new key-value pair in the `item` dictionary. The key is "tagged_values" and the value is a list created from the `merged_tagged_values`.
            item["tagged_values"] = [
                (tag, values if len(values) > 1 else values[0])
                for tag, values in merged_tagged_values.items()
            ]