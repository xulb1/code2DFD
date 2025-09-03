import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability

ZOOKEEPER_SERVER_IMAGES = [
    "wurstmeister/zookeeper",
    "zookeeper:"
]
# Keywords for ZooKeeper client and server
ZOOKEEPER_KEYWORDS = {
    "server": [
        "spring-cloud-zookeeper-server",
        "org.apache.zookeeper.server"
    ],
    "client": [
        "@EnableDiscoveryClient",
        "spring-cloud-starter-zookeeper-discovery",
        "spring.cloud.zookeeper.connect-string"
    ]
}

def detect_zookeeper(microservices: dict, information_flows: dict, dfd) -> dict:
    """
    Détecte les serveurs et clients ZooKeeper et établit les liens avec les microservices.
    """
    zookeeper_servers = set()
    zookeeper_clients = set()

    # --- Détection des serveurs et clients via les mots-clés ---
    for role, keywords in ZOOKEEPER_KEYWORDS.items():
        for keyword in keywords:
            # Recherche de mots-clés dans tous les fichiers du projet
            results = fi.search_keywords(keyword, file_extension=["*.xml","*.json","*.tf","*.gradle","*.conf","*.java","*.yml","*.yaml","*.properties"])
            for _, res in results.items():
    
                if (keyword=="zookeeper:" and "docker" not in res['name'])\
                    or ( len(res["path"].split("/"))>1 and "xml" in res["name"]):
                    continue

                # Utilisation de la fonction pour lier le chemin du fichier à un microservice
                service_name = tech_sw.detect_microservice(res["path"], dfd)
                
                if service_name:
                    m = microservices.get(service_name)
                    if m:
                        if role == "server":
                            zookeeper_servers.add(service_name)
                            m.setdefault("stereotype_instances", []).append("configuration_server")
                            m.setdefault("tagged_values", []).append(("Configuration Server", "ZooKeeper"))
                            item_stereotype = "configuration_server"
                        else:  # role == "client"
                            zookeeper_clients.add(service_name)
                            m.setdefault("stereotype_instances", []).append("configuration_client")
                            m.setdefault("tagged_values", []).append(("Client of Configuration Server", "ZooKeeper"))
                            item_stereotype = "configuration_client"
                        
                        # Ajout de la traçabilité
                        traceability.add_trace({
                            "parent_item": service_name,
                            "item": item_stereotype,
                            "file": res["path"],
                            "line": res["line_nr"],
                            "span": res["span"]
                        })

    # --- Détection des serveurs via l'image Docker (méthode de secours) ---
    for m in microservices.values():
        if any(img in m.get("image", "") for img in ZOOKEEPER_SERVER_IMAGES):
            service_name = m.get("name")
            if service_name and service_name not in zookeeper_servers:
                zookeeper_servers.add(service_name)
                m.setdefault("stereotype_instances", []).append("configuration_server")
                m.setdefault("tagged_values", []).append(("Configuration Server", "Zookeeper"))
    
    # --- Création des liens d'information ---

    # 1. Liens entre clients et serveurs ZooKeeper
    for client_name in zookeeper_clients:
        for server_name in zookeeper_servers:
            add_information_flow(information_flows, client_name, server_name)

    # 2. Liens entre serveurs ZooKeeper et services Kafka
    kafka_services = [m["name"] for m in microservices.values()
                      if any(tag == ("Message Broker", "Kafka") for tag in m.get("tagged_values", []))]

    for zk_server in zookeeper_servers:
        for kafka_service in kafka_services:
            if zk_server != kafka_service:
                add_information_flow(information_flows, kafka_service, zk_server)

    return microservices, information_flows


def add_information_flow(information_flows: dict, sender: str, receiver: str):
    """ Ajoute un flux d'information si il n'existe pas déjà et supprime le flux inverse. """
    flow_exists = any(
        (flow["sender"] == sender and flow["receiver"] == receiver)
        for flow in information_flows.values()
    )

    if not flow_exists:
        flow_id = max(information_flows.keys(), default=-1) + 1
        information_flows[flow_id] = {
            "sender": sender,
            "receiver": receiver,
            "stereotype_instances": ["restful_http"]
        }
        traceability.add_trace({
            "parent_item": f"{sender}_to_{receiver}",
            "item": "information_flow",
            "from": sender,
            "to": receiver
        })
    # Suppression des flux inversés
    to_remove = [i for i, flow in information_flows.items()
                 if flow["sender"] == receiver and flow["receiver"] == sender]
    for i in to_remove:
        information_flows.pop(i)





def detect_zookeeper_v0(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects ZooKeeper config services.
    """

    zookeeper_service = False

    # Service
    for m in microservices.values():
        if "wurstmeister/zookeeper" in m["image"]:
            zookeeper_service = m["name"]
            m.setdefault("stereotype_instances",[]).append("configuration_server")
            m.setdefault("tagged_values",[]).append(("Configuration Server", "ZooKeeper"))

    # Link to kafka if existing
    if zookeeper_service:
        kafka_service = False
        for m in microservices.values():
            for prop in m["tagged_values"]:
                if prop == ("Message Broker", "Kafka"):
                    kafka_service = m["name"]
        if kafka_service:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": zookeeper_service,
                "receiver": kafka_service,
                "stereotype_instances": ["restful_http"]
            }

            # check if link in other direction
            to_purge = set()
            for i in information_flows:
                if information_flows[i]["sender"] == kafka_service and information_flows[i]["receiver"] == zookeeper_service:
                    to_purge.add(i)
            for p in to_purge:
                information_flows.pop(p)

    return microservices, information_flows
