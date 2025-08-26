import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability

# Constantes pour la détection d'Etcd
ETCD_SERVER_IMAGES = [
    "quay.io/coreos/etcd",
    "bitnami/etcd",
    "gcr.io/etcd-development/etcd",
    "etcd:"
]
ETCD_CLIENT_KEYWORDS = [
    # Dépendances Maven/Gradle
    "io.etcd",
    "jetcd-core",
    
    # Propriétés de configuration
    "etcd.endpoints",
    "etcd-client.endpoints",
    "etcd.connection-string",
    "etcd.urls"
]

def detect_etcd(microservices: dict, information_flows: dict, dfd) -> dict:
    """
    Détecte les serveurs et clients Etcd et établit les liens entre les microservices.
    """
    etcd_servers = set()
    etcd_clients = set()

    # --- Détection des serveurs et clients via les mots-clés ---
    for keyword in ETCD_CLIENT_KEYWORDS:
        results = fi.search_keywords(keyword,file_extension=["*.conf","*.sh","*.xml","*.gradle","*.json","*.yml","*.yaml","*.properties"])
        
        for _, res in results.items():
            if (keyword=="etcd:" and "docker" not in res['name'])\
                or ( len(res["path"].split("/"))>1 and "xml" in res["name"]):
                    continue

            service_name = tech_sw.detect_microservice(res["path"], dfd)
            
            if service_name:
                m = microservices.get(service_name)
                if m:
                    # Dans le contexte Java, la présence d'une dépendance jetcd ou
                    # de l'API client indique un client Etcd
                    if service_name not in etcd_clients:
                        etcd_clients.add(service_name)
                        m.setdefault("stereotype_instances", []).append("configuration_client")
                        m.setdefault("tagged_values", []).append(("Client of Configuration Server", "Etcd"))
                        
                        traceability.add_trace({
                            "parent_item": service_name,
                            "item": "configuration_client",
                            "file": res["path"],
                            "line": res["line_nr"],
                            "span": res["span"]
                        })

    # --- Détection des serveurs via l'image Docker ---
    for m_id, m in microservices.items():
        service_name = m.get("name")
        if any(img in m.get("image", "") for img in ETCD_SERVER_IMAGES):
            if service_name and service_name not in etcd_servers:
                etcd_servers.add(service_name)
                m.setdefault("stereotype_instances", []).append("configuration_server")
                m.setdefault("tagged_values", []).append(("Configuration Server", "Etcd"))
                
                traceability.add_trace({
                    "parent_item": service_name,
                    "item": "configuration_server",
                    "reason": "Docker image detected",
                    "file": m.get("file_path", "N/A")
                })

    # --- Création des liens d'information ---
    for client_name in etcd_clients:
        for server_name in etcd_servers:
            add_information_flow(information_flows, client_name, server_name)

    return microservices, information_flows


def add_information_flow(information_flows: dict, sender: str, receiver: str):
    """
    Ajoute un flux d'information si il n'existe pas déjà et supprime le flux inverse.
    """
    flow_exists = any(
        (flow["sender"] == sender and flow["receiver"] == receiver) or
        (flow["sender"] == receiver and flow["receiver"] == sender)
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