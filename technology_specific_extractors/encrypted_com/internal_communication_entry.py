import core.file_interaction as fi
import output_generators.traceability as traceability

ENCRYPTION_KEYWORDS = {
    "server": {
        "config":[
            "server.ssl.enabled=true",
            "server.ssl.key-store",
            "server.ssl.key-store-password",
            "server.ssl.key-store-type",
            "server.port=8443",
            "management.ssl.enabled=true"
        ],
        "java_code":[
            "@EnableWebSecurity",
            "requiresSecure"
        ]
    },
    "client": {
        "all":[
            "https://"
        ],
        "config":[
            "eureka.client.serviceUrl=https://",
            "spring.cloud.config.uri=https://"
        ],
        "java_code":[
            "@FeignClient(",
            "WebClient.create(\"https://",
            "RestTemplate().getForObject(\"https://"
        ]
    },
    "infra": [
        "ssl_certificate",
        "ssl_certificate_key",
        "listen 443 ssl",
        "istio-proxy",
        "istio.io/rev",
        "sidecar.istio.io/inject:",
        "linkerd",
        "linkerd.io/inject:",
        "linkerd-proxy"
        # "envoy",
    ]
}


def check_inter_service_encryption(microservices: dict, information_flows: dict) -> dict:
    """
    Vérifie que les communications inter-services sont chiffrées.
    La logique est refactorisée pour être plus robuste et plus précise.
    """
    # Vérification individuelle des services
    for m in microservices.values():
        service_name = m.get("name")
        directory_path = m.get("directory_path")
        
        # Détection SSL côté serveur
        #TODO: detection pb
        for mot in ENCRYPTION_KEYWORDS["server"]["java_code"]:
            results = fi.search_keywords(mot, directory_path)
            if results:
                for i in results["content"]:
                    print(i)
        for mot in ENCRYPTION_KEYWORDS["server"]["config"]:
            results = fi.search_keywords(mot, directory_path)
            if results:
                for i in results["content"]:
                    print(i)
        is_server_ssl_enabled = any(fi.search_keywords(keyword, directory_path, file_extension=["*.java"]) for keyword in ENCRYPTION_KEYWORDS["server"]["java_code"]) or \
                                any(fi.search_keywords(keyword, directory_path, file_extension=["*.conf","*.sh","*.xml","*.gradle","*.json","*.yml","*.yaml","*.properties"]) for keyword in ENCRYPTION_KEYWORDS["server"]["config"])
        if is_server_ssl_enabled:
            m.setdefault("stereotype_instances", []).append("tls_enabled")
            m.setdefault("tagged_values", []).append(("Security", "Server SSL/TLS Enabled"))

        # Détection SSL côté client
        is_client_ssl_enabled = any(fi.search_keywords(keyword, directory_path) for keyword in ENCRYPTION_KEYWORDS["client"]["all"]) or \
                                any(fi.search_keywords(keyword, directory_path,file_extension=["*.conf","*.sh","*.xml","*.gradle","*.json","*.yml","*.yaml", "*.properties"]) for keyword in ENCRYPTION_KEYWORDS["client"]["config"]) or \
                                any(fi.search_keywords(keyword, directory_path,file_extension=["*.java"]) for keyword in ENCRYPTION_KEYWORDS["client"]["java_code"])
        if is_client_ssl_enabled:
            m.setdefault("stereotype_instances", []).append("client_tls_enabled")
            m.setdefault("tagged_values", []).append(("Security", "Client SSL/TLS Enabled"))

        # Détection SSL via l'infrastructure
        is_infra_ssl_enabled = any(fi.search_keywords(keyword, directory_path, file_extension=["*.conf","*.xml","*.gradle","*.sh","*.json","*.yml","*.yaml", "*.properties"]) for keyword in ENCRYPTION_KEYWORDS["infra"])
        if is_infra_ssl_enabled:
            m.setdefault("stereotype_instances", []).append("infra_tls_enabled")
            m.setdefault("tagged_values", []).append(("Security", "Infrastructure SSL/TLS Enabled"))

    # Vérification de chaque flux d'information
    for flow_id, flow in information_flows.items():
        sender_name = flow.get("sender")
        receiver_name = flow.get("receiver")

        sender_service = microservices.get(sender_name)
        receiver_service = microservices.get(receiver_name)

        if not sender_service or not receiver_service:
            continue

        sender_uses_tls = "client_tls_enabled" in sender_service.get("stereotype_instances", [])
        receiver_accepts_tls = "tls_enabled" in receiver_service.get("stereotype_instances", [])
        infra_tls_for_sender = "infra_tls_enabled" in sender_service.get("stereotype_instances", [])
        infra_tls_for_receiver = "infra_tls_enabled" in receiver_service.get("stereotype_instances", [])

        is_secured = False

        # client + serveur => une configuration SSL
        if sender_uses_tls and receiver_accepts_tls:
            # Pour garantir la certitude, on peut chercher la chaîne "https://" dans la configuration du sender.
            secure_url_found = fi.search_keywords(f"https://{receiver_name}", sender_service.get("directory_path"))
            if secure_url_found:
                is_secured = True
                traceability.add_trace({
                    "parent_item": f"Flow_{flow_id}",
                    "item": "tls_secured",
                    "reason": "Direct HTTPS URL found in sender's configuration"
                })

        # Chiffrement au niveau de l'infra
        if not is_secured and (infra_tls_for_sender or infra_tls_for_receiver):
            is_secured = True
            traceability.add_trace({
                "parent_item": f"Flow_{flow_id}",
                "item": "tls_secured_via_infra",
                "reason": "TLS handled by a service mesh or reverse proxy"
            })

        if not is_secured:
            flow.setdefault("stereotype_instances", []).append("security_vulnerability")
            traceability.add_trace({
                "parent_item": f"Flow_{flow_id}",
                "item": "security_vulnerability",
                "reason": "Inter-service communication is not encrypted."
            })
            sender_service.setdefault("stereotype_instances", []).append("security_vulnerability")
            sender_service.setdefault("tagged_values", []).append(
                ("Security Risk", "Unencrypted Inter-Service Traffic")
            )

    return microservices