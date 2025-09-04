import core.file_interaction as fi
import output_generators.traceability as traceability

AUTH_PATTERNS = {
    # Patterns pour l'authentification et l'autorisation côté serveur (Spring Security)
    "server": {
        "config_files": [
            "spring.security.oauth2.resourceserver.jwt",
            "spring.security.oauth2.resourceserver.opaque-token",
            "security.jwt.secret"
        ],
        "java_code": [
            "JwtDecoder",
            "JwtAuthenticationConverter",
            "ResourceServerConfigurerAdapter",
            "@EnableWebSecurity",
            "@EnableResourceServer",
            "http.oauth2ResourceServer()"
        ]
    },
    # Patterns pour l'authentification côté client (injection de token)
    "client": {
        "java_code": [
            "requestTemplate.header(\"Authorization\"",
            "WebClient.builder().defaultHeaders(",
            "RestTemplate().getForObject(\"http"  # Un appel non sécurisé est une vulnérabilité
        ]
    }
}


def check_inter_service_auth_and_authz(microservices: dict, information_flows: dict) -> dict:
    """
    Vérifie l'authentification et l'autorisation mutuelles des requêtes inter-services 
    en utilisant une analyse plus ciblée des configurations et des patterns de code.
    """
    
    # Étape 1 : Analyser chaque service individuellement
    for service in microservices.values():
        directory_path, path = "", ""
        for a in service:
            if "path" in a:
                path = a
        if path:
            directory_path = (service.get(f"{path}")).rsplit("/",1)[0]
        # print(directory_path,"----------------------------------------------")
        if not directory_path:
            continue

        # Détection des mécanismes de sécurité côté serveur
        server_security_found = any(fi.search_keywords(pattern, directory_path, file_extension=["*.properties", "*.yml", "*.yaml","*.xml","*.sh","*.json","*.conf"]) for pattern in AUTH_PATTERNS["server"]["config_files"]) or \
                                any(fi.search_keywords(pattern, directory_path, file_extension=["*.java", "*.kt"]) for pattern in AUTH_PATTERNS["server"]["java_code"])
        if not server_security_found:
            service.setdefault("stereotype_instances", []).append("security_vulnerability")
            service.setdefault("tagged_values", []).append(("Security Risk", "No OAuth or Token Security"))

        # Détection de l'injection de token côté client
        client_auth_found = any(fi.search_keywords(pattern, directory_path, file_extension=["*.java", "*.kt"]) for pattern in AUTH_PATTERNS["client"]["java_code"])
        if client_auth_found:
            # Vérification de l'existence d'appels non sécurisés
            if "RestTemplate().getForObject(\"http:" in client_auth_found:
                service.setdefault("stereotype_instances", []).append("security_vulnerability")
                service.setdefault("tagged_values", []).append(("Security Risk", "Unsecured HTTP call detected alongside secured calls."))
            else:
                service.setdefault("stereotype_instances", []).append("auth_client_enabled")
                service.setdefault("tagged_values", []).append(("Security", "Client Adds Auth Header"))

    # Étape 2 : Vérifier les flux d'information pour s'assurer qu'ils sont protégés
    for flow_id, flow in information_flows.items():
        sender_name = flow.get("sender")
        receiver_name = flow.get("receiver")

        sender_service = microservices.get(sender_name)
        receiver_service = microservices.get(receiver_name)

        if not sender_service or not receiver_service:
            continue

        sender_is_not_secure_client = "security_vulnerability" in sender_service.get("stereotype_instances", [])
        receiver_is_not_secure_server = "security_vulnerability" in receiver_service.get("stereotype_instances", [])

        is_secured = False
        reason = ""

        # Un flux est sécurisé si le client envoie un token et que le serveur sait le valider
        if sender_is_not_secure_client and receiver_is_not_secure_server:
            is_secured = False
            reason = "Missing security configuration on either sender or receiver."
            flow.setdefault("stereotype_instances", []).append("security_vulnerability")
        
        else:
            if sender_is_not_secure_client:
                sender_service.setdefault("stereotype_instances", []).append("security_vulnerability")
                sender_service.setdefault("tagged_values", []).append(("Security Risk", "Does not seem to send authentication headers."))
            
            if receiver_is_not_secure_server:
                receiver_service.setdefault("stereotype_instances", []).append("security_vulnerability")
                receiver_service.setdefault("tagged_values", []).append(("Security Risk", "Does not seem to be configured as a secure resource server."))

        traceability.add_trace({
            "parent_item": f"Flow_{flow_id}",
            "item": "inter_service_auth_and_authz_check_improved",
            "is_secured": is_secured,
            "reason": reason
        })

    return microservices