import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability

# Dictionnaire de mots-clés hautement fiables pour le chiffrement
ENCRYPTION_KEYWORDS = {
    "configuration": [
        "server.ssl.enabled=true",
        "server.ssl.key-store",
        "server.ssl.key-alias",
        "management.ssl.enabled=true"
    ],
    "code": [
        "SslContextBuilder",
        "SslBundles",
        "with-https",
        "with-ssl",
        "SslConfigurer"
    ],
    "gateway_config": [
        "uri: https://"
    ]
}

def check_external_encryption(microservices: dict) -> dict:
    """
    Vérifie que le trafic provenant d'entités externes est chiffré
    en se basant sur des mots-clés de haute confiance.
    """
    for m in microservices.values():
        # Détection des points d'entrée (Gateway, service public)
        is_entry_point = any(
            tag == ("API_Gateway", True)
            for tag in m.get("tagged_values", [])
        )
        
        if not is_entry_point:
            continue
            
        is_secured = False
        service_name = m.get("name")
        path, directory_path = "", ""
        for a in m:
            if "path" in a:
                path = a
        if path:
            directory_path = (m.get(f"{path}")).rsplit("/",1)[0]
        
        print(directory_path,"&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
        

        # Recherche des mots-clés dans les fichiers de configuration
        for keyword in ENCRYPTION_KEYWORDS["configuration"]:
            # On cherche dans les fichiers de configuration (.yml, .properties)
            results = fi.search_keywords(keyword, directory_path, file_patterns=["*.conf","*.xml","*.gradle","*.sh","*.json","*.yml","*.yaml", "*.properties"])
            if results:
                is_secured = True
                for _, res in results.items():
                    traceability.add_trace({
                        "parent_item": service_name,
                        "item": "external_encryption_check",
                        "reason": f"Encryption config keyword found: '{keyword}'",
                        "file": res["path"],
                        "line": res["line_nr"]
                    })
                break
        
        if is_secured:
            continue
            
        # Recherche dans le code Java (pour des implémentations personnalisées)
        for keyword in ENCRYPTION_KEYWORDS["code"]:
            # On cherche spécifiquement dans les fichiers .java
            results = fi.search_keywords(keyword, directory_path, file_patterns=["*.java", "*.kt"])
            if results:
                is_secured = True
                for _, res in results.items():
                    traceability.add_trace({
                        "parent_item": service_name,
                        "item": "external_encryption_check",
                        "reason": f"Encryption code keyword found: '{keyword}'",
                        "file": res["path"],
                        "line": res["line_nr"]
                    })
                break

        # Si toujours rien, on cherche dans la configuration de passerelle (ex: Spring Cloud Gateway)
        if not is_secured and is_entry_point:
            for keyword in ENCRYPTION_KEYWORDS["gateway_config"]:
                results = fi.search_keywords(keyword, directory_path, file_patterns=["*.xml","*.json","*.yml","*.yaml", "*.properties"])
                if results:
                    is_secured = True
                    for _, res in results.items():
                        traceability.add_trace({
                            "parent_item": service_name,
                            "item": "external_encryption_check",
                            "reason": f"Gateway encryption keyword found: '{keyword}'",
                            "file": res["path"],
                            "line": res["line_nr"]
                        })
                    break

        # Si aucune preuve de chiffrement n'est trouvée, marquer la vulnérabilité
        if not is_secured:
            m.setdefault("stereotype_instances", []).append("security_vulnerability")
            m.setdefault("tagged_values", []).append(("Security Risk", "Unencrypted External Traffic"))
            traceability.add_trace({
                "parent_item": service_name,
                "item": "security_vulnerability",
                "reason": "No high-confidence encryption keywords found for external traffic."
            })
            
    return microservices

