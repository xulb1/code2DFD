import core.file_interaction as fi
import output_generators.traceability as traceability
from collections import defaultdict

# Dictionnaire de mots-clés pour l'analyse de la règle de dissociation
SECURITY_ANALYSIS_KEYWORDS = {
    "centralized_implementation": {
        "build_files": [
            "spring-boot-starter-oauth2-resource-server",
            "spring-cloud-starter-security",
            ".security.auth-starter"
        ],
        "config_files": [
            "spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
            "spring.security.oauth2.resourceserver.opaque-token.introspection-uri",
            "spring.cloud.config.uri",
            "spring.cloud.vault.uri",
            "security.jwt.public-key-location"
        ]
    },
    "decentralized_implementation": {
        "java_code": [
            "WebSecurityConfigurerAdapter",
            "JwtAuthenticationEntryPoint",
            "JwtTokenFilter",
            "AuthenticationFilter",
            "JwtValidator",
            "TokenProvider",
            "http.authorizeRequests()"
        ],
        "config_files": [
            "security.jwt.secret",
            "jwt.secret.key"
        ]
    }
}

def check_auth_logic_separation(microservices: dict) -> dict:
    """
    Vérifie la règle de dissociation de la logique d'authentification de manière plus fiable.
    """
    local_security_impls = defaultdict(list)
    
    for service_id, service in microservices.items():
        directory_path = service.get("directory_path")
        
        # Étape 1 : Vérifier l'implémentation centralisée
        is_centralized = False
        
        # Recherche dans les fichiers de construction (Maven/Gradle)
        has_shared_lib = any(fi.search_keywords(kw, directory_path, file_extension=["*.xml","*.gradle","*.sh","*.conf","*.json","*.properties","*.yml","*.yaml"]) for kw in SECURITY_ANALYSIS_KEYWORDS["centralized_implementation"]["build_files"])
        
        # Recherche dans les fichiers de configuration
        has_external_auth_config = any(fi.search_keywords(kw, directory_path, file_extension=["*.xml","*.gradle","*.sh","*.conf","*.json","*.yml","*.yaml","*.properties"]) for kw in SECURITY_ANALYSIS_KEYWORDS["centralized_implementation"]["config_files"])
        
        if has_shared_lib or has_external_auth_config:
            is_centralized = True
            service.setdefault("stereotype_instances", []).append("auth_logic_centralized")
            service.setdefault("tagged_values", []).append(("Security", "Use Central Auth logic"))
            traceability.add_trace({
                "parent_item": service_id,
                "item": "auth_logic_centralized",
                "reason": "Found proof of central security implementation."
            })

        # Étape 2 : Si non centralisé, chercher une implémentation locale
        if not is_centralized:
            has_local_java_impl = any(fi.search_keywords(kw, directory_path, file_extension=["*.java"]) for kw in SECURITY_ANALYSIS_KEYWORDS["decentralized_implementation"]["java_code"])
            has_local_config = any(fi.search_keywords(kw, directory_path, file_extension=["*.xml","*.gradle","*.sh","*.conf","*.json","*.properties","*.yml","*.yaml"]) for kw in SECURITY_ANALYSIS_KEYWORDS["decentralized_implementation"]["config_files"])
            
            if has_local_java_impl or has_local_config:
                local_security_impls[service_id].append("local_impl")
                service.setdefault("stereotype_instances", []).append("auth_logic_local")
                service.setdefault("tagged_values", []).append(("Security Risk", "Local Auth logic"))
            else:
                # Cas où aucun indice de sécurité n'est trouvé.
                # Cela peut être une vulnérabilité ou une approche gérée par l'infra (e.g., service mesh)
                service.setdefault("stereotype_instances", []).append("security_vulnerability")
                service.setdefault("tagged_values", []).append(("Security Risk", "No auth logic found"))
                traceability.add_trace({
                    "parent_item": service_id,
                    "item": "security_vulnerability",
                    "reason": "No clear security implementation found in code or config."
                })
                
    # Étape 3 : Vérifier la duplication des logiques locales
    if len(local_security_impls) > 1:
        for service_id in local_security_impls.keys():
            service = microservices.get(service_id)
            service.setdefault("stereotype_instances", []).append("security_vulnerability")
            service.setdefault("tagged_values", []).append(("Security Risk", "Auth logic duplicated"))
            traceability.add_trace({
                "parent_item": service_id,
                "item": "security_vulnerability",
                "reason": f"Duplicated security logic in services: {list(local_security_impls.keys())}"
            })
            
    return microservices