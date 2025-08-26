import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability

# Mots-clés pour la détection de la sécurité dans un registre de services

# TODO: VOIR POUR LES COM SÉCU INTERSERVICES
SECURITY_KEYWORDS = {
    "Eureka": [
        "spring-boot-starter-security",
        "WebSecurityConfigurerAdapter",
        "@EnableWebSecurity",
        "SecurityFilterChain",
        "spring.security.user",
        "spring.security.password"
    ],
    "Consul": [
        "consul.acl.token",
        "consul.token",
        "consul.acl",
        "CONSUL_HTTP_TOKEN",
        "acl_master_token",
        "acl.tokens.default",
        "spring.cloud.consul.discovery.token"
    ],
    "ZooKeeper": [
        "zookeeper.sasl.client",
        "zookeeper.authProvider",
        "zookeeper.jaas.login",
        "zookeeper.auth",
        "java.security.auth.login.config",
        "jaas.conf",
        "SASL"
    ],
    "Etcd": [
        "etcd.security.client",
        "etcd.ssl.enabled",
        "etcd.auth.enabled"
    ]
}

def check_registry_security(microservices: dict) -> dict:
    """
    Checks if a service registry has authentication and authorization in place.
    """
    for m in microservices.values():
        is_secured = False
        registry_type = None

        # 1. Check if the microservice is a registry and identify its type
        for tag in m.get("tagged_values", []):
            if tag[0] in ["Service Registry", "Configuration Server"]:
                registry_type = tag[1]
                break
        
        if not registry_type:
            continue
        
        # 2. Get the security keywords for this specific registry type
        keywords_to_search = SECURITY_KEYWORDS.get(registry_type, [])
        
        # 3. Search for the keywords in the service's directory
        for keyword in keywords_to_search:
            results = fi.search_keywords(keyword, m.get("directory_path"))
            
            if results:
                is_secured = True
                for _, res in results.items():
                    traceability.add_trace({
                        "parent_item": m.get("name"),
                        "item": "security_check",
                        "reason": f"Security keyword found: '{keyword}' for {registry_type}",
                        "file": res["path"],
                        "line": res["line_nr"],
                        "span": res["span"]
                    })
                    # print(f"Security keyword found for {registry_type}: '{keyword}'")
                break
        
        # 4. If no security keywords were found, flag a vulnerability
        if not is_secured:
            m.setdefault("stereotype_instances", []).append("security_vulnerability")
            m.setdefault("tagged_values", []).append(("Security Risk", f"Insecure {registry_type} Registry"))
    return microservices