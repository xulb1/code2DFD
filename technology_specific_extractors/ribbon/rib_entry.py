import core.file_interaction as fi
import core.technology_switch as tech_sw


def detect_ribbon_load_balancers(microservices: dict, dfd) -> dict:
    """Detects load balancing via Ribbon.
    """
    
    return detect_client_side(microservices, dfd)


def detect_client_side(microservices: dict, dfd) -> dict:
    """Detects client side load balancing.
    """

    results = fi.search_keywords("RibbonClient", file_extension=["*.java", "*.kt"])     # content, name, path
    for r in results.values():
        microservice = tech_sw.detect_microservice(r["path"], dfd)
        for line in r["content"]:
            if "@RibbonClient" in line:
                for m in microservices.values():
                    if m["name"] == microservice:
                        m.setdefault("stereotype_instances",[]).append("load_balancer")
                        m.setdefault("tagged_values",[]).append(("Load Balancer", "Ribbon"))

    return microservices
