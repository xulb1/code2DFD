import re
import core.file_interaction as fi
import core.technology_switch as tech_sw


def detect_circuit_breakers_v0(microservices: dict, information_flows: dict, dfd) -> dict:
    """Find circuit breakers.
    """

    results = fi.search_keywords("@EnableCircuitBreaker", file_extension=["*.java"])     # content, name, path
    for r in results.keys():
        microservice = tech_sw.detect_microservice(results[r]["path"], dfd)
        # Check if circuit breaker tech was found
        circuit_breaker_tuple = False
        correct_id = False
        for m in microservices:
            if microservices[m]["name"] == microservice:
                correct_id = m
                for prop in microservices[correct_id]["properties"]:
                    if prop[0] == "circuit_breaker":
                        circuit_breaker_tuple = ("Circuit Breaker", prop[1])

        if correct_id:
            for line_nr in range(len(results[r]["content"])):
                line = results[r]["content"][line_nr]
                if "@EnableCircuitBreaker" in line:
                    microservices[correct_id].setdefault("stereotype_instances", []).append("circuit_breaker")

                    if circuit_breaker_tuple:
                        microservices[correct_id].setdefault("tagged_values", []).append(circuit_breaker_tuple)

                    # adjust flows going from this service
                    for flow in information_flows.values():
                        if flow["sender"] == microservice:
                            flow.setdefault("stereotype_instances", []).append("circuit_breaker_link")
                            
                            if circuit_breaker_tuple:
                                if "tagged_values" in flow:
                                    if type(flow["tagged_values"]) == list:
                                        flow["tagged_values"].append(circuit_breaker_tuple)
                                    else:
                                        flow["tagged_values"].add(circuit_breaker_tuple)
                                else:
                                    flow["tagged_values"] = [circuit_breaker_tuple]

    return microservices, information_flows



# Mapping des annotations de résilience par technologie
CIRCUIT_BREAKER_ANNOTATIONS = {
    "Hystrix": ["EnableCircuitBreaker", "HystrixCommand"],
    "Resilience4j": ["CircuitBreaker", "Retry", "RateLimiter", "Bulkhead", "TimeLimiter"],
    "Microprofile FT": ["CircuitBreaker", "Timeout", "Retry", "Fallback", "Bulkhead"],
}

# Crée un pattern regex unique pour toutes les annotations
ALL_ANNOTATIONS_PATTERN = re.compile(
    r'^\s*@(' + '|'.join({ann for anns in CIRCUIT_BREAKER_ANNOTATIONS.values() for ann in anns}) + r')\b'
)

def detect_circuit_breakers(microservices: dict, information_flows: dict, dfd) -> dict:
    """Détecte tous les mécanismes de résilience dans les microservices, gère les répétitions et ignore les commentaires."""

    
    # results = fi.search_keywords(list({f"@{ann}" for anns in CIRCUIT_BREAKER_ANNOTATIONS.values() for ann in anns}))
    # for i in results.values():
    #     print(i["name"])
    #     print("")
    # print("--------------jdskqmfldkjslkfdjqsmlfjqslkdfqj---------------------")
    
    results = fi.search_keywords(list({f"@{ann}" for anns in CIRCUIT_BREAKER_ANNOTATIONS.values() for ann in anns}), file_extension=["*.java"])
    # print("----------------------------------")
    # for i in results.values():
    #     print(i["name"])
    #     print("")
    # print("--------------jdskqmfldkjslkfdjqsmlfjqslkdfqj---------------------")
    

    for r in results.keys():
        microservice = tech_sw.detect_microservice(results[r]["path"], dfd)
        correct_id = None
        circuit_breaker_tuple = False

        for m in microservices:
            if microservices[m]["name"] == microservice:
                correct_id = m
                for prop in microservices[correct_id]["properties"]:
                    if prop[0] == "circuit_breaker":
                        circuit_breaker_tuple = ("Circuit Breaker", prop[1])

        if correct_id:
            for line in results[r]["content"]:
                line = line.strip()
                if line.startswith("//"):  # Ignore les commentaires
                    continue

                match = ALL_ANNOTATIONS_PATTERN.match(line)
                if match:
                    annotation_name = match.group(1)
                    # Détecte la techno correspondante
                    tech_name = next((tech for tech, anns in CIRCUIT_BREAKER_ANNOTATIONS.items() if annotation_name in anns), "unknown")

                    # Tagged values microservice
                    if circuit_breaker_tuple:
                        tagged = microservices[correct_id].setdefault("tagged_values", [])
                        if circuit_breaker_tuple not in tagged:
                            tagged.append(circuit_breaker_tuple)
                    else:
                        circuit_breaker_tuple = ("Circuit Breaker", tech_name)
                        tagged = microservices[correct_id].setdefault("tagged_values", [])
                        if circuit_breaker_tuple not in tagged:
                            tagged.append(circuit_breaker_tuple)

                    # print(circuit_breaker_tuple,"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<circuitbreaker")
                    # Mise à jour des flux sortants
                    for flow in information_flows.values():
                        if flow["sender"] == microservice:
                            flow_stereos = flow.setdefault("stereotype_instances", [])
                            if "circuit_breaker_link" not in flow_stereos:
                                flow_stereos.append("circuit_breaker_link")

    return microservices, information_flows


#UNUSED
def detect_circuit_breaker_tech(path: str) -> str:
    """Détecte la technologie de résilience utilisée dans un fichier Java via regex."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.readlines()

    for line in content:
        line = line.strip()
        if line.startswith("//"):
            continue
        match = ALL_ANNOTATIONS_PATTERN.match(line)
        if match:
            annotation_name = match.group(1)
            for tech, anns in CIRCUIT_BREAKER_ANNOTATIONS.items():
                if annotation_name in anns:
                    return tech
    return "unknown"
