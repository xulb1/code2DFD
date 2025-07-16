import core.file_interaction as fi
import core.technology_switch as tech_sw


def detect_circuit_breakers(microservices: dict, information_flows: dict, dfd) -> dict:
    """Find circuit breakers.
    """

    results = fi.search_keywords("@EnableCircuitBreaker")     # content, name, path
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


# TODO:
def detect_circuit_breaker_tech(path):
    return False
