import ast

import core.file_interaction as fi
import core.technology_switch as tech_sw
import tmp.tmp as tmp
import output_generators.traceability as traceability


def set_information_flows(dfd) -> dict:
    """Detects uses of Feign Client in the code.
    """

    microservices = tech_sw.get_microservices(dfd)

    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])
    else:
        information_flows = dict()

    # check for circuit breaker
    results = fi.search_keywords("@EnableFeignClients", file_extension=["*.java", "*.kt"])     # content, name, path
    for id in results.keys():
        microservice = tech_sw.detect_microservice(results[id]["path"], dfd)
        for line in results[id]["content"]:
            if "@EnableCircuitBreaker" in line:
                for m in microservices.values():
                    if m["name"] == microservice:
                        m.setdefault("properties",set()).update("hystrix_enabled")
                        # print("fgn_entry : ","hystrix","<<<<<<<<< circuit breaker",microservice)

    results = fi.search_keywords("@FeignClient", file_extension=["*.java", "*.kt"])     # content, name, path
    for id in results.keys():
        microservice = tech_sw.detect_microservice(results[id]["path"], dfd)

        # setting correct load balancer and checking for circuit breaker
        stereotype_instances = ["load_balanced_link", "restful_http", "feign_connection"]
        load_balancer = "Ribbon"    # default load balancer for FeignClient
        tagged_values = set()
        for m in microservices.keys():
            if microservices[m]["name"] == microservice:
                for prop in microservices[m]["properties"]:
                    if prop[0] == "feign_ribbon_disabled":
                        load_balancer = "Spring Cloud Load Balancer" # Load balancer if Ribbon is explicitely disabled (also, recently recommended)
                    elif prop[0] == "circuit_breaker":
                        stereotype_instances.append("circuit_breaker_link")
                        # tagged_values.add(("Circuit Breaker", prop[1]))
                    elif prop[0] == "feign_hystrix":
                        stereotype_instances.append("circuit_breaker_link")
                        # tagged_values.add(("Circuit Breaker", "Hystrix"))

        tagged_values.add(("Load Balancer", load_balancer))

        target_service = False
        for line in results[id]["content"]:
            if "@FeignClient" in line:
                if "name" in line:
                    target_service = line.split("name")[1].split(",")[0].strip().strip("=)\"").strip()
                elif "value" in line:
                    target_service = line.split("value")[1].split(",")[0].strip().strip("=)\"").strip()
                elif "," in line:
                    target_service = line.split("FeignClient(")[1].split(",")[0].strip().strip(")").strip().strip("\"").strip()
                if not is_microservice(target_service, dfd):
                    target_service = False
                if not target_service and "url" in line:
                    target_url = line.split("url")[1].split("=")[1].split(",")[0].strip().strip("\"")
                    target_service = fi.resolve_url(target_url, microservice, dfd)

                if target_service:
                    for m in microservices.keys():
                        if microservices[m]["name"].casefold() == target_service.casefold():
                            for s in microservices[m]["stereotype_instances"]:
                                if s == "authentication_scope_all_requests":
                                    stereotype_instances.add("authenticated_request")
                if target_service and microservice:
                    # set flow
                    id2 = max(information_flows.keys(), default=-1) + 1
                    information_flows[id2] = {
                        "sender": microservice,
                        "receiver": target_service,
                        "stereotype_instances": stereotype_instances,
                        "tagged_values": tagged_values
                    }
                    
                    traceability.add_trace(
                        {
                            "item": f"{microservice} -> {target_service}",
                            "file": results[id]["path"],
                            "line": results[id]["line_nr"],
                            "span": results[id]["span"]
                        }
                    )

    tmp.tmp_config.set("DFD", "information_flows", str(information_flows).replace("%", "%%"))
    return information_flows


def is_microservice(service: str, dfd) -> bool:
    """Checks if input service is in the list of microservices.
    """

    if not service:
        return False
    is_microservice = False
    microservices = tech_sw.get_microservices(dfd)
    for m in microservices.keys():
        if service.casefold() == microservices[m]["name"].casefold():
            is_microservice = True

    return is_microservice




#
