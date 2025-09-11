import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability


def detect_load_balancers(microservices: dict, information_flows: dict, dfd) -> dict:
    """Find load balancers.
    """

    results = fi.search_keywords("@LoadBalanced", file_extension=["*.java", "*.kt", "*.scala"])     # content, name, path
    for r in results.keys():
        microservice = tech_sw.detect_microservice(results[r]["path"], dfd)

        for m in microservices.values():
            if m["name"] == microservice:
                if "stereotype_instances" in m:
                    m["stereotype_instances"].append("load_balancer")
                else:
                    m["stereotype_instances"] = ["load_balancer"]
                if "tagged_values" in m:
                    m["tagged_values"].append(('Load Balancer', "Spring Cloud"))
                else:
                    m["tagged_values"] = [('Load Balancer', "Spring Cloud")]
                
                # print("lob_entry :","SpringCloud","<<<<<<<<<<<<<<<<<load balancer")
                # # Traceability
                traceability.add_trace(
                    {
                        "parent_item": microservice,
                        "item": "load_balancer",
                        "file": results[r]["path"],
                        "line": results[r]["line_nr"],
                        "span": results[r]["span"]
                    }
                )

                # adjust flows going from this service
                for i in information_flows.values():
                    if i["sender"] == microservice:
                        if "stereotype_instances" in i:
                            i["stereotype_instances"].append("load_balanced_link")
                        else:
                            i["stereotype_instances"] = ["load_balanced_link"]

                        # if "tagged_values" in information_flows[i]:
                        #     if type(information_flows[i]["tagged_values"]) == list:
                        #         information_flows[i]["tagged_values"].append(('Load Balancer', "Spring Cloud"))
                        #     else:
                        #         information_flows[i]["tagged_values"].add(('Load Balancer', "Spring Cloud"))
                        # else:
                        #     information_flows[i]["tagged_values"] = [('Load Balancer', "Spring Cloud")]

    return microservices, information_flows
