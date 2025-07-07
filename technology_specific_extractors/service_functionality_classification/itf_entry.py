import output_generators.traceability as traceability

def classify_internal_infrastructural(microservices: dict) -> dict:
    """Classifies processes as either internal or infrastructural.
    The latter if they are marked as one of the known infrastructural technologies.
    """

    infrastructural_stereotypes = [ "configuration_server",
                                    "administration_server",
                                    "service_discovery",
                                    "gateway",
                                    "message_broker",
                                    "authentication_server",
                                    "authorization_server",
                                    "logging_server",
                                    "monitoring_server",
                                    "monitoring_dashboard",
                                    "web_server",
                                    "web_application",
                                    "deployment_server",
                                    "stream_aggregator",
                                    "tracing_server",
                                    "metrics_server",
                                    "visualization",
                                    "search_engine",
                                    "proxy"
                                    ]

    for m in microservices.values():
        infrastructural = False
        if "database" not in m["stereotype_instances"]:
            deciding_stereotype = None
            for s in m["stereotype_instances"]:
                if s in infrastructural_stereotypes:
                    infrastructural = True
                    deciding_stereotype = s
            
            if infrastructural:
                m["stereotype_instances"].append("infrastructural")
                m["type"] = "service"
                if deciding_stereotype:
                    traceability.add_trace({
                        "parent_item": m["name"],
                        "item": "infrastructural",
                        "file": f"heuristic, based on stereotype {deciding_stereotype}",
                        "line": f"heuristic, based on stereotype {deciding_stereotype}",
                        "span": f"heuristic, based on stereotype {deciding_stereotype}"
                    })
            else:
                m["type"] = "service"
                if "stereotype_instances" in m:
                    m["stereotype_instances"].append("internal")
                else:
                    m["stereotype_instances"] = ["internal"]

                traceability.add_trace({
                    "parent_item": m["name"],
                    "item": "internal",
                    "file": "heuristic",
                    "line": "heuristic",
                    "span": "heuristic"
                })


    return microservices
