import output_generators.traceability as traceability


def add_user(external_components: dict) -> dict:
    """Adds an user to the external components.
    """
    key = max(external_components.keys(), default=-1) + 1

    external_components[key] = dict()
    external_components[key]["name"] = "user"
    external_components[key]["type"] = "external_component"
    external_components[key]["stereotype_instances"] = ["user_stereotype", "entrypoint", "exitpoint"]

    trace = dict()
    trace["item"] = "user"
    trace["file"] = "implicit"
    trace["line"] = "implicit"
    trace["span"] = "implicit"

    traceability.add_trace(trace)

    trace["parent_item"] = "user"
    trace["item"] = "user_stereotype"
    trace["file"] = "implicit"
    trace["line"] = "implicit"
    trace["span"] = "implicit"

    traceability.add_trace(trace)

    trace["parent_item"] = "user"
    trace["item"] = "entrypoint"
    trace["file"] = "heuristic"
    trace["line"] = "heuristic"
    trace["span"] = "heuristic"

    traceability.add_trace(trace)

    trace["parent_item"] = "user"
    trace["item"] = "exitpoint"
    trace["file"] = "heuristic"
    trace["line"] = "heuristic"
    trace["span"] = "heuristic"

    traceability.add_trace(trace)

    return external_components


def add_user_connections(information_flows: dict, microservice: str) -> dict:

    key = max(information_flows.keys(), default=-1) + 1
    
    information_flows[key] = dict()
    information_flows[key]["sender"] = "user"
    information_flows[key]["receiver"] = microservice
    information_flows[key]["stereotype_instances"] = ["restful_http"]
    information_flows[key + 1] = dict()
    information_flows[key + 1]["sender"] = microservice
    information_flows[key + 1]["receiver"] = "user"
    information_flows[key + 1]["stereotype_instances"] = ["restful_http"]

    trace = {
        "item": f"user -> {microservice}",
        "file": "implicit",
        "line": "implicit",
        "span": "implicit"
    }
    traceability.add_trace(trace)

    trace["item"] = f"{microservice} -> user"
    traceability.add_trace(trace)

    return information_flows
