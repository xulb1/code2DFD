import output_generators.traceability as traceability


def add_user(external_components: dict) -> dict:
    """Adds an user to the external components.
    """
    key = max(external_components.keys(), default=-1) + 1

    external_components[key] = {
        "name": "user",
        "type": "external_component",
        "stereotype_instances": ["user_stereotype", "entrypoint", "exitpoint"]
    }

    traceability.add_trace({
        "item": "user",
        "file": "implicit",
        "line": "implicit",
        "span": "implicit"
    })
    traceability.add_trace({
        "parent_item": "user",
        "item": "user_stereotype",
        "file": "implicit",
        "line": "implicit",
        "span": "implicit"
    })
    traceability.add_trace({
        "parent_item": "user",
        "item": "entrypoint",
        "file": "heuristic",
        "line": "heuristic",
        "span": "heuristic"
    })
    traceability.add_trace({
        "parent_item": "user",
        "item": "exitpoint",
        "file": "heuristic",
        "line": "heuristic",
        "span": "heuristic"
    })

    return external_components


def add_user_connections(information_flows: dict, microservice: str) -> dict:

    key = max(information_flows.keys(), default=-1) + 1
    
    information_flows[key] = {
        "sender": "user",
        "receiver": microservice,
        "stereotype_instances": ["restful_http"]
    }
    information_flows[key + 1] = {
        "sender": microservice,
        "receiver": "user",
        "stereotype_instances": ["restful_http"]
    }

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
