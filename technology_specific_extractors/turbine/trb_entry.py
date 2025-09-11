import os

import core.file_interaction as fi
import core.technology_switch as tech_sw
import tmp.tmp as tmp
import output_generators.traceability as traceability


def detect_turbine(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects turbine server.
    """

    microservices = detect_turbine_server(microservices, dfd)
    microservices, information_flows = detect_turbineamqp(microservices, information_flows, dfd)
    microservices, information_flows = detect_turbine_stream(microservices, information_flows, dfd)

    return microservices, information_flows


def detect_turbine_server(microservices: dict, dfd) -> dict:
    """Detects standard turbine servers.
    """

    results = fi.search_keywords("@EnableTurbine", file_extension=["*.java", "*.kt", "*.scala"])     # content, name, path
    for r in results.values():
        microservice = tech_sw.detect_microservice(r["path"], dfd)
        for line in r["content"]:
            if "@EnableTurbine" in line:
                for m in microservices.values():
                    if m["name"] == microservice:
                        m.setdefault("stereotype_instances",[]).append("monitoring_server")
                        m.setdefault("tagged_values",[]).append(("Monitoring Server", "Turbine"))

                        traceability.add_trace({
                            "parent_item": m["name"],
                            "item": "monitoring_server",
                            "file": r["path"],
                            "line": r["line_nr"],
                            "span": r["span"]
                        })

    return microservices


def detect_turbineamqp(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects turbine servers implementes via EnableTurbineAmqp annotation.
    """

    results = fi.search_keywords("@EnableTurbineAmqp", file_extension=["*.java", "*.kt", "*.scala"])     # content, name, path
    for r in results.values():
        microservice = tech_sw.detect_microservice(r["path"], dfd)
        for line in r["content"]:
            if "@EnableTurbineAmqp" in line:
                for m in microservices.values():
                    if m["name"] == microservice:
                        m.setdefault("stereotype_instances",[]).append("monitoring_server")
                        m.setdefault("tagged_values",[]).append(("Monitoring Server", "Turbine"))

                        traceability.add_trace({
                            "parent_item": m["name"],
                            "item": "monitoring_server",
                            "file": r["path"],
                            "line": r["line_nr"],
                            "span": r["span"]
                        })

                    if ("Monitoring Dashboard", "Hystrix") in m["tagged_values"]:
                        dashboard = m["name"]

                        key = max(information_flows.keys(), default=-1) + 1
                        information_flows[key] = {
                            "sender": microservice,
                            "receiver": dashboard,
                            "stereotype_instances": ["restful_http"]
                        }
                        
                        traceability.add_trace({
                            "item": f"{microservice} -> {dashboard}",
                            "file": r["path"],
                            "line": r["line_nr"],
                            "span": r["span"]
                        })

                    elif ("Message Broker", "RabbitMQ") in m["tagged_values"]:
                        rabbitmq = m["name"]

                        key = max(information_flows.keys(), default=-1) + 1
                        information_flows[key] = {
                            "sender": rabbitmq,
                            "receiver": microservice,
                            "stereotype_instances": ["restful_http"]
                        }

                        traceability.add_trace({
                            "item": f"{rabbitmq} -> {microservice}",
                            "file": r["path"],
                            "line": r["line_nr"],
                            "span": r["span"]
                        })

    return microservices, information_flows


def detect_turbine_stream(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects Tubrine servers via EnableTurbineStream annotation.
    """

    uses_rabbit = False
    rabbitmq = False
    turbine_server = False
    results = fi.search_keywords("EnableTurbineStream", file_extension=["*.java", "*.kt", "*.scala"])     # content, name, path
    for r in results.values():
        trace_info = (False, False, False)
        microservice = tech_sw.detect_microservice(r["path"], dfd)
        for line in r["content"]:
            if "@EnableTurbineStream" in line:
                for m in microservices.values():
                    if m["name"] == microservice:
                        turbine_server = m["name"]
                        m.setdefault("stereotype_instances",[]).append("monitoring_server")
                        m.setdefault("tagged_values",[]).append(("Monitoring Server", "Turbine"))

                        traceability.add_trace({
                            "parent_item": m["name"],
                            "item": "monitoring_server",
                            "file": r["path"],
                            "line": r["line_nr"],
                            "span": r["span"]
                        })

                        # find pom_file and check which broker there is a dependency for
                        path = r["path"]
                        found_pom = False
                        local_repo_path = tmp.tmp_config["Repository"]["local_path"]
                        dirs = list()
                        path = os.path.dirname(path)
                        dirs.append(os.scandir(os.path.join(local_repo_path, path)))

                        while path != "" and not found_pom:
                            directory = dirs.pop()
                            for entry in directory:
                                if entry.is_file() and entry.name.casefold() == "pom.xml":
                                    with open(entry.path, "r") as file:
                                        lines = file.readlines()
                                    for line in lines:
                                        if "<artifactId>spring-cloud-starter-stream-rabbit</artifactId>" in line:
                                            uses_rabbit = True
                                            trace_info = (r["path"], r["line_nr"], r["span"])
                            path = os.path.dirname(path)
                            dirs.append(os.scandir(os.path.join(local_repo_path, path)))

                    if ("Monitoring Dashboard", "Hystrix") in m["tagged_values"]:
                        dashboard = m["name"]

                        key = max(information_flows.keys(), default=-1) + 1
                        information_flows[key] = {
                            "sender": microservice,
                            "receiver": dashboard,
                            "stereotype_instances": ["restful_http"]
                        }

                        traceability.add_trace({
                            "item": f"{microservice} -> {dashboard}",
                            "file": r["path"],
                            "line": r["line_nr"],
                            "span": r["span"]
                        })

                    if turbine_server and uses_rabbit:
                        if ("Message Broker", "RabbitMQ") in m["tagged_values"]:
                            rabbitmq = m["name"]

                            key = max(information_flows.keys(), default=-1) + 1
                            information_flows[key] = {
                                "sender": rabbitmq,
                                "receiver": turbine_server,
                                "stereotype_instances": ["restful_http"]
                            }

                            traceability.add_trace({
                                "item": f"{rabbitmq} -> {turbine_server}",
                                "file": trace_info[0],
                                "line": trace_info[1],
                                "span": trace_info[2]
                            })

                            # check if flow in other direction exists (can happen faultely in docker compse)
                            for i in information_flows:
                                if information_flows[i]["sender"] == turbine_server and information_flows[i]["receiver"] == rabbitmq:
                                    information_flows.pop(i)
            

    # clients:
    if uses_rabbit and rabbitmq:
        results = fi.search_keywords("spring-cloud-netflix-hystrix-stream", file_extension=["*.xml","*.gradle"])     # content, name, path
        for r in results.values():
            microservice = tech_sw.detect_microservice(r["path"], dfd)
            
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": microservice,
                "receiver": rabbitmq,
                "stereotype_instances": ["restful_http"]
            }

            traceability.add_trace({
                "item": f"{microservice} -> {rabbitmq}",
                "file": trace_info[0],
                "line": trace_info[1],
                "span": trace_info[2]
            })

    return microservices, information_flows
