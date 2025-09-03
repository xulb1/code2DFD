import ast

import technology_specific_extractors.environment_variables as env
import core.technology_switch as tech_sw
import tmp.tmp as tmp
import output_generators.traceability as traceability


def set_information_flows(dfd) -> set:
    """Goes through services and checks if there are connections to databases.
    """

    information_flows = dict()
    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])

    external_components = dict()
    if tmp.tmp_config.has_option("DFD", "external_components"):
        external_components = ast.literal_eval(tmp.tmp_config["DFD"]["external_components"])

    microservices = tech_sw.get_microservices(dfd)

    microservices, information_flows, external_components = check_properties(microservices, information_flows, external_components)

    tmp.tmp_config.set("DFD", "information_flows", str(information_flows).replace("%", "%%"))
    tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))
    tmp.tmp_config.set("DFD", "external_components", str(external_components).replace("%", "%%"))
    return microservices, information_flows


def get_information_flows(microservices: dict, information_flows: dict, external_components: dict) -> dict:

    microservices, information_flows, external_components = check_properties(microservices, information_flows, external_components)

    return microservices, information_flows, external_components


def check_properties(microservices: dict, information_flows: dict, external_components: dict) -> dict:
    """Checks microservices' properties for connection details to datasources. If found, sets these connections.
    """

    for m in microservices.values():
        database_service, username, password, database_url = False, False, False, False
        trace_info = (False, False, False)
        sender = m["name"]
        for prop in m["properties"]:
            if prop[0] == "datasource_url":
                trace_info = (prop[2][0], prop[2][1], prop[2][2])
                if "mem:" in prop[1]:    # in-memory database
                    pass
                else:
                    database_url = prop[1]
                    parts = database_url.split("/")
                    for mi in microservices.values():
                        if mi["name"] in parts:
                            database_service = mi["name"]
            elif prop[0] == "datasource_host":
                trace_info = (prop[2][0], prop[2][1], prop[2][2])
                for mi in microservices.values():
                    if mi["name"] == prop[1]:
                        database_service = mi["name"]
            elif prop[0] == "datasource_uri":
                trace_info = (prop[2][0], prop[2][1], prop[2][2])
                database = prop[1].split("://")[1].split("/")[0]
                for mi in microservices.values():
                    if mi["name"] == database:
                        database_service = mi["name"]
            if prop[0] == "datasource_username":
                username = env.resolve_env_var(prop[1])
            if prop[0] == "datasource_password":
                password = env.resolve_env_var(prop[1])

        if database_service:    # found a connection to a microservice
            # set information flow
            key = max(information_flows.keys(), default=-1) + 1

            information_flows[key] = {
                "sender": database_service,
                "receiver": sender,
                "stereotype_instances": ["jdbc"]
            }
            if password:
                information_flows[key].setdefault("tagged_values",[]).append(("Password", password.strip()))
            if username:
                information_flows[key].setdefault("tagged_values",[]).append(("Username", username.strip()))
            if username or password:
                information_flows[key]["stereotype_instances"].append("plaintext_credentials_link")

            traceability.add_trace({
                "item": f"{database_service} -> {sender}",
                "file": trace_info[0],
                "line": trace_info[1],
                "span": trace_info[2]
            })

            # adjust service to database
            for mk in microservices.values():
                if mk["name"] == database_service:
                    mk["type"] = "database_component"
                    mk.setdefault("stereotype_instances",[]).append("database")
                    if password:
                        mk["stereotype_instances"].append("plaintext_credentials")
                        mk.setdefault("tagged_values",[]).append(("Password", password.strip()))
                    if username:
                        mk["stereotype_instances"].append("plaintext_credentials")
                        mk.setdefault("tagged_values",[]).append(("Username", username.strip()))

            # check if information flow in other direction exists (can happen faultely in docker-compose)
            for i in information_flows:
                if information_flows[i]["sender"] == sender and information_flows[i]["receiver"] == database_service:
                    information_flows.pop(i)

        elif database_url:  # found a connection to an unknown url

            # determine port if possible
            port = False
            if "localhost:" in database_url:
                port = database_url.split("localhost:")[1].split("/")[0].strip().strip("\"")

            # determines type of DB
            database_type = False
            for prop in m["properties"]:
                if prop[0] == "datasource_type":
                    database_type = prop[1]

            if not database_type:
                if "mysql" in database_url.casefold():
                    database_type = "MySQL"
                elif "mongo" in database_url.casefold():
                    database_type = "MongoDB"
                elif "postgres" in database_url.casefold():
                    database_type = "PostgreSQL"
                elif "neo4j" in database_url.casefold():
                    database_type = "Neo4j"
                else:
                    database_type = "UnknownDB"

            #FIXME: duplicate database found
            # create external component
            key = max(external_components.keys(), default=-1) + 1
            external_components[key] = {
                "name": "database-" + str(m["name"]),
                "type": "external_component",
                "stereotype_instances": ["entrypoint", "exitpoint", "external_database"]
            }

            trace = {
                "item": f"database-{m['name']}",
                "file": trace_info[0],
                "line": trace_info[1],
                "span": trace_info[2]
            }

            traceability.add_trace(trace)

            if database_type:
                external_components[key].setdefault("tagged_values",[]).append(("Database", database_type))

            if port:
                external_components[key].setdefault("tagged_values",[]).append(("Port", port))

            if password:
                external_components[key].setdefault("tagged_values",[]).append(("Password", password.strip()))
                external_components[key].setdefault("stereotype_instances",[]).append("plaintext_credentials")
                
            if username:
                external_components[key].setdefault("tagged_values",[]).append(("Username", username.strip()))
                external_components[key].setdefault("stereotype_instances",[]).append("plaintext_credentials")

            # set information flow
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": f"database-{m['name']}",
                "receiver": m["name"],
                "stereotype_instances": ["jdbc"]
            }
            
            if username or password:
                information_flows[key]["stereotype_instances"].append("plaintext_credentials_link")

            if password:
                information_flows[key].setdefault("tagged_values", []).append(("Password", password.strip()))
            if username:
                information_flows[key].setdefault("tagged_values", []).append(("Username", username.strip()))

            tmp.tmp_config.set("DFD", "external_components", str(external_components).replace("%", "%%"))

            traceability.add_trace({
                "item": f"database-{m['name']}) -> {m['name']}",
                "file": trace_info[0],
                "line": trace_info[1],
                "span": trace_info[2]
            })

    return microservices, information_flows, external_components


def clean_database_connections(microservices: dict, information_flows: dict):
    """Removes database connections in wrong direction, which can occur from docker compose.
    """

    to_purge = set()
    for microservice in microservices.values():
        if microservice["type"] == "database_component":
            for i in information_flows:
                if information_flows[i]["receiver"] == microservice["name"]:
                    to_purge.add(i)
    
    for p in to_purge:
        del information_flows[p]
