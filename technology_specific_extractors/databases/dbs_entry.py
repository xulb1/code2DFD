import core.file_interaction as fi
import output_generators.traceability as traceability

def detect_databases(microservices: dict) -> dict:
    """Detects databases.
    """

    for indice, m in microservices.items():
        database = False
        if "image" in m:
            if "mongo:" in m["image"]:
                database = "MongoDB"
            elif "mysql-server:" in m["image"]:
                database = "MySQL"

        if database:
            m["type"] == "database_component"
            m.setdefault("stereotype_instances",[]).append("database")
            m.setdefault("tagged_values",[]).append(("Database", database))

            traceability.add_trace({
                "parent_item": m["name"],
                "item": "database",
                "file": "heuristic, based on image",
                "line": "heuristic, based on image",
                "span": "heuristic, based on image"
            })
        else:
            microservices = detect_via_docker(microservices, indice)

    return microservices


def detect_via_docker(microservices: dict, m: int) -> dict:
    """Checks microservifces' build paths for dockerfile. If found, parses for possible databases.
    """

    path = microservices[m]["image"]
    dockerfile_lines = fi.check_dockerfile(path)

    database = False
    if not dockerfile_lines:
        return microservices
    
    for line in dockerfile_lines:
        if "FROM" in line:
            if "mongo" in line:
                database = "MongoDB"
            elif "postgres" in line:
                database = "PostgreSQL"

    if not database:
        return microservices
    
    microservices[m]["type"] = "database_component"
    microservices[m].setdefault("stereotype_instances",[]).append("database")
    microservices[m].setdefault("tagged_values",[]).append(("Database", database))
    
    traceability.add_trace({
        "parent_item": microservices[m]["name"],
        "item": "database",
        "file": "heuristic, based on Dockerfile base image",
        "line": "heuristic, based on Dockerfile base image",
        "span": "heuristic, based on Dockerfile base image"
    })

    return microservices
