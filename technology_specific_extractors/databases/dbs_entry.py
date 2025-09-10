import core.file_interaction as fi
import output_generators.traceability as traceability

def detect_databases(microservices: dict) -> dict:
    """Detects databases.
    """

    for indice, m in microservices.items():
        database = False
        if "image" in m:
            if "mongo" in m["image"].lower() and "express" not in m["image"].lower():
                database = "MongoDB"
            elif "mysql" in m["image"].lower():
                database = "MySQL"
            elif "postgres" in m["image"].lower():
                database = "PostgreSQL"
            elif "mariadb" in m["image"].lower():
                database = "MariaDB"
            elif "mssql" in m["image"].lower():
                database = "Microsoft SQL Server"
            elif all(w in m["image"] for w in ["oracle.com", "database"]):
                database = "Oracle DB"
            elif "redis" in m["image"].lower():
                database = "Redis"
            elif "database" in m["image"].lower():
                print(f"\033[91mm{m["image"]}\033[0m")
                database = "Unknown DB"
            

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
    if path == "image_placeholder":
        return microservices
    dockerfile_lines = fi.check_dockerfile(path)

    database = False
    if not dockerfile_lines:
        return microservices
    
    for line in dockerfile_lines:
        if "FROM" in line:
            if "mongo" in line.lower() and "express" not in line.lower():
                database = "MongoDB"
            elif "mysql" in line.lower():
                database = "MySQL"
            elif "postgres" in line.lower():
                database = "PostgreSQL"
            elif "mariadb" in line.lower():
                database = "MariaDB"
            elif "mssql" in line.lower():
                database = "Microsoft SQL Server"
            elif all(w in line.lower() for w in ["oracle.com", "database"]):
                database = "Oracle DB"
            elif "redis" in line.lower():
                database = "Redis"
            elif "database" in line.lower():
                print(f"\033[91m{line}\033[0m")
                database = "Unknown DB"

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
