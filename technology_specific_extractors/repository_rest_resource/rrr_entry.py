import core.file_interaction as fi
import core.technology_switch as tech_sw


def detect_endpoints(microservices: dict, dfd) -> dict:
    """Detects endpoints offered via @RepositoryRestResource
    """

    results = fi.search_keywords("@RepositoryRestResource", file_extension=["*.java", "*.kt"])
    for r in results.keys():
        endpoints = set()
        microservice = tech_sw.detect_microservice(results[r]["path"], dfd)
        for line in results[r]["content"]:
            if ("@RepositoryRestResource" in line) and ("path" in line):
                endpoint = line.split("path")[1].split(",")[0].strip().strip("=\"/() ")
                endpoint = f"/{endpoint}"
                endpoints.add(endpoint)
                # print("===============--------------------------===============")
                # print(endpoints)
                # print("===============--------------------------===============")
                for m in microservices.values():
                    if m["name"] == microservice:
                        m.setdefault("tagged_values", []).append(("Endpoints", list(endpoints)))
    
    return microservices
