import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability


def detect_local_logging(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects if a service performs local logging.
    """

    microservices = detect_loggerfactory(microservices, dfd)
    microservices = detect_lombok(microservices, dfd)

    return microservices, information_flows


def detect_loggerfactory(microservices: dict, dfd) -> dict:
    """Detects logging directly via loggerfactory.
    """

    results = fi.search_keywords("LoggerFactory", file_extension=["*.java", "*.kt", "*.scala"])
    for r in results.keys():
        found = False
        if "test" in results[r]["path"].casefold():
            continue
        microservice = tech_sw.detect_microservice(results[r]["path"], dfd)
        for line in results[r]["content"]:
            if "LoggerFactory" in line:
                if "LoggerFactory.getLogger" in line and "=" in line:
                    logger = line.split("=")[0].strip().split(" ")[-1]
                    for line2 in results[r]["content"]:
                        for c in ["info", "error", "debug", "trace", "warn"]:
                            if f"{logger.casefold()}.{c}" in line2.casefold():       # logger is used -> find mciroservice and add stereotype
                                for m in microservices.values():
                                    if m["name"] == microservice:
                                        m.setdefault("stereotype_instances",[]).append("local_logging")
                                        found = True

                                        traceability.add_trace({
                                            "parent_item": m["name"],
                                            "item": "local_logging",
                                            "file": results[r]["path"],
                                            "line": results[r]["line_nr"],
                                            "span": results[r]["span"]
                                        })

                                        break
                                    if found: break
                            if found: break
                    if found: break
                if found: break

    return microservices


def detect_lombok(microservices: dict, dfd) -> dict:
    """Detects logging with Lombok.
    """

    annotations = ["Slf4j", "Log", "Log4j2", "CommonsLog"]
    for annotation in annotations:
        results = fi.search_keywords(annotation, file_extension=["*.java", "*.kt", "*.scala"])
        for r in results.keys():
            if "test" in results[r]["path"].casefold():
                continue

            annotation_found = False
            use_found = False

            for line in results[r]["content"]:
                if "@" + annotation in line:
                    annotation_found = True
                else:
                    for c in ["info", "error", "debug", "trace", "warn"]:
                        if ("log." + c) in line.casefold():
                            use_found = True

            if annotation_found and use_found:
                microservice = tech_sw.detect_microservice(results[r]["path"], dfd)
                for m in microservices.values():
                    if m["name"] == microservice:
                        m.setdefault("stereotype_instances",[]).append("local_logging")
                        m.setdefault("tagged_values",[]).append(("Logging Technology", "Lombok"))
                        traceability.add_trace({
                            "parent_item": m["name"],
                            "item": "local_logging",
                            "file": results[r]["path"],
                            "line": results[r]["line_nr"],
                            "span": results[r]["span"]
                        })

    return microservices
