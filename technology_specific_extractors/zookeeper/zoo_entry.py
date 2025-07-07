import output_generators.traceability as traceability


def detect_zookeeper(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects ZooKeeper config services.
    """

    zookeeper_service = False

    # Service
    for m in microservices.values():
        if "wurstmeister/zookeeper" in m["image"]:
            zookeeper_service = m["name"]
            m.setdefault("stereotype_instances",[]).append("configuration_server")
            m.setdefault("tagged_values",[]).append(("Configuration Server", "ZooKeeper"))

        # Link to kafka if existing
    if zookeeper_service:
        kafka_service = False
        for m in microservices.values():
            for prop in m["tagged_values"]:
                if prop == ("Message Broker", "Kafka"):
                    kafka_service = m["name"]
        if kafka_service:
            key = max(information_flows.keys(), default=-1) + 1
            information_flows[key] = {
                "sender": zookeeper_service,
                "receiver": kafka_service,
                "stereotype_instances": ["restful_http"]
            }

            # check if link in other direction
            to_purge = set()
            for i in information_flows:
                if information_flows[i]["sender"] == kafka_service and information_flows[i]["receiver"] == zookeeper_service:
                    to_purge.add(i)
            for p in to_purge:
                information_flows.pop(p)

    return microservices, information_flows
