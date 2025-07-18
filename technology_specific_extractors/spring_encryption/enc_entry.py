import core.file_interaction as fi
import core.technology_switch as tech_sw


def detect_spring_encryption(microservices: dict, information_flows: dict, dfd) -> dict:
    """Detects use of Spring's crypto module encryption functions.
    """

    microservices = detect_passwordEncoder(microservices, dfd)
    microservices = detect_bytesEncryptor(microservices, dfd)
    microservices = detect_keyGenerator(microservices, dfd)

    return microservices, information_flows


def detect_passwordEncoder(microservices: dict, dfd) -> dict:
    """Detetcs encryption with BCryptPasswordEncoder.
    """

    passwordencoders = ["BCryptPasswordEncoder", "Pbkdf2PasswordEncoder", "ShaPasswordEncoder"]
    encoders = set()

    for passwordencoder in passwordencoders:
        results = fi.search_keywords(passwordencoder)
        for r in results.values():
            for line in r["content"]:
                if f"= new {passwordencoder}" in line:
                    encoders.add(line.split("=")[0].strip().split(" ")[-1])

    for encoder in encoders:
        results = fi.search_keywords(encoder)
        for r in results.values():
            microservice = tech_sw.detect_microservice(r["path"], dfd)
            for line in r["content"]:
                if f"{encoder}.encode" in line:
                    for m in microservices.values():
                        if m["name"] == microservice:
                            m.setdefault("stereotype_instances",[]).append("encryption")

    return microservices


def detect_bytesEncryptor(microservices: dict, dfd) -> dict:
    """Detects uses of Spring Security's BytesEncryptor.
    """

    types = ["stronger", "standard", "text", "delux", "queryableText", "noOpText"]
    for type in types:
        results = fi.search_keywords(f"Encryptors {type}")
        for r in results.values():
            stereotypes, tagged_values = False, False
            microservice = tech_sw.detect_microservice(r["path"], dfd)
            for line in r["content"]:
                if f"Encryptors.{type}" in line:
                    stereotypes = "encryption"
                    try:
                        password = line.split(f"Encryptors.{type}(")[1].split(",")[0].strip()
                        tagged_values = ("Encrypted String", password)
                    except Exception:
                        password = False
                        
            for m in microservices.values():
                if m["name"] == microservice:
                    if stereotypes:
                        m.setdefault("stereotype_instances",[]).append(stereotypes)
                    if tagged_values:
                        m.setdefault("tagged_values",[]).append(tagged_values)
    return microservices


def detect_keyGenerator(microservices: dict, dfd) -> dict:
    """Detetcs Spring Security's KeyGenerators.
    """

    # Generate list of keygenerators
    keygenerators = []

    commands = ["string", "shared", "secureRandom"]
    results = fi.search_keywords("Keygenerator")
    for r in results.values():
        for command in commands:
            for line in r["content"]:
                if f"Keygenerator.{command}" in line:
                    # Direct use
                    if "().generateKey" in line:
                        microservice = tech_sw.detect_microservice(r["path"], dfd)
                        for m in microservices.values():
                            if m["name"] == microservice:
                                m.setdefault("stereotypes",[]).append("keygenerator")
                    # Creation here, use later
                    else:
                        keygenerators.add(extract_keygenerator(line))

    # Find uses of the keygenerators
    for keygenerator in keygenerators:
        results = fi.search_keywords(f"{keygenerator}.generateKey")
        for r in results.values():
            microservice = tech_sw.detect_microservice(r["path"], dfd)
            for m in microservices.values():
                if m["name"] == microservice:
                    m.setdefault("stereotypes",[]).append("keygenerator")

    return microservices


def extract_keygenerator(line: str) -> str:
    """Extracts name of a keygenerator from line provided as input.
    """

    if "=" in line:
        return line.split("=")[0].split(" ")[-1].strip()
    return str()
