"""
Détecteurs de logging pour applications Java microservices.
"""
from typing import Dict, Any, Tuple, List, Set, Optional
from javalang import tree
import re
import logging

import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability

logger = logging.getLogger(__name__)

# TODO: add tag to microservices, and avoid duplication...


# ----------------- constantes -----------------
LOGGING_JAVA_EXT = ["*.java", "*.kt", "*.scala"]
LOG_CONFIG_EXTS = ["Dockerfile", "*.gradle", "*.xml", "*.yml", "*.yaml", "*.properties", "*.tf", "*.sh", "*.json", "*.conf"]


CENTRAL_KEYWORDS = [
    "elasticsearch", "logstash", "kibana", "fluentd", "fluent-bit",
    "filebeat", "loki", "grafana", "splunk", "graylog", "rsyslog"
]

AGENT_CONFIG_FILES = ["fluentd.conf", "fluent-bit.conf", "filebeat.yml", "filebeat.yaml", "fluent.conf"]

FILE_APPENDER_KEYWORDS = ["FileAppender", "RollingFileAppender", "<appender", "appender name", "File="]
DIRECT_SHIP_KEYWORDS = ["SocketAppender", "LogstashTcpSocketAppender", "HttpAppender", "ElasticsearchAppender", "tcp://", "udp://", "http://", "https://"]

LOMBOK_ANNOTATIONS = ["Slf4j", "Log", "Log4j2", "CommonsLog"]

SANITIZE_KEYWORDS = ["mask", "redact", "anonym", "drop_fields", "remove_fields", "filter_record_transformer", "processors", "mask_fields", "sanitize", "obfuscate"]

BROKER_KEYWORDS = ["kafka", "rabbitmq", "amqp", "activemq", "mqtt"]
TLS_INDICATORS = {
    "config": [
        "spring.kafka.ssl.",
        "spring.rabbitmq.ssl.",
        "security.protocol=SSL",
        "ssl.keystore",
        "ssl.truststore",
        # TODO: comment gérer les espaces entre avant/après le "="
        "ssl.enabled=true",
        "tls.enabled"],
    "java_code":[
        "SslHandler",
        "SslContextFactory"]
    }
HEALTH_INDICATORS = ["management.health.kafka.enabled=true","management.health.rabbit.enabled=true","/health", "livenessProbe", "readinessProbe", "actuator", "metrics","HealthIndicator"]

SENSITIVE_IDENTIFIERS = ["password", "passwd", "secret", "token", "apiKey", "apikey", "ssn", "credential", "credentials", "key"]

# try import javalang for AST based detection
try:
    import javalang  # type: ignore
    JAVALANG_AVAILABLE = True
except Exception:
    JAVALANG_AVAILABLE = False
    logger.info("javalang not available: AST detection will fallback to regex heuristics.")


# ----------------- helpers -----------------
def _add_trace(parent: str, item: str, file: str, line: int = None, span=None, note: str = None):
    traceability.add_trace({
        "parent_item": parent,
        "item": item,
        "file": file,
        "line": line,
        "span": span,
        "note": note
    })


def _merge_results_for_keywords(keywords: List[str], directory_path: Optional[str]=None, file_extension: Optional[List[str]]=None) -> Dict[str, Any]:
    """
    Appelle fi.search_keywords pour chaque keyword et fusionne les résultats.
    Renvoie un dict {key::id : result_dict} similaire à la forme précédente.
    """
    aggregated = {}
    for kw in keywords:
        try:
            results = fi.search_keywords(kw, directory_path=directory_path, file_extension=file_extension)
        except TypeError:
            results = fi.search_keywords(kw)
        for k, v in results.items():
            aggregated[f"{kw}::{k}"] = v
    return aggregated


# ----------------- détecteurs qui modifient microservices -----------------
def detect_loggerfactory_and_mark(microservices: Dict[str, dict], dfd) -> Dict[str, dict]:
    """
    Recherche LoggerFactory.getLogger(...) puis recherche usages (info, error, ...)
    Si trouvé, met à jour microservices[ms]['stereotype_instances'] avec 'local_logging'
    """
    results = fi.search_keywords("LoggerFactory", file_extension=LOGGING_JAVA_EXT)
    for r in results.keys():
        entry = results[r]
        path = entry.get("path")
        if not path or "test" in path.casefold():
            continue
        content = entry.get("content", [])
        ms_name = tech_sw.detect_microservice(path, dfd)
        if not ms_name:
            print("Service non-trouvé:",path)
            continue
        # trouve la variable logger déclarée
        logger_var = None
        line_nr = entry.get("line_nr")
        span = entry.get("span")
        for line in content:
            if "LoggerFactory.getLogger" in line and "=" in line:
                tokens = line.split("=")[0].strip().split()
                if tokens:
                    logger_var = tokens[-1]
                break
        if not logger_var:
            continue
        # recherche utilisations
        used = False
        for line in content:
            if re.search(rf"\b{re.escape(logger_var)}\s*\.\s*(info|error|warn|debug|trace)\b", line, flags=re.IGNORECASE):
                used = True
                break
        if used:
            ms = [m for m in microservices.values() if m['name'] == ms_name]
            if not ms:
                key = max(microservices.keys(), default=-1) + 1
                microservices[key] = {
                    "name": ms_name,
                    "stereotype_instances": []
                }
                ms = microservices[key]
            else :
                ms = ms[0]

            if "local_logging" not in ms["stereotype_instances"]:
                ms["stereotype_instances"].append("local_logging")
            ms.setdefault("tagged_values", []).append(("Logging Technology", "LoggerFactory"))
            _add_trace(ms_name, "local_logging", path, line_nr, span, note="LoggerFactory usage")
    return microservices


def detect_lombok_and_mark(microservices: Dict[str, dict], dfd) -> Dict[str, dict]:
    """
    Recherche annotations lombok @Slf4j, @Log, etc. et usages log.info(...)
    Met à jour microservices directement.
    """
    for ann in LOMBOK_ANNOTATIONS:
        results = fi.search_keywords("@" + ann, file_extension=LOGGING_JAVA_EXT)
        for r in results.keys():
            entry = results[r]
            path = entry.get("path")
            if not path or "test" in path.casefold():
                continue
            content = entry.get("content", [])
            ms_name = tech_sw.detect_microservice(path, dfd)
            if not ms_name:
                print("Service non-trouvé:",path)
                continue
            annotation_found = any(f"@{ann}" in line for line in content)
            use_found = any(re.search(r"\blog\.(info|error|warn|debug|trace)\b", line, flags=re.IGNORECASE) for line in content)
            if annotation_found and use_found:
                ms = [m for m in microservices.values() if m['name'] == ms_name]
                if not ms:
                    key = max(microservices.keys(), default=-1) + 1
                    microservices[key] = {
                        "name": ms_name,
                        "stereotype_instances": []
                    }
                    ms = microservices[key]
                else :
                    ms = ms[0]

                if "local_logging" not in ms["stereotype_instances"]:
                    ms["stereotype_instances"].append("local_logging")
                
                ms.setdefault("tagged_values", []).append(("Logging Technology", "Lombok"))
                _add_trace(ms_name, "local_logging", path, entry.get("line_nr"), entry.get("span"), note=f"Lombok @{ann}")
    return microservices


def detect_file_appenders_and_mark(microservices: Dict[str, dict], dfd) -> Dict[str, dict]:
    """
    Détecte appenders file/rolling dans fichiers de config (logback/log4j2) et marque les microservices associés.
    """
    for kw in FILE_APPENDER_KEYWORDS:
        results = fi.search_keywords(kw, file_extension=LOG_CONFIG_EXTS)
        for r in results.keys():
            entry = results[r]
            path = entry.get("path")
            if not path:
                continue
            ms_name = tech_sw.detect_microservice(path, dfd)
            if not ms_name:
                print("Service non-trouvé:",path)
                continue
            
            ms = [m for m in microservices.values() if m['name'] == ms_name]
            if not ms:
                key = max(microservices.keys(), default=-1) + 1
                microservices[key] = {
                    "name": ms_name,
                    "stereotype_instances": []
                }
                ms = microservices[key]
            else :
                ms = ms[0]

            if "local_logging" not in ms["stereotype_instances"]:
                ms["stereotype_instances"].append("local_logging")
            ms.setdefault("tagged_values", []).append(("Logging Technology", "FileAppender")) #:{kw}"))
            _add_trace(ms_name, "local_logging", path, entry.get("line_nr"), entry.get("span"), note=f"file appender keyword {kw}")
    return microservices


# ----------------- AST / regex detection des logs exposant des secrets -----------------
def _expr_contains_sensitive_identifier_javalang(node) -> bool:
    """
    Inspecte récursivement un nœud javalang pour déterminer si une expression contient
    un identifiant sensible (password, token, apiKey...) ou une concaténation impliquant ces identifiants.
    """
    sensitive = False
    # Literal like "password=..." is not by itself sensitive on AST; MemberReference or Literal containing sensitive token is suspect
    if isinstance(node, tree.Literal):
        # literal.value est la string littérale: includes quotes
        val = getattr(node, "value", "") or ""
        if any(k.lower() in val.lower() for k in SENSITIVE_IDENTIFIERS):
            return True
    if isinstance(node, tree.MemberReference):
        # node.member est le nom de la variable ou champ
        if any(k.lower() in (node.member or "").lower() for k in SENSITIVE_IDENTIFIERS):
            return True
    if isinstance(node, tree.BinaryOperation):
        # ex: "pwd=" + password
        left = getattr(node, "operandl", None) or getattr(node, "left", None)
        right = getattr(node, "operandr", None) or getattr(node, "right", None)
        if left and _expr_contains_sensitive_identifier_javalang(left):
            return True
        if right and _expr_contains_sensitive_identifier_javalang(right):
            return True
    if isinstance(node, tree.MethodInvocation):
        # inspect arguments
        for arg in getattr(node, "arguments", []) or []:
            if _expr_contains_sensitive_identifier_javalang(arg):
                return True
    # for ArraySelector, ReferenceType etc - descend via attributes
    # fallback: inspect children via .children if available
    try:
        for child in node.children:
            if isinstance(child, (list, tuple)):
                for c in child:
                    if hasattr(c, "children") and _expr_contains_sensitive_identifier_javalang(c):
                        return True
            else:
                if hasattr(child, "children") and _expr_contains_sensitive_identifier_javalang(child):
                    return True
    except Exception:
        pass
    return sensitive


def detect_sensitive_logging_ast(microservices: Dict[str, dict], dfd) -> Dict[str, dict]:
    """
    Parcourt les fichiers Java et détecte, via AST si possible, des appels de log où un secret
    pourrait être exposé. Marque le microservice avec tagged_values ('SensitiveLogging', reason).
    """

    java_files = fi.search_keywords("logger.", file_extension=LOGGING_JAVA_EXT)

    # if search returned nothing, try LoggerFactory
    if not java_files:
        java_files = fi.search_keywords("LoggerFactory", file_extension=LOGGING_JAVA_EXT)

    for r in java_files.keys():
        entry = java_files[r]
        path = entry.get("path")
        if not path or "test" in path.casefold():
            continue
        ms_name = tech_sw.detect_microservice(path, dfd)
        if not ms_name:
            print("Service non-trouvé:",path)
            continue
        content_lines = entry.get("content", [])
        joined = "\n".join(content_lines)
        suspicious_found = False
        evidence_note = None

        # Prefer AST detection
        if JAVALANG_AVAILABLE and path.endswith(".java"):
            try:
                tree = javalang.parse.parse(joined)
                for _, node in tree.filter(javalang.tree.MethodInvocation):
                    # qualifier peut être 'logger' or variable name
                    qualifier = getattr(node, "qualifier", None) or ""
                    member = getattr(node, "member", "") or ""
                    # check common logging method names
                    if re.match(r"^(info|error|warn|debug|trace)$", member, flags=re.IGNORECASE):
                        # inspect arguments
                        for arg in getattr(node, "arguments", []) or []:
                            if _expr_contains_sensitive_identifier_javalang(arg):
                                suspicious_found = True
                                evidence_note = f"AST: logger call with sensitive expr in {member}()"
                                break
                    if re.match(r"^(info|error|warn|debug|trace)$", qualifier, flags=re.IGNORECASE):
                        # inspect arguments
                        for arg in getattr(node, "arguments", []) or []:
                            if _expr_contains_sensitive_identifier_javalang(arg):
                                suspicious_found = True
                                evidence_note = f"AST: logger call with sensitive expr in {qualifier}()"
                                break
                    if suspicious_found:
                        break
            except Exception:
                # parsing failed, fallback to regex
                logger.debug("javalang parse failed for %s, fallback to regex", path)
                JAVALANG_LOCAL_FALLBACK = True
        else:
            JAVALANG_LOCAL_FALLBACK = True

        # fallback detection by regex/heuristics if AST absent or failed
        if not suspicious_found:
            # simple heuristics:
            # - logger.info("..."+password)
            # - logger.info(password)
            # - logger.info(String.format(..., password))
            # - logger.info("user="+user)
            for i, line in enumerate(content_lines):
                if re.search(r"\blog\.(info|error|warn|debug|trace)\s*\(", line, flags=re.IGNORECASE) or re.search(r"\b\w+Logger\.(info|error|warn|debug|trace)\s*\(", line, flags=re.IGNORECASE):
                    # look at this line and a few next lines (multi-line args)
                    window = " ".join(content_lines[i:i+4])
                    # concat with + and sensitive var
                    if re.search(r'(\+)\s*(' + r'|'.join(map(re.escape, SENSITIVE_IDENTIFIERS)) + r")\b", window, flags=re.IGNORECASE):
                        suspicious_found = True
                        evidence_note = "Concatenation with sensitive identifier near logger call"
                        break
                    # direct argument is a sensitive variable (logger.info(password))
                    if re.search(r"\b(?:logger|LOG|log)\s*\.\s*(?:info|error|warn|debug|trace)\s*\(\s*(" + r'|'.join(SENSITIVE_IDENTIFIERS) + r")\b", window, flags=re.IGNORECASE):
                        suspicious_found = True
                        evidence_note = "Direct sensitive variable passed to logger"
                        break
                    # String.format(..., password)
                    if re.search(r"String\.format\s*\(.*\b(" + r'|'.join(SENSITIVE_IDENTIFIERS) + r")\b", window, flags=re.IGNORECASE):
                        suspicious_found = True
                        evidence_note = "String.format with sensitive variable"
                        break
                    # replaceAll with sensitive patterns used to obfuscate - we regard presence as good if it's used to sanitize,
                    # but if replaceAll is applied incorrectly (no mask), we can't easily judge statically.
        if suspicious_found:
            ms = [m for m in microservices.values() if m['name'] == ms_name]
            if not ms:
                key = max(microservices.keys(), default=-1) + 1
                microservices[key] = {
                    "name": ms_name,
                    "stereotype_instances": []
                }
                ms = microservices[key]
            else:
                ms = ms[0]

            ms.setdefault("tagged_values", []).append(("SensitiveLogging", evidence_note))
            ms.setdefault("stereotype_instances", []).append("local_logging_suspect")
            _add_trace(ms_name, "sensitive_logging", path, entry.get("line_nr"), entry.get("span"), note=evidence_note)
    return microservices


# ----------------- infra detectors (R9, agent, sanitization, broker/tls) -----------------
def detect_central_logging_components(microservices: dict, dfd) -> dict:
    """
    Detects the presence of central logging components in microservice configurations.
    """
    for kw in CENTRAL_KEYWORDS:
        results = fi.search_keywords(kw, file_extension=["*.yml", "*.yaml", "*.json", "*.md", "*.txt"])
        for r in results.keys():
            entry = results[r]
            path = entry.get("path")
            
            ms_name = tech_sw.detect_microservice(path, dfd)
            if not ms_name:
                print("Service non-trouvé:",path)
                continue
            
            ms = [m for m in microservices.values() if m['name'] == ms_name]
            if not ms:
                key = max(microservices.keys(), default=-1) + 1
                microservices[key] = {"name": ms_name}
                ms = microservices[key]
            else :
                ms = ms[0]

            ms.setdefault("tagged_values", []).append(("Central Logger", kw))
            ms.setdefault("stereotype_instances", []).append("central_logging_server")
            _add_trace("central_logging", "component_found", path, entry.get("line_nr"), entry.get("span"))
    
    return microservices


def detect_local_agents(microservices: dict, dfd) -> dict:
    """
    Detects the presence of local logging agents in microservice environments.
    """
    for filename in AGENT_CONFIG_FILES:
        results = fi.search_keywords(filename, file_extension=["*.*"])
        for r in results.keys():
            entry = results[r]
            path = entry.get("path")
            
            ms_name = tech_sw.detect_microservice(path, dfd)
            if not ms_name:
                print("Service non-trouvé:",path)
                continue
            
            ms = [m for m in microservices.values() if m['name'] == ms_name]
            if not ms:
                key = max(microservices.keys(), default=-1) + 1
                microservices[key] = {"name": ms_name}
                ms = microservices[key]
            else :
                ms = ms[0]

            ms.setdefault("tagged_values", []).append(("Local Agent", filename.split('.')[0]))
            ms.setdefault("stereotype_instances", []).append("local_logging_agent")
            _add_trace("local_agent", "config_found", path, entry.get("line_nr"), entry.get("span"))
    
    # manifest mentions
    for kw in ["fluentd", "fluent-bit", "filebeat", "promtail"]:
        ag_results = fi.search_keywords(kw, file_extension=["*.yml", "*.yaml", "*.json"])
        for k in ag_results.keys():
            entry = ag_results[k]
            path = entry.get("path")
            
            ms_name = tech_sw.detect_microservice(path, dfd)
            if not ms_name:
                print("Service non-trouvé:",path)
                continue
            
            ms = [m for m in microservices.values() if m['name'] == ms_name]
            if not ms:
                key = max(microservices.keys(), default=-1) + 1
                microservices[key] = {"name": ms_name}
                ms = microservices[key]
            else :
                ms = ms[0]
                
            ms.setdefault("tagged_values", []).append(("Local Agent", kw))
            ms.setdefault("stereotype_instances", []).append("local_logging_agent")
            _add_trace("local_agent", "manifest_mention", path, entry.get("line_nr"), entry.get("span"))
    
    return microservices


def detect_sanitization_mechanisms(microservices: dict, dfd) -> dict:
    """
    Detects the presence of sanitization mechanisms in microservice configurations and code.
    """
    cfg_results = _merge_results_for_keywords(SANITIZE_KEYWORDS, file_extension=["*.yml", "*.yaml", "*.conf", "*.xml", "*.properties"])
    for k in cfg_results.keys():
        entry = cfg_results[k]
        path = entry.get("path")
        ms_name = tech_sw.detect_microservice(path, dfd)
        if not ms_name:
            print("Service non-trouvé:",path)
            continue
        
        ms = [m for m in microservices.values() if m['name'] == ms_name]
        if not ms:
            key = max(microservices.keys(), default=-1) + 1
            microservices[key] = {"name": ms_name}
            ms = microservices[key]
        else :
            ms = ms[0]

        ms.setdefault("stereotype_instances", []).append("sanitization_mechanism")
        _add_trace("sanitization", "config_keyword", path, entry.get("line_nr"), entry.get("span"))
    # code replaceAll(...) for secret masking
    repl_results = fi.search_keywords("replaceAll(", file_extension=LOGGING_JAVA_EXT)
    for r in repl_results.keys():
        entry = repl_results[r]
        path = entry.get("path")
        lines = entry.get("content", [])
        for i, line in enumerate(lines):
            if re.search(r"replaceAll\(.{0,120}(password|secret|token|apikey|apiKey).{0,120}\)", line, flags=re.IGNORECASE):
                ms_name = tech_sw.detect_microservice(path, dfd)
                if not ms_name:
                    print("Service non-trouvé:",path)
                    continue
                
                ms = [m for m in microservices.values() if m['name'] == ms_name]
                if not ms:
                    key = max(microservices.keys(), default=-1) + 1
                    microservices[key] = {"name": ms_name}
                    ms = microservices[key]
                else:
                    ms = ms[0]

                ms.setdefault("stereotype_instances", []).append("sanitization_mechanism")
                _add_trace("sanitization", "code_redaction", path, entry.get("line_nr"), entry.get("span"))
                break
    
    return microservices


def detect_broker_and_security(microservices: dict, dfd) -> dict:
    """
    Identifies message broker usage and associated security mechanisms in microservices.
    """
    for b in BROKER_KEYWORDS:
        results = fi.search_keywords(b, file_extension=["*.yml", "*.yaml", "*.properties", "*.xml", "*.java", "*.kt", "*.scala"])
        for r in results.keys():
            entry = results[r]
            path = entry.get("path")
            ms_name = tech_sw.detect_microservice(path, dfd)
            if not ms_name:
                print("Service non-trouvé:",path)
                continue
            ms = [m for m in microservices.values() if m['name'] == ms_name]
            if not ms:
                key = max(microservices.keys(), default=-1) + 1
                microservices[key] = {"name": ms_name}
                ms = microservices[key]
            else:
                ms = ms[0]
            ms.setdefault("tagged_values", []).append(("Message Broker", b))
            ms.setdefault("stereotype_instances", []).append("message_broker")
            _add_trace("broker", "mention", entry.get("path"), entry.get("line_nr"), entry.get("span"))
    for m in microservices.values():
        if "broker" in m["stereotype_instances"]:
            path = m["path"]
            for t in TLS_INDICATORS:
                results = fi.search_keywords(t, directory_path=path, file_extension=["*.conf", "*.yml", "*.yaml", "*.properties", "*.xml"])
                for r in results.keys():
                    entry = results[r]
                    # m.setdefault("tagged_values", []).append(("Security", "Broker TLS Enabled"))
                    m.setdefault("stereotype_instances", []).append("broker_tls_enabled")
                    _add_trace("broker_tls", "tls_indicator", entry.get("path"), entry.get("line_nr"), entry.get("span"))
    
    for m in microservices.values():
        if "broker" in m["stereotype_instances"]:
            path = m["path"]
            for h in HEALTH_INDICATORS:
                results = fi.search_keywords(h, directory_path=path)
                                            #  file_extension=["*.yml", "*.yaml", "*.java", "*.kt", "*.scala", "*.properties"])
                for r in results.keys():
                    entry = results[r]
                    m.setdefault("stereotype_instances", []).append("monitored_message_broker")
                    _add_trace("health", "indicator", entry.get("path"), entry.get("line_nr"), entry.get("span"))
    
    return microservices


# --------------- orchestration ---------------
def analyze_logging_architecture(microservices: Dict[str, dict], information_flows: Dict, dfd) -> Dict[str, Any]:
    """
    Orchestration haute-niveau :
     - détections infra R9, R10 (partiel), R11, R12,
    """
    print("-------------------- CHECK LOGGING --------------------")
    # Detect and mark local logging at code level
    microservices = detect_loggerfactory_and_mark(microservices, dfd)
    microservices = detect_lombok_and_mark(microservices, dfd)
    microservices = detect_file_appenders_and_mark(microservices, dfd)

    # AST-based detection of sensitive logging
    microservices = detect_sensitive_logging_ast(microservices, dfd)

    # R9 - infra detectors
    microservices = detect_central_logging_components(microservices,dfd)

    # R10 - local agents
    microservices = detect_local_agents(microservices,dfd)
    
    # R11 - sanitization mechanism
    microservices = detect_sanitization_mechanisms(microservices, dfd)

    # R12 - broker
    brsec = detect_broker_and_security(microservices, dfd)

    return microservices
