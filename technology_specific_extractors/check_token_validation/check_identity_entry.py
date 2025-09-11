"""
Détecteurs de sécurité pour applications Java microservices - R4 et R5.

R4: Transformation des identités externes en représentations internes sécurisées.
R5: Validation des tokens d'authentification.
"""

from typing import Dict, Any, List, Optional
import logging

import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability

logger = logging.getLogger(__name__)


JAVA_EXT = ["*.java", "*.kt", "*.scala"]
AUTH_CONFIG_EXT = [
    "*.yml", "*.yaml", "*.properties", "*.conf", "*.ini", "*.xml", "*.json",
    "docker-compose.yml", "Dockerfile"
]

def _add_trace(ms_name: str, item: str, file: str, line: Optional[int] = None, span=None, note: Optional[str] = None):
    traceability.add_trace({
        "parent_item": ms_name,
        "item": item,
        "file": file,
        "line": line,
        "span": span,
        "note": note
    })

def _merge_results_for_keywords(keywords: List[str], file_extension: List[str]) -> Dict[str, Any]:
    """
    Appelle fi.search_keywords pour chaque keyword et fusionne les résultats.
    """
    aggregated = {}
    for kw in keywords:
        try:
            results = fi.search_keywords(kw, file_extension=file_extension)
        except TypeError:
            results = fi.search_keywords(kw)
        for k, v in results.items():
            aggregated[f"{kw}::{k}"] = v
    return aggregated

def _ensure_microservice_entry(microservices: Dict[str, dict], ms_name: str) -> dict:
    ms = [m for m in microservices.values() if m['name'] == ms_name]
    if not ms:
        key = max(microservices.keys(), default=-1) + 1
        microservices[key] = {"name": ms_name, "stereotype_instances": []}
        return microservices[key]
    else:
        return ms[0]

# __________________________________________________________________________________
# ---------------------------------- détecteur R4 ----------------------------------
# ``````````````````````````````````````````````````````````````````````````````````
IDENTITY_KEYWORDS_STRONG = [
    "JwtDecoder", "NimbusJwtDecoder", "JwtEncoder",
    "io.jsonwebtoken",
    "spring.security.oauth2.resourceserver.jwt.issuer-uri",
    "spring.security.oauth2.resourceserver.jwt.jwk-set-uri"
]

IDENTITY_KEYWORDS_WEAK = [
    "InternalIdentity", "SignedIdentity", "SecurityContext"
]

def detect_internal_identity(microservices: Dict[str, dict], dfd) -> Dict[str, dict]:
    """
    R4: Vérifie que les identités externes sont transformées en représentations internes signées.
    Recherche: 
        - indices forts : JWT, Keycloak, Nimbus, ...
        - indices faibles : InternalIdentity, Principal, ...
    """
    results_strong = _merge_results_for_keywords(IDENTITY_KEYWORDS_STRONG, file_extension=AUTH_CONFIG_EXT + JAVA_EXT)
    results_weak = _merge_results_for_keywords(IDENTITY_KEYWORDS_WEAK, file_extension=AUTH_CONFIG_EXT + JAVA_EXT)

    for label, results, level in [("InternalIdentityStrong", results_strong, "strong"),
                                  ("InternalIdentityWeak", results_weak, "weak")]:
        for r, entry in results.items():
            path = entry.get("path")
            if not path: 
                continue
            ms_name = tech_sw.detect_microservice(path, dfd)
            if not ms_name:
                continue
            ms = _ensure_microservice_entry(microservices, ms_name)
            ms.setdefault("tagged_values", []).append((label, r))
            ms.setdefault("stereotype_instances", []).append("internal_identity_" + level)
            _add_trace(ms_name, "internal_identity", path, entry.get("line_nr"), entry.get("span"), note=f"{label} evidence")
    return microservices


# __________________________________________________________________________________
# ---------------------------------- détecteur R5 ----------------------------------
# ``````````````````````````````````````````````````````````````````````````````````
TOKEN_VALIDATION_KEYWORDS_STRONG = [
    "JwtParser", "JwtDecoder", "JwtValidators",
    "verifySignature", "JwtException",
    "spring.security.oauth2.resourceserver.jwt",
    "nimbus-jose-jwt", "jjwt"
]

TOKEN_VALIDATION_KEYWORDS_WEAK = [
    "parseClaimsJws", "parseToken", "validateToken", "checkToken"
]

def detect_token_validation(microservices: Dict[str, dict], dfd) -> Dict[str, dict]:
    """
    R5: Vérifie que les tokens d’authentification sont validés.
    Recherche:
        - indices forts: JwtDecoder, Nimbus, jjwt, validations de signature, ...
        - indices faibles: validateToken, parseToken, ...
    """
    results_strong = _merge_results_for_keywords(TOKEN_VALIDATION_KEYWORDS_STRONG, file_extension=AUTH_CONFIG_EXT + JAVA_EXT)
    results_weak = _merge_results_for_keywords(TOKEN_VALIDATION_KEYWORDS_WEAK, file_extension=AUTH_CONFIG_EXT + JAVA_EXT)

    for label, results, level in [("Strong Token Validation", results_strong, "strong"),
                                  ("Weak Token Validation", results_weak, "weak")]:
        for r, entry in results.items():
            path = entry.get("path")
            if not path: 
                continue
            ms_name = tech_sw.detect_microservice(path, dfd)
            if not ms_name:
                continue
            ms = _ensure_microservice_entry(microservices, ms_name)
            ms.setdefault("tagged_values", []).append(("Security", label))
            ms.setdefault("stereotype_instances", []).append("token_validation_" + level)
            _add_trace(ms_name, "token_validation", path, entry.get("line_nr"), entry.get("span"), note=f"{label} evidence")
    return microservices
