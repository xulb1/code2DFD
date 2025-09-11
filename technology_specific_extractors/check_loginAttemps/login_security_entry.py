"""
Détecteur de la règle de sécurité R6 :
"Limiter le nombre de tentatives de login avant mesures préventives."
"""

# TODO: AJOUTER la vérification de MFA

from typing import Dict, Any, List, Optional
import logging

import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability

logger = logging.getLogger(__name__)


AUTH_JAVA_EXT = ["*.java", "*.kt", "*.scala"]

AUTH_CONFIG_EXT = [
    "*.yml", "*.yaml", "*.properties", "*.conf", "*.ini",
    "*.xml", "*.json", "*.jwt", "*.cfg",
    "*.tf", "*.hcl", "Dockerfile", "*.rego"
]

# Indicateurs de mise en place explicite (forte confiance)
HIGH_KEYWORDS = [
    "MAX_LOGIN_ATTEMPTS",
    "MAX_ATTEMPTS",
    "AccountLockedException",
    "lockAccount",
    "setAccountNonLocked(false)",
    "CaptchaService",
    "recaptcha",
    "Bucket4j",
    "RateLimiter",
    "BruteForceProtection",
    "failureCount"  # Keycloak
]

# Indicateurs de mise en place potentielle de faible confiance -> nécessite corroboration
MEDIUM_KEYWORDS = [
    "failedAttempts",
    "loginAttempts",
    "incrementFailedAttempts",
    "resetFailedAttempts",
    "disableUser",
    "setEnabled(false)",
    "login.attempt.limit",
    "max-login-attempts"
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


def _merge_results_for_keywords(keywords: List[str], file_extensions: List[str]) -> Dict[str, Any]:
    """
    Appelle fi.search_keywords pour chaque keyword et fusionne les résultats.
    """
    aggregated = {}
    for kw in keywords:
        try:
            results = fi.search_keywords(kw, file_extension=file_extensions)
        except TypeError:
            results = fi.search_keywords(kw)
        for k, v in results.items():
            aggregated[f"{kw}::{k}"] = v
    return aggregated



# ----------------- Détecteur R6 -----------------
def detect_login_attempt_limits(microservices: Dict[str, dict], dfd) -> Dict[str, dict]:
    """
    Recherche si un mécanisme de limitation de login (R6) est implémenté.
    Ajoute le stéréotype 'login_attempt_protection' au microservice si preuve détectée.
    Si preuve faible → ajout du tag seul.
    Si aucune preuve → rien ajouté (règle considérée comme non respectée).
    """

    # Recherche dans le code
    high_hits = _merge_results_for_keywords(HIGH_KEYWORDS, AUTH_JAVA_EXT + AUTH_CONFIG_EXT)
    medium_hits = _merge_results_for_keywords(MEDIUM_KEYWORDS, AUTH_JAVA_EXT + AUTH_CONFIG_EXT)

    all_hits = {**high_hits, **medium_hits}

    for r, entry in all_hits.items():
        path = entry.get("path")
        if not path or "test" in path.casefold():
            continue

        ms_name = tech_sw.detect_microservice(path, dfd)
        if not ms_name:
            logger.debug("Service non-trouvé pour %s", path)
            continue

        # Vérification forte
        keyword = r.split("::")[0]
        ms = [m for m in microservices.values() if m["name"] == ms_name]
        if not ms:
            key = max(microservices.keys(), default=-1) + 1
            microservices[key] = {"name": ms_name, "stereotype_instances": [], "tagged_values": []}
            ms = microservices[key]
        else:
            ms = ms[0]
        
        if keyword in HIGH_KEYWORDS:
            if "login_attempt_protection" not in ms["stereotype_instances"]:
                ms["stereotype_instances"].append("login_attempt_protection")
            ms.setdefault("tagged_values", []).append(("SecurityRule", "LoginAttempsSecurity"))
            _add_trace(ms_name, "login_attempt_protection", path, entry.get("line_nr"), entry.get("span"), note=f"Mot-clé fort détecté: {keyword}")
            continue

        # Vérification faible
        if keyword in MEDIUM_KEYWORDS:
            count_medium = sum(1 for tv in ms.get("tagged_values", []) if tv == ("SecurityRule", "LoginAttempsSecurity (low confidence)"))
            if count_medium >= 2:  # donc au moins 2 indices moyens
                if "login_attempt_protection" not in ms["stereotype_instances"]:
                    ms["stereotype_instances"].append("login_attempt_protection")
                ms.setdefault("tagged_values", []).append(("SecurityRule", "LoginAttempsSecurity (low confidence)"))
                _add_trace(ms_name, "login_attempt_protection", path, entry.get("line_nr"), entry.get("span"), note=f"Indices moyens concordants, dont {keyword}")
            else:
                ms.setdefault("tagged_values", []).append(("SecurityRule", "LoginAttempsSecurity (low confidence)"))

    return microservices
