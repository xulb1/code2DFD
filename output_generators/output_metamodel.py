#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
converter.py
------------
Convertit un output de code2DFD en JSON structuré selon le métamodèle mm-v2-gemini-v2.3.
Usage:
    python converter.py input.json output.json
"""

import json
import uuid
import sys
from datetime import datetime

def generate_id(prefix):
    """Génère des IDs uniques avec préfixe."""
    return f"{prefix}-{uuid.uuid4().hex[:6]}"

def convert_code2dfd_to_mm(input_data, repository_url="unknown", commit_hash="unknown"):
    """
    Convertit un JSON produit par code2DFD vers le métamodèle mm-v2-gemini-v2.3.
    """
    data = input_data

    # Squelette de sortie
    output = {
        "metadata": {
            "extractionDate": datetime.utcnow().isoformat() + "Z",
            "applicationName": "ConvertedApp",
            "applicationVersion": "1.0.0",
            "extractionToolVersion": "code2DFD-adapter-1.0",
            "repositoryUrl": repository_url,
            "commitHash": commit_hash
        },
        "architecture": {
            "name": "Converted Architecture",
            "description": "Architecture extraite et adaptée depuis code2DFD",
            "componentAndConnectorStructure": {
                "components": [],
                "connectors": []
            },
            "deploymentStructure": {
                "id": generate_id("deploy"),
                "name": "Default Deployment",
                "description": "Converted deployment from code2DFD",
                "environment": ["UNKNOWN"],
                "containerOrchestrator": [],
                "deploymentStrategy": "N/A",
                "rollbackStrategy": "N/A",
                "deploymentElements": []
            },
            "securityConcepts": {
                "securityMechanisms": [],
                "securityZones": [],
                "threats": []
            },
            "detectedAntiPatterns": []
        }
    }

    # Conversion des microservices
    for ms in data.get("microservices", []):
        component = {
            "id": generate_id("cpt"),
            "type": "Microservice" if ms.get("type") == "service" else "TechnicalComponent",
            "name": ms.get("name"),
            "description": "Converted from code2DFD output",
            "microserviceFramework": "Unknown",
            "exposedProtocols": [],
            "isContainerized": "isContainerised" in ms.get("stereotype_instances", []),
            "language": "Unknown",
            "runtimeVersion": "Unknown",
            "buildTool": "Unknown",
            "dependencies": [],
            "interfaces": []
        }

        # Ajout d'interfaces si des endpoints sont trouvés
        for tagged in ms.get("tagged_values", []):
            if isinstance(tagged, list) and tagged[0].lower() == "endpoints":
                component["interfaces"].append({
                    "id": generate_id(f"{component['id']}-i"),
                    "type": "SynchronousCommunicationInterface",
                    "description": "API converted from code2DFD",
                    "authenticationRequired": "auth" in "".join(ms.get("stereotype_instances", [])).lower(),
                    "authorizationRequired": "auth" in "".join(ms.get("stereotype_instances", [])).lower(),
                    "isInternal": "internal" in ms.get("stereotype_instances", []),
                    "isEncryptedCommunication": "tls" in "".join(ms.get("stereotype_instances", [])).lower(),
                    "protocol": "HTTP",
                    "api": {
                        "id": generate_id("api"),
                        "baseURL": f"http://{ms['name']}",
                        "restEndpoints": [
                            {"route": ep, "httpRequests": [], "httpResponses": []}
                            for ep in tagged[1] if isinstance(tagged[1], list)
                        ]
                    }
                })

        output["architecture"]["componentAndConnectorStructure"]["components"].append(component)

    # Conversion des information_flows en connectors
    for flow in data.get("information_flows", []):
        connector = {
            "id": generate_id("cnr"),
            "type": "HTTPConnector",
            "name": f"{flow['sender']} -> {flow['receiver']}",
            "description": "Converted flow from code2DFD",
            "protocol": "HTTP",
            "communicationPattern": "synchronous-request-reply",
            "isEncryptedCommunication": "tls" in "".join(flow.get("stereotype_instances", [])).lower(),
            "mutualAuthenticationRequired": False,
            "sourceComponentId": flow["sender"],
            "destinationComponentId": flow["receiver"]
        }
        output["architecture"]["componentAndConnectorStructure"]["connectors"].append(connector)

    # Conversion des external_components
    for ext in data.get("external_components", []):
        component = {
            "id": generate_id("ext"),
            "type": "ExternalComponent",
            "name": ext.get("name"),
            "description": "External system",
            "microserviceFramework": "N/A",
            "exposedProtocols": [],
            "isContainerized": False,
            "language": "N/A",
            "runtimeVersion": "N/A",
            "buildTool": "N/A"
        }
        output["architecture"]["componentAndConnectorStructure"]["components"].append(component)

    return output

def main():
    if len(sys.argv) != 3:
        print("Usage: python converter.py input.json output.json")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, "r", encoding="utf-8") as f:
        input_data = json.load(f)

    result = convert_code2dfd_to_mm(input_data)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Conversion terminée. Résultat dans: {output_file}")

if __name__ == "__main__":
    main()
