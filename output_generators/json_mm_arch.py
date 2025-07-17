from datetime import datetime
from pathlib import Path
import json
import os
import re

import tmp.tmp as tmp


def generate_json_architecture(microservices: dict, information_flows: dict, external_components: dict):
    """Creates JSON file that contains the complete extracted architecture.
    """
    print(list(microservices.values()))
    print(list(information_flows.values()))
    print(list(external_components.values()))
    
    full_dict = {"microservices": list(microservices.values()),
                 "information_flows": list(information_flows.values()),
                 "external_components": list(external_components.values())}

    output_path = tmp.tmp_config["Analysis Settings"]["output_path"]
    parts = Path(output_path).parts
    filename = f"{parts[-2]}--{parts[-1]}_json_architecture.json"
    output_path = os.path.join(output_path, filename)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as architecture_file:
        json.dump(full_dict, architecture_file, indent=4)

def __():
    allfilie = ""
    


def generate_id(prefix,radical,i):
    return f"{prefix}-{radical}{i}"

# Étape 1 : Convertir les microservices en composants
def convert_micro(microservices: dict, external_components: dict) -> list:
    components = []
    name_to_id = {}

    for svc in microservices.values():
        cpt_id = generate_id("cpt")
        name_to_id[svc["name"]] = cpt_id

        component = {
            "id": cpt_id,
            "type": "Microservice",
            "name": svc["name"],
            "microserviceFramework": "Spring Boot" if "spring" in svc.get("gradle_path", "").lower() else "Unknown",
            "exposedProtocols": None,
            "isContainerized": True,
            "language": None,
            "runtimeVersion": None,
            "buildTool": "Gradle" if "gradle" in svc.get("gradle_path", "") else "Unknown",
            "dependencies": [],
            "interfaces": []
        }

        # Extraire les endpoints si présents
        endpoints = next((val for key, val in svc.get("tagged_values", []) if key == "Endpoints"), [])
        if endpoints:
            interface_id = generate_id(f"{cpt_id}-i")
            interface = {
                "id": interface_id,
                "type": "SynchronousCommunicationInterface",
                "authenticationRequired": "authentication_scope_all_requests" in svc.get("stereotype_instances", []),
                "authorizationRequired": "resource_server" in svc.get("stereotype_instances", []),
                "isInternal": "internal" in svc.get("stereotype_instances", []),
                "isEncryptedCommunication": True,
                "timeout": 5000,
                "protocol": "HTTPS",
                "api": {
                    "id": generate_id("api"),
                    "isCorsEnabled": False,
                    "baseURL": f"https://{svc['name']}.internal",
                    "port": 443,
                    "documentationUrl": "",
                    "summary": "",
                    "apiType": "REST",
                    "tokenValidationEnabled": True,
                    "appliedSecurityMechanisms": [],
                    "restEndpoints": [
                        {
                            "route": route,
                            "produces": ["application/json"],
                            "httpRequests": [{"httpMethod": ["GET"], "pathVariables": [], "queryParams": []}],
                            "httpResponses": [{"statusCode": [200], "contentType": "application/json", "message": ""}]
                        }
                        for route in endpoints
                    ]
                }
            }
            component["interfaces"].append(interface)

        components.append(component)
    
    # Étape 2 : Convertir les external_components
    for ext in external_components.values():
        cpt_id = generate_id("ext")
        name_to_id[ext["name"]] = cpt_id
        components.append({
            "id": cpt_id,
            "type": "ExternalSystem",
            "name": ext["name"],
            "description": "",
            "exposedProtocols": ["HTTPS"],
            "isContainerized": False,
            "language": "N/A",
            "runtimeVersion": "N/A",
            "buildTool": "N/A"
        })

# Étape 3 : Convertir les information_flows en connecteurs
def convert_flows(information_flows: dict)-> list:
    connectors = []
    for flow in information_flows.values():
        src = flow["sender"]
        dst = flow["receiver"]
        if not src or not dst:
            continue
        conn = {
            "id": generate_id("cnr"),
            "type": "HTTPConnector",
            "name": f"{flow['sender']} -> {flow['receiver']}",
            "description": "Flux d'information",
            "protocol": "HTTPS",
            "communicationPattern": "synchronous-request-reply",
            "isEncryptedCommunication": True,
            "mutualAuthenticationRequired": False,
            "secure": True,
            "sourceComponentId": src,
            "destinationComponentId": dst
        }
        connectors.append(conn)

def _():
    # Étape 4 : Envelopper dans le format mm-v2
    output_json = {
        "metadata": {
            "extractionDate": "2025-07-17T00:00:00Z",
            "applicationName": "ConvertedApp",
            "applicationVersion": "1.0.0",
            "extractionToolVersion": "CustomTransformer-1.0",
            "repositoryUrl": "",
            "commitHash": ""
        },
        "architecture": {
            "name": "Spring Boot Microservices (converted)",
            "description": "Structure convertie depuis un modèle simple vers mm-v2",
            "componentAndConnectorStructure": {
                # "components": components,
                # "connectors": connectors
            },
            "deploymentStructure": {},
            "securityConcepts": {},
            "detectedAntiPatterns": []
        }
    }




def clean_name_for_id(name):
    """Clean and shorten a name to be suitable for an ID segment."""
    name = name.lower()
    name = re.sub(r'[^a-z0-9\s-]', '', name) # Remove special characters except spaces and hyphens
    name = re.sub(r'\s+', '_', name)       # Replace spaces with underscores
    # name = name.replace('-service', '')    # Remove common suffixes
    # name = name.replace('-server', '')
    name = name.replace('-mongodb', '_db') # Shorten common database names
    name = name.replace('gateway', 'gw')   # Shorten gateway
    # if len(name) > 15: # Arbitrary length limit for succinctness
        # name = name[:15].rstrip('_')
    return name or "unknown"

def map_stereotype_to_protocol(stereotype):
    """Maps a stereotype to a known protocol."""
    protocol_map = {
        "restful_http": "HTTPS", # Assuming HTTPS for RESTful communication
        "jdbc": "JDBC",
        "message_broker": "MQ", # General Message Queue
        "rabbitmq": "RabbitMQ", # Specific Message Queue
        "kafka": "Kafka" # Specific Message Queue
    }
    return protocol_map.get(stereotype, "Unknown")

def map_stereotype_to_communication_pattern(stereotype):
    """Maps a stereotype to a communication pattern."""
    pattern_map = {
        "restful_http": "synchronous-request-reply",
        "jdbc": "database-access",
        "message_broker": "asynchronous-publish-subscribe",
        "rabbitmq": "asynchronous-publish-subscribe",
        "kafka": "asynchronous-publish-subscribe"
    }
    return pattern_map.get(stereotype, "unknown")

def map_stereotype_to_security_mechanism(stereotype):
    """Maps a stereotype to a security mechanism type."""
    sec_map = {
        "encryption": "TLS",
        "authentication_with_plaintext_credentials": "Basic Auth",
        "auth_provider": "OAuth2/JWT", # Could be more specific based on context
        "token_server": "OAuth2/JWT",
        "authorization_server": "OAuth2/JWT",
        "resource_server": "OAuth2/JWT"
    }
    return sec_map.get(stereotype, None)

def find_tagged_value(tagged_values, key):
    """Helper to find a value by key in tagged_values list."""
    for tag_key, tag_value in tagged_values:
        if tag_key == key:
            return tag_value
    return None

def convert_architecture(microservices: dict, information_flows: dict, external_components: dict) -> dict:
    output_path = tmp.tmp_config["Analysis Settings"]["output_path"]
    parts = Path(output_path).parts

    # --- Metadata ---
    metadata = {
        "extractionDate": datetime.now().isoformat(timespec='seconds') + 'Z',
        "applicationName": parts[-2],
        "applicationVersion": None, # Default, as not in source
        "extractionToolVersion": None,
        "repositoryUrl": None, # Not directly in source
        "commitHash": parts[-1]
    }
    
    # --- Architecture Root ---
    architecture_id = f"{parts[-2]}_arch"
    architecture = {
        "id": architecture_id,
        "name": f"{metadata['applicationName']} Architecture",
        "componentAndConnectorStructure": {
            "components": [],
            "connectors": []
        },
        "deploymentStructure": { # Minimal deployment structure, can be expanded
            "id": f"{architecture_id}-deploy_default",
            "name": "Default Deployment",
            "description": "Default deployment structure inferred from components.",
            "environment": ["UNKNOWN"],
            "deploymentElements": []
        },
        "securityConcepts": { # Default empty, will fill if data found
            "securityMechanisms": [],
            "securityZones": [],
            "threats": []
        },
        "detectedAntiPatterns": [] # Default empty
    }

    component_id_map = {} # Map original component name to new ID
    new_security_mechanisms = {} # To avoid duplicates

    # --- Components ---
    for i, ms in microservices.items():
        comp_name_cleaned = clean_name_for_id(ms["name"])
        comp_id = f"{architecture_id}-comp_{comp_name_cleaned}"
        component_id_map[ms["name"]] = comp_id

        component = {
            "id": comp_id,
            "type": "Microservice" if ms["type"] == "service" else "TechnicalComponent",
            "name": ms["name"],
            "description": f"Microservice: {ms['name']}",
            "microserviceFramework": "N/A", # Not directly available
            "exposedProtocols": [],
            "isContainerized": True, # Assumption for microservices
            "language": "N/A", # Not directly available
            "runtimeVersion": "N/A", # Not directly available
            "buildTool": "N/A", # Not directly available
            "dependencies": [], # Not directly available
            "interfaces": []
        }

        # Extract info from tagged_values
        port = find_tagged_value(ms.get("tagged_values", []), "Port")
        if port:
            component["exposedProtocols"].append(f"Port:{port}")
        
        endpoints = find_tagged_value(ms.get("tagged_values", []), "Endpoints")
        if endpoints:
            # Create a default API interface for endpoints
            int_id = f"{comp_id}-int_api"
            api_id = f"{int_id}-endpoint"
            api_type = "REST" # Assumption
            
            interface = {
                "id": int_id,
                "type": "SynchronousCommunicationInterface",
                "description": f"API for {ms['name']}",
                "authenticationRequired": "pre_authorized_endpoints" not in ms.get("stereotype_instances", []),
                "authorizationRequired": "pre_authorized_endpoints" not in ms.get("stereotype_instances", []),
                "isInternal": "internal" in ms.get("stereotype_instances", []),
                "isEncryptedCommunication": "encryption" in ms.get("stereotype_instances", []),
                "securityChecks": {}, # Can be populated based on stereotypes
                "protocol": "HTTPS" if "restful_http" in ms.get("stereotype_instances", []) else "HTTP",
                "api": {
                    "id": api_id,
                    "apiType": api_type,
                    "baseURL": f"http://{ms['name']}.internal",
                    "restEndpoints": []
                }
            }

            if type(endpoints) is not list:
                endpoints = [endpoints]
            print(endpoints)
            for endpoint_route in endpoints:
                interface["api"]["restEndpoints"].append({
                    "route": endpoint_route,
                    "produces": ["application/json"],
                    "httpRequests": [{"httpMethod": ["GET"]}] # Defaulting to GET
                })
                
            component["interfaces"].append(interface)

        # Handle specific stereotypes to fill fields
        if "resource_server" in ms.get("stereotype_instances", []):
            component["type"] = "Microservice"
            # Attempt to add security mechanisms
            if "authentication_scope_all_requests" in ms.get("stereotype_instances", []):
                sm_id = f"{architecture_id}-sm_allauth"
                if sm_id not in new_security_mechanisms:
                    new_security_mechanisms[sm_id] = {
                        "id": sm_id,
                        "name": "Global Authentication Scope",
                        "type": "Authentication",
                        "enforcementPoint": ms["name"]
                    }
            if "encryption" in ms.get("stereotype_instances", []):
                sm_id = f"{architecture_id}-sm_tls"
                if sm_id not in new_security_mechanisms:
                    new_security_mechanisms[sm_id] = {
                        "id": sm_id,
                        "name": "TLS/Encryption",
                        "type": "TLS",
                        "enforcementPoint": ms["name"]
                    }

        if "database" in ms.get("stereotype_instances", []):
            component["type"] = "TechnicalComponent"
            component["technicalType"] = "Database"
            db_type = find_tagged_value(ms.get("tagged_values", []), "Database Type")
            component["configuration"] = {"databaseType": db_type or "MongoDB"} # Assuming MongoDB for given examples

        if "message_broker" in ms.get("stereotype_instances", []):
            component["type"] = "TechnicalComponent"
            component["technicalType"] = "MessageBroker"
            broker_type = find_tagged_value(ms.get("tagged_values", []), "Message Broker")
            component["brokerType"] = broker_type or "N/A"
        
        if "gateway" in ms.get("stereotype_instances", []):
            component["type"] = "APIGateway"
            component["gatewayType"] = find_tagged_value(ms.get("tagged_values", []), "Gateway")
            component["isSingleEntrypoint"] = True
            component["performsLoadBalancing"] = "load_balancer" in ms.get("stereotype_instances", [])
        
        # Add other specific types
        if "configuration_server" in ms.get("stereotype_instances", []):
            component["type"] = "TechnicalComponent"
            component["technicalType"] = "ConfigurationServer"
            component["configuration"] = {"tool": find_tagged_value(ms.get("tagged_values", []), "Configuration Server")}
        if "monitoring_server" in ms.get("stereotype_instances", []):
            component["type"] = "TechnicalComponent"
            component["technicalType"] = "MonitoringTool"
            component["toolName"] = find_tagged_value(ms.get("tagged_values", []), "Monitoring Server")
            component["hasMonitoringDashboard"] = "monitoring_dashboard" in ms.get("stereotype_instances", [])
        if "service_discovery" in ms.get("stereotype_instances", []):
            component["type"] = "TechnicalComponent"
            component["technicalType"] = "ServiceDiscovery"
            component["toolName"] = find_tagged_value(ms.get("tagged_values", []), "Service Discovery")
        if "authorization_server" in ms.get("stereotype_instances", []):
            component["type"] = "TechnicalComponent"
            component["technicalType"] = "AuthService"
            component["securityMechanism"] = ["OAuth2"]
        if "tracing_server" in ms.get("stereotype_instances", []):
            component["type"] = "TechnicalComponent"
            component["technicalType"] = "TracingTool"
            component["toolName"] = find_tagged_value(ms.get("tagged_values", []), "Tracing Server")


        # Common security flags from stereotypes for component
        if "plaintext_credentials" in ms.get("stereotype_instances", []):
            ap_id = f"{architecture_id}-ap_plaintext_creds_{comp_name_cleaned}"
            architecture["detectedAntiPatterns"].append({
                "id": ap_id,
                "antiPatternName": "Plaintext Credentials",
                "description": f"Component '{ms['name']}' uses plaintext credentials.",
                "severity": "High",
                "componentsInvolvedIds": [comp_id],
                "recommendation": "Use secret management system or encrypted credentials."
            })
            sm_id = f"{architecture_id}-sm_no_plaintext"
            if sm_id not in new_security_mechanisms:
                 new_security_mechanisms[sm_id] = {
                    "id": sm_id,
                    "name": "No Plaintext Credentials",
                    "type": "Secure Credential Management",
                    "enforcementPoint": "Application/Config",
                    "compliantWithRule": "R2" # Example rule
                }

        if "csrf_disabled" in ms.get("stereotype_instances", []):
            ap_id = f"{architecture_id}-ap_csrf_disabled_{comp_name_cleaned}"
            architecture["detectedAntiPatterns"].append({
                "id": ap_id,
                "antiPatternName": "CSRF Disabled",
                "description": f"CSRF protection is disabled for component '{ms['name']}'.",
                "severity": "High",
                "componentsInvolvedIds": [comp_id],
                "recommendation": "Enable CSRF protection for web-facing components."
            })
            sm_id = f"{architecture_id}-sm_csrf"
            if sm_id not in new_security_mechanisms:
                 new_security_mechanisms[sm_id] = {
                    "id": sm_id,
                    "name": "CSRF Protection",
                    "type": "CSRF Protection",
                    "enforcementPoint": "Application/Framework",
                    "compliantWithRule": "R3"
                }

        architecture["componentAndConnectorStructure"]["components"].append(component)

    # --- Connectors (Information Flows) ---
    connector_counter = {} # To handle multiple connectors between same sender/receiver

    for i, flow in information_flows.items():
        sender_id = component_id_map.get(flow["sender"], flow["sender"]) # Use new ID or original name for external
        receiver_id = component_id_map.get(flow["receiver"], flow["receiver"]) # Use new ID or original name for external

        # Handle external components explicitly
        if sender_id == flow["sender"] and sender_id not in component_id_map.values():
            # Add to deployment elements or assume it's "user" for now
            if flow["sender"] == "user":
                sender_id = "user_client" # Standard ID for user
            elif flow["sender"] == "external-website":
                sender_id = "ext_website"
            elif flow["sender"] == "github-repository":
                sender_id = "github_repo"
            elif flow["sender"] == "mail-server":
                sender_id = "mail_server_ext"
            else:
                sender_id = f"{architecture_id}-ext_{clean_name_for_id(flow['sender'])}"

        if receiver_id == flow["receiver"] and receiver_id not in component_id_map.values():
            if flow["receiver"] == "user":
                receiver_id = "user_client"
            elif flow["receiver"] == "external-website":
                receiver_id = "ext_website"
            elif flow["receiver"] == "github-repository":
                receiver_id = "github_repo"
            elif flow["receiver"] == "mail-server":
                receiver_id = "mail_server_ext"
            else:
                receiver_id = f"{architecture_id}-ext_{clean_name_for_id(flow['receiver'])}"

        # Generate a unique short ID for the connector
        conn_base_name = f"{clean_name_for_id(flow['sender'])}_{clean_name_for_id(flow['receiver'])}"
        connector_counter[conn_base_name] = connector_counter.get(conn_base_name, 0) + 1
        conn_id = f"{architecture_id}-conn_{conn_base_name}_{connector_counter[conn_base_name]}"

        connector = {
            "id": conn_id,
            "type": "HTTPConnector", # Default type
            "name": f"{flow['sender']} to {flow['receiver']}",
            "description": f"Communication from {flow['sender']} to {flow['receiver']}",
            "protocol": "N/A",
            "communicationPattern": "N/A",
            "isEncryptedCommunication": False,
            "mutualAuthenticationRequired": False,
            "secure": False,
            "sourceComponentId": sender_id,
            "destinationComponentId": receiver_id
        }
        
        # Extract protocol and pattern from stereotypes
        for stereo in flow.get("stereotype_instances", []):
            protocol = map_stereotype_to_protocol(stereo)
            if protocol != "Unknown":
                connector["protocol"] = protocol
            
            pattern = map_stereotype_to_communication_pattern(stereo)
            if pattern != "unknown":
                connector["communicationPattern"] = pattern
        
        if "plaintext_credentials_link" in flow.get("stereotype_instances", []):
            connector["secure"] = False
            ap_id = f"{architecture_id}-ap_plaintext_creds_link_{conn_base_name}"
            architecture["detectedAntiPatterns"].append({
                "id": ap_id,
                "antiPatternName": "Plaintext Credentials in Communication",
                "description": f"Communication from {flow['sender']} to {flow['receiver']} uses plaintext credentials.",
                "severity": "High",
                "connectorsInvolvedIds": [conn_id],
                "recommendation": "Encrypt communication channel or use secure credential management."
            })
        if "authentication_with_plaintext_credentials" in flow.get("stereotype_instances", []):
             connector["secure"] = False

        if "circuit_breaker_link" in flow.get("stereotype_instances", []):
            # This is not a security concern, but a resilience pattern
            # Can be added to details if needed
            pass
        if "load_balanced_link" in flow.get("stereotype_instances", []):
            # Not a security concern
            pass
        if "encryption" in flow.get("stereotype_instances", []):
            connector["isEncryptedCommunication"] = True
            connector["secure"] = True

        architecture["componentAndConnectorStructure"]["connectors"].append(connector)

    # Add security mechanisms to architecture
    architecture["securityConcepts"]["securityMechanisms"] = list(new_security_mechanisms.values())

    # --- External Components ---
    # Convert external components into components and link them to security zones or deployment elements
    for ext_comp in external_components.values():
        ext_comp_name_cleaned = clean_name_for_id(ext_comp["name"])
        ext_comp_id = component_id_map.get(ext_comp["name"], f"{architecture_id}-ext_{ext_comp_name_cleaned}")
        
        # Add a placeholder component for external systems if not already added by a connector
        if ext_comp_id not in [c["id"] for c in architecture["componentAndConnectorStructure"]["components"]]:
             architecture["componentAndConnectorStructure"]["components"].append({
                "id": ext_comp_id,
                "type": "ExternalSystem" if ext_comp.get("type") == "external_component" else "N/A",
                "name": ext_comp["name"],
                "description": f"External component: {ext_comp['name']}",
                "exposedProtocols": ["N/A"]
            })

        # Add to default deployment element
        default_network_id = f"{architecture_id}-deploy_default-net_default"
        default_cluster_id = f"{architecture_id}-deploy_default-net_default-cluster_default"
        default_server_id = f"{architecture_id}-deploy_default-net_default-cluster_default-server_default"
        
        # Ensure default network, cluster, server exist
        if not any(el["id"] == default_network_id for el in architecture["deploymentStructure"]["deploymentElements"]):
            architecture["deploymentStructure"]["deploymentElements"].append({
                "id": default_network_id,
                "type": "Network",
                "name": "Default Network",
                "cluster": {
                    "id": default_cluster_id,
                    "name": "Default Cluster",
                    "servers": [
                        {
                            "id": default_server_id,
                            "name": "Default Server",
                            "containers": []
                        }
                    ]
                }
            })
        
        # Add external component as a "container" representing itself in the default server
        default_server = next((n for n in architecture["deploymentStructure"]["deploymentElements"] if n["id"] == default_network_id for c in n.get("cluster", {}).get("servers", []) if c["id"] == default_server_id), None)
        if default_server:
            servers = default_server.get("cluster", {}).get("servers", [])
            for s in servers:
                for c in s["containers"]:
                    if c["id"]==ext_comp_id:
                        default_server["containers"].append({
                            "id": ext_comp_id,
                            "name": ext_comp["name"],
                            "imageName": "N/A",
                            "representsDeployedComponentId": ext_comp_id # Links to itself as an external component
                        })
                        break

    return {"metadata": metadata, "architecture": architecture}


def save_arch(microservices: dict, information_flows: dict, external_components: dict) -> None:
    try:
        output_path = tmp.tmp_config["Analysis Settings"]["output_path"]
        parts = Path(output_path).parts
        filename = f"{parts[-2]}--{parts[-1]}_json_architecture-mm.json"
        output_path = os.path.join(output_path, filename)
        
        arch = convert_architecture(microservices, information_flows, external_components)
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as architecture_file:
            json.dump(arch, architecture_file, indent=4)
        
        print(f"Successfully converted {filename} to {output_path}, mm converted")
    except Exception as e:
        print(f"Error converting {filename}: {e}")
