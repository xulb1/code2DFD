import tmp.tmp as tmp
import yaml
import ast
import os
import re
from collections import defaultdict
from pathlib import Path

import output_generators.traceability as traceability
from output_generators.logger import logger
import core.technology_switch as tech_sw
import core.file_interaction as fi

# from kubernetes import client
# from kubernetes.config import ConfigException


def set_microservices(dfd) -> dict:
    """
    Extrait la liste des microservices et autres entités DFD à partir des
    fichiers de configuration Kubernetes et stocke la variable dans le fichier tmp.
    """

    if tmp.tmp_config.has_option("DFD", "microservices"):
        microservices = ast.literal_eval(tmp.tmp_config["DFD"]["microservices"])
    else:
        microservices = dict()

    k8s_files = fi.search_files(["*.yaml", "*.yml"], getContent=True)
    for kf, content in k8s_files.items():
        if not os.path.basename(kf).startswith("test"):
            manifests = parse_k8s_manifests(content)
            if manifests:
                for manifest in manifests:
                    entity_name = None
                    entity_type = "unknown"
                    kind = manifest.get('kind')
                    metadata = manifest.get('metadata')
                    spec = manifest.get('spec', {})
                    
                    if not metadata or 'name' not in metadata:
                        continue
                        
                    entity_name = metadata['name']
                    image = "image_placeholder"
                    properties = {}
                    tagged_values = []
                    
                    # Détection du type et extraction des propriétés
                    if kind in ["Deployment", "DaemonSet", "StatefulSet", "Job"]:
                        entity_type = "internal"
                        template_spec = spec.get('template', {}).get('spec', {})
                        
                        # Sécurité au niveau du pod
                        pod_security_context = template_spec.get('securityContext')
                        if pod_security_context:
                            properties['pod_security_context'] = pod_security_context
                        
                        
                        for container in template_spec.get('containers', []):
                            # Extraction de l'image Docker et des ports
                            if 'image' in container:
                                image = container['image']
                                print(image)
                            if 'ports' in container:
                                tagged_values.extend(("Port",[p.get('containerPort') for p in container['ports']]))
                                
                            # Contexte de sécurité du conteneur
                            container_security_context = container.get('securityContext')
                            if container_security_context:
                                properties['container_security_context'] = container_security_context
                                
                            if 'istio-proxy' in [i.get('name') for i in template_spec.get('initContainers', [])] or \
                               'linkerd-proxy' in [i.get('name') for i in template_spec.get('initContainers', [])]:
                                properties['service_mesh_injected'] = True
                            
                            # Probes de santé
                            if container.get('livenessProbe'):
                                properties['liveness_probe_configured'] = True
                            if container.get('readinessProbe'):
                                properties['readiness_probe_configured'] = True
                            
                    elif kind == "Service":
                        entity_type = "service"
                        if 'ports' in spec:
                            tagged_values.extend(('Port',[p.get('port') for p in spec['ports']]))
                            # properties['service_ports'] = [{"name": p.get('name'), "port": p.get('port'), "protocol": p.get('protocol')} for p in spec['ports']]
                    
                    elif kind == "Ingress":
                        entity_type = "external"
                        properties['rules'] = spec.get('rules', [])
                        # TLS Ingress
                        if spec.get('tls'):
                            properties['tls_enabled'] = True

                    elif kind in ["PersistentVolumeClaim", "PersistentVolume"]:
                        entity_type = "data_store"
                    
                    
                    # Ajout de l'entité avec ses propriétés
                    if entity_name and entity_type != "unknown":
                        key = max(microservices.keys(), default=-1) + 1
                        microservices[key] = {
                            "name": entity_name,
                            "image": image,
                            "type": entity_type,
                            "k8s_path": kf,
                            "properties": set(), # TODO: modify properties
                            "stereotype_instances": list(),
                            "tagged_values": list()
                        }
                        
                        traceability.add_trace({
                            "item": entity_name,
                            "file": kf,
                            "line": 0,
                            "span": (0, 0)
                        })

    
    tmp.tmp_config.set("DFD", "microservices", str(microservices).replace("%", "%%"))
    return microservices


def parse_k8s_manifests(k8s_content: str) -> list:
    """
    Analyse un manifeste Kubernetes à partir de son contenu et retourne une liste de dictionnaires.
    """
    try:
        # load_all charge plusieurs documents YAML d'un seul fichier
        content = "\n".join(k8s_content)
        
        return list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        print((f"Erreur lors de l'analyse du contenu K8s: {e}"))
        logger.error(f"Erreur lors de l'analyse du contenu K8s: {e}")
        return []


def detect_microservice_2(file_path: str, dfd):
    """
    Détecte les liens de communication et les attributs de sécurité
    entre les microservices identifiés.
    """
    
    microservices = tech_sw.get_microservices(dfd)

    k8s_files = fi.search_files(["*.yaml", "*.yml"], getContent=True)
    
    for kf, content in k8s_files.items():
        if not os.path.basename(kf).startswith("test"):
            
            manifests = parse_k8s_manifests(content)
            
            if manifests:
                for manifest in manifests:
                    kind = manifest.get('kind')
                    metadata = manifest.get('metadata', {})
                    spec = manifest.get('spec', {})
                    name = metadata.get('name')

                    if not name:
                        continue

                    # 1. Détection des liens de communication
                    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
                        template_spec = spec.get('template', {}).get('spec', {})
                        for container in template_spec.get('containers', []):
                            for env_var in container.get('env', []):
                                if env_var.get('name') and ('_SERVICE_HOST' in env_var['name'] or '_SERVICE_PORT' in env_var['name']):
                                    target_svc_name = env_var['name'].split('_SERVICE_')[0].lower().replace('_', '-')
                                    if dfd.has_service(target_svc_name):
                                        dfd.add_flow(name, target_svc_name, "Communication via variable d'environnement")

                    # 2. Détection des attributs de sécurité
                    # NetworkPolicy
                    if kind == "NetworkPolicy":
                        policy_name = name
                        dfd.add_security_annotation(policy_name, "NetworkPolicy")
                    
                    # Secrets
                    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
                        template_spec = spec.get('template', {}).get('spec', {})
                        for volume in template_spec.get('volumes', []):
                            if volume.get('secret'):
                                secret_name = volume['secret'].get('secretName')
                                if secret_name:
                                    dfd.add_security_annotation(name, f"Utilisation du Secret: {secret_name}")

                    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
                        template_spec = spec.get('template', {}).get('spec', {})
                        if template_spec.get('securityContext'):
                            dfd.add_security_annotation(name, "securityContext")

    # Pour se conformer à la signature de grd_entry.py, retourne le nom du premier microservice
    if microservices:
        first_ms = next(iter(microservices.values()))
        return first_ms['name']
        
    return False



# ==================================================================
#                           DETECT FLOWS
# ==================================================================

def set_information_flows(dfd) -> dict:
    """Adds connections based on parsed Kubernetes config files.
    """
    if tmp.tmp_config.has_option("DFD", "information_flows"):
        information_flows = ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])
    else:
        information_flows = dict()

    microservices = tech_sw.get_microservices(dfd)

    # Detect flows from Kubernetes configuration files
    new_information_flows = detect_k8s_flows(microservices)
    
    # Merge old and new flows
    for ni in new_information_flows.keys():
        flow_id = max(information_flows.keys(), default=-1) + 1
        information_flows[flow_id] = new_information_flows[ni]

    tmp.tmp_config.set("DFD", "information_flows", str(information_flows).replace("%", "%%"))
    return information_flows

def detect_k8s_flows(microservices: dict) -> dict:
    """
    Detects communication flows by analyzing Kubernetes manifest files.
    """
    k8s_files = fi.search_files(["*.yaml", "*.yml"], getContent=True)
    flows = defaultdict(dict)
    
    # Pre-parse all manifests to have a full view of the cluster resources
    all_manifests = {}
    for kf, content in k8s_files.items():
        if not os.path.basename(kf).startswith("test"):
            manifests = parse_k8s_manifests(content)
            for manifest in manifests:
                kind = manifest.get('kind')
                name = manifest.get('metadata', {}).get('name')
                if kind and name:
                    # Store manifests by kind and name for easy lookup
                    if kind not in all_manifests:
                        all_manifests[kind] = {}
                    all_manifests[kind][name] = manifest

    # Find flows by analyzing Deployments, StatefulSets, etc.
    for kf, content in k8s_files.items():
        if not os.path.basename(kf).startswith("test"):
            manifests = parse_k8s_manifests(content)
            for manifest in manifests:
                kind = manifest.get('kind')
                if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
                    source_ms_name = manifest.get('metadata', {}).get('name')
                    template_spec = manifest.get('spec', {}).get('template', {}).get('spec', {})
                    
                    # 1. Analyze environment variables for links
                    for container in template_spec.get('containers', []):
                        for env_var in container.get('env', []):
                            # Common patterns for service URLs
                            if env_var.get('value') and isinstance(env_var['value'], str):
                                # Regex to find hostnames (e.g., "my-svc:8080", "my-svc.namespace.svc.cluster.local")
                                match = re.search(r"([a-zA-Z0-9-]+\.)?([a-zA-Z0-9-]+)(:\d+)?", env_var['value'])
                                if match:
                                    target_svc_name = match.group(2)
                                    target_ms = find_microservice_by_name(microservices, target_svc_name)
                                    if target_ms:
                                        add_flow(flows, source_ms_name, target_ms['name'], "Via env variable", "Data Flow", {"env_var": env_var['name']})

                    # 2. Analyze ConfigMaps/Secrets for links
                    for volume in template_spec.get('volumes', []):
                        if 'configMap' in volume:
                            cm_name = volume['configMap']['name']
                            if cm_name in all_manifests.get('ConfigMap', {}):
                                cm_data = all_manifests['ConfigMap'][cm_name].get('data', {})
                                for key, value in cm_data.items():
                                    target_svc_name = infer_target_service(value)
                                    if target_svc_name:
                                        target_ms = find_microservice_by_name(microservices, target_svc_name)
                                        if target_ms:
                                            add_flow(flows, source_ms_name, target_ms['name'], "Via ConfigMap", "Data Flow", {"configMap_key": key})
                        
                        if 'secret' in volume:
                            secret_name = volume['secret']['secretName']
                            # Note: We cannot read secret data from the manifest, so this is a limited check
                            # unless you have a way to decrypt them. We can only infer a link if the Secret name
                            # matches a pattern, e.g., "db-secret", "api-key-service-a"
                            if 'api-key' in secret_name or 'url' in secret_name:
                                target_svc_name = infer_target_service(secret_name)
                                if target_svc_name:
                                    target_ms = find_microservice_by_name(microservices, target_svc_name)
                                    if target_ms:
                                        add_flow(flows, source_ms_name, target_ms['name'], "Via Secret Name", "Data Flow", {"secret_name": secret_name})

    return flows

def add_flow(flows, from_ms, to_ms, label, flow_type, properties):
    """Helper function to add a flow to the flows dictionary."""
    flow_key = f"{from_ms}->{to_ms}"
    if flow_key not in flows:
        flows[flow_key] = {
            "sender": from_ms,
            "receiver": to_ms,
            "stereotype_instances": ["restful_http"]

            "label": label,
            "type": flow_type,
            "properties": properties
        }

def find_microservice_by_name(microservices: dict, name: str) -> dict or None:
    """Helper function to find a microservice by its name."""
    return next(
            (ms for ms in microservices.values() if ms['name'] == name),
            None
        )

def infer_target_service(value: str) -> str or None:
    """Infers a service name from a string (e.g., URL, variable name)."""
    # Regex to find service names from a URL or a name
    match = re.search(r"([a-zA-Z0-9-]+\.)?([a-zA-Z0-9-]+)(:\d+)?", value)
    return match.group(2) if match else None


def parse_k8s_manifests(k8s_content: str) -> list:
    """Parses K8s manifest, handling multiple YAML documents."""
    try:
        content = "\n".join(k8s_content)
        return list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        logger.error(f"Error parsing K8s content: {e}")
        return []