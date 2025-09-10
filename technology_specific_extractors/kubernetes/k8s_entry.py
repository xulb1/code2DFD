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

# FIXME: Rechercher plus d'attribut de sécurité et vérifier la qualité de la détection de services et de liens

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
            manifests = parse_k8s_manifests(kf,content)
            if manifests:
                for manifest in manifests:
                    if not manifest:
                        continue
                    entity_name = None
                    entity_type = "unknown"
                    try:
                        kind = manifest.get('kind')
                        metadata = manifest.get('metadata')
                        spec = manifest.get('spec', {})
                    except AttributeError:
                        print("\033[31mERROR with manifest (list instead of dict object -> get() on the first element of the list)\033[0m")
                        kind = manifest[0].get('kind',None)
                        metadata = manifest[0].get('metadata',None)
                        spec = manifest[0].get('spec', {})
                    
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


def detect_microservice(file_path: str, dfd) -> str:
    """
    Détecte le microservice auquel un manifeste Kubernetes appartient
    en se basant sur le nom de la ressource.
    """

    # S'assurer que le fichier est un manifeste YAML
    if not file_path.lower().endswith(('.yaml', '.yml')):
        return None

    microservices = tech_sw.get_microservices(dfd)
    
    try:
        with open(file_path, 'r') as f:
            manifests = list(yaml.safe_load_all(f))
    except (yaml.YAMLError, FileNotFoundError) as e:
        logger.error(f"Erreur de lecture ou de parsing YAML pour {file_path}: {e}")
        return None

    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue

        metadata = manifest.get('metadata', {})
        resource_name = metadata.get('name')
        
        if resource_name:
            # Tenter une correspondance directe avec le nom de la ressource
            for m in microservices.values():
                ms_name = m["name"]
                # On compare le nom de la ressource avec le nom du microservice
                if resource_name.lower() == ms_name.lower():
                    logger.info(f"Microservice '{ms_name}' détecté via le manifeste Kubernetes '{resource_name}'")
                    return ms_name

            # Si aucune correspondance directe, chercher des schémas de nommage courants
            for m in microservices.values():
                ms_name = m["name"]
                if ms_name.lower() in resource_name.lower():
                    logger.info(f"Microservice '{ms_name}' détecté via le nom de ressource '{resource_name}' (nom partiel)")
                    return ms_name

    logger.info(f"Aucun microservice détecté pour le manifeste {file_path}")
    return None


##============================================================================================
##============================================================================================
##============================================================================================
#                           DETECT FLOWS
##============================================================================================
##============================================================================================
##============================================================================================

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
    Détecte les flux de communication en analysant les fichiers manifestes Kubernetes.
    """
    k8s_files = fi.search_files(["*.yaml", "*.yml"], getContent=True)
    flows = defaultdict(dict)
    
    # Step 1: Global view of the Cluster
    all_manifests = defaultdict(lambda: defaultdict(dict))
    for kf, content in k8s_files.items():
        if not os.path.basename(kf).startswith("test"):
            manifests = parse_k8s_manifests(kf,content)
            for manifest in manifests:
                if not manifest:
                    continue
                try:
                    kind = manifest.get('kind')
                    name = manifest.get('metadata', {}).get('name')
                except AttributeError:
                    print("\033[31mERROR with manifest (list instead of dict object -> get() on the first element of the list)\033[0m")
                    kind = manifest[0].get('kind',None)
                    name = manifest[0].get('metadata', {}).get('name')


            
                if kind and name:
                    all_manifests[kind][name] = manifest

    # Step 2: Link services to Workloads (Deployments, StatefulSets, etc.)
    service_to_workload = {}
    for svc_name, svc_manifest in all_manifests['Service'].items():
        selector = svc_manifest.get('spec', {}).get('selector', {})
        if selector:
            # looking for workload corresponding to this selector
            for wl_kind in ['Deployment', 'StatefulSet', 'DaemonSet']:
                for wl_name, wl_manifest in all_manifests[wl_kind].items():
                    wl_labels = wl_manifest.get('spec', {}).get('template', {}).get('metadata', {}).get('labels', {})
                    if all(item in wl_labels.items() for item in selector.items()):
                        service_to_workload[svc_name] = wl_name
                        break
                if svc_name in service_to_workload:
                    break

    # Step 3: Detect flows
    for kf, content in k8s_files.items():
        if not os.path.basename(kf).startswith("test"):
            manifests = parse_k8s_manifests(kf,content)
            for manifest in manifests:
                if not manifest:
                    continue
                try:
                    kind = manifest.get('kind')
                    source_ms_name = manifest.get('metadata', {}).get('name')                
                except AttributeError:
                    print("\033[31mERROR with manifest (list instead of dict object -> get() on the first element of the list)\033[0m")
                    kind = manifest[0].get('kind',None)
                    source_ms_name = manifest[0].get('metadata', {}).get('name')                

                
                # A. Workloads Analysis (Deployments, StatefulSets, etc.)
                if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
                    template_spec = manifest.get('spec', {}).get('template', {}).get('spec', {})
                    
                    # 1. Env var Analysis
                    for container in template_spec.get('containers', []):
                        for env_var in container.get('env', []):
                            value = env_var.get('value')
                            if isinstance(value, str):
                                target_svc_name = infer_target_service(value)
                                if target_svc_name:
                                    target_ms = find_microservice_by_name(microservices, target_svc_name)
                                    if target_ms:
                                        add_flow(flows, source_ms_name, target_ms['name'], "Data Flow", {"env_var": env_var['name']})

                    # 2. ConfigMaps/Secrets Analysis
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
                                            add_flow(flows, source_ms_name, target_ms['name'], "Data Flow", {"configMap_key": key})
                        
                        if 'secret' in volume:
                            secret_name = volume['secret']['secretName']
                            target_svc_name = infer_target_service(secret_name)
                            if target_svc_name:
                                target_ms = find_microservice_by_name(microservices, target_svc_name)
                                if target_ms:
                                    add_flow(flows, source_ms_name, target_ms['name'], "Data Flow", {"secret_name": secret_name})

                # B. Ingress Analysis
                elif kind == "Ingress":
                    rules = manifest.get('spec', {}).get('rules', [])
                    for rule in rules:
                        # Ingress with Host or path ?
                        host = rule.get('host', 'default')
                        http_paths = rule.get('http', {}).get('paths', [])
                        
                        for path in http_paths:
                            backend = path.get('backend', {})
                            # K8s versions (>= 1.19)
                            service_name = backend.get('service', {}).get('name')
                            # older versions
                            if not service_name:
                                service_name = backend.get('serviceName')

                            if service_name:
                                # which service is behind (workload)
                                target_workload_name = service_to_workload.get(service_name)
                                if target_workload_name:
                                    target_ms = find_microservice_by_name(microservices, target_workload_name)
                                    if target_ms:
                                        add_flow(
                                            flows, 
                                            service_name,  # external source
                                            target_ms['name'],
                                            "External Flow",
                                            {"host": host, "path": path.get('path', '/')}
                                        )

                # C. Services Analysis (inter-services connectivity)
                elif kind == "Service":
                    target_ms_name = service_to_workload.get(source_ms_name)
                    if target_ms_name:
                        pass
                    if manifest.get('spec', {}).get('type') == 'ExternalName':
                        external_name = manifest.get('spec', {}).get('externalName')
                        # considered as outgoing flow
                        source_ms_name = service_to_workload.get(manifest.get('metadata', {}).get('name'))
                        if source_ms_name:
                            add_flow(
                                flows,
                                source_ms_name,
                                external_name,
                                "External Flow",
                                None
                            )
    
    return flows

def add_flow(information_flows: dict, from_ms: str, to_ms: str, flow_type: str, properties: set):
    """Helper function to add a flow to the flows dictionary."""
    print(f"""NEW FLOW :
          From: {from_ms}
          To  : {to_ms}""")
    
    flow_key = max(information_flows.keys(), default=-1) + 1
    if flow_key not in information_flows:
        information_flows[flow_key] = {
            "sender": from_ms,
            "receiver": to_ms,
            "stereotype_instances": ["restful_http"],
            "properties": properties
        }

def find_microservice_by_name(microservices: dict, name: str) -> dict:
    """Helper function to find a microservice by its name."""
    return next(
            (ms for ms in microservices.values() if ms['name'] == name),
            None
        )

def infer_target_service(value: str) -> str:
    """Infers a service name from a string (e.g., URL, variable name)."""
    
    match = re.search(r"([a-zA-Z0-9-]+\.)?([a-zA-Z0-9-]+)(:\d+)?", value)
    return match.group(2) if match else None

def parse_k8s_manifests(path_file, k8s_content: str) -> list:
    """Parses K8s manifest, handling multiple YAML documents."""
    try:
        content = "\n".join(k8s_content)
        return list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        print(f"\033[91m--> {path_file} <--\nError parsing K8s content: {e}\033[0m")
        logger.error(f"--> {path_file} <-- | Error parsing K8s content: {e}")
        return []
