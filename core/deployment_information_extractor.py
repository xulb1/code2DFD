import os
import re
import yaml
import json
import uuid
import glob

import core.technology_switch as tech_sw
import core.file_interaction as fi

class fi2:
    @staticmethod
    def search_files(patterns, path="/"):
        all_files = []
        for pattern in patterns:
            all_files.extend(glob.glob(os.path.join(path, '**', pattern), recursive=True))
        return [(f, None) for f in all_files]

    @staticmethod
    def get_file_as_yaml(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return list(yaml.safe_load_all(f))
        except (yaml.YAMLError, FileNotFoundError) as e:
            return []
    
    @staticmethod
    def read_file_lines(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.readlines()
        except FileNotFoundError:
            return []

def generate_id():
    return str(uuid.uuid4())

def extract_java_runtime_from_dockerfile(content):
    java_version, os_name = "N/A", "N/A"
    for line in content:
        line = line.strip().lower()
        if line.startswith("from"):
            match_jdk = re.search(r"openjdk:(\d+)", line)
            match_java = re.search(r"jdk:(\d+)", line)
            if match_jdk: java_version = match_jdk.group(1)
            elif match_java: java_version = match_java.group(1)
            if "alpine" in line: os_name = "Alpine Linux"
            elif "ubuntu" in line: os_name = "Ubuntu"
            elif "debian" in line: os_name = "Debian"
            else: os_name = "Linux"
    return java_version, os_name

def parse_dockerfile(path, service_name, service_mapping):
    content = fi2.read_file_lines(path)
    dirname = os.path.basename(os.path.dirname(path))
    image_name, tag, exposed_ports, env_vars = "unknown", "latest", [], {}
    java_version, os_name = extract_java_runtime_from_dockerfile(content)
    
    for line in content:
        line = line.strip()
        if line.startswith("FROM"):
            parts = line.split()
            if len(parts) >= 2:
                image_parts = parts[1].split(":")
                image_name = image_parts[0]
                if len(image_parts) > 1: tag = image_parts[1]
        elif line.startswith("EXPOSE"):
            exposed_ports += [int(p) for p in line.split()[1:]]
    
    component_id = None
    for k,v in service_mapping.items():
        if service_name.casefold().replace('_','').replace('-','') in v.casefold().replace('_','').replace('-','') \
            or v.casefold().replace('_','').replace('-','') in service_name.casefold().replace('_','').replace('-',''):
            component_id=k
            break
    
    cpu_requests = "UNKNOWN"
    cpu_limits = "UNKNOWN"
    memory_requests = "UNKNOWN"
    memory_limits = "UNKNOWN"

    return {
        "id": f"ctr-{generate_id()}",
        "name": dirname,
        "imageName": image_name,
        "tag": tag,
        "exposedPorts": exposed_ports,
        "cpuRequests": cpu_requests,
        "cpuLimits": cpu_limits,
        "memoryRequests": memory_requests,
        "memoryLimits": memory_limits,
        "executionEnvironment": {"id": f"{generate_id()}-env", "name": "Docker"},
        "representsDeployedComponentId": component_id,
        "operatingSystem": os_name,
        "javaRuntimeVersion": java_version
    }

def parse_compose(path, service_mapping):
    docs = fi2.get_file_as_yaml(path)
    if not docs: return []
    data = docs[0]
    elements = []
    
    for name, svc in data.get("services", {}).items():
        component_id = None
        for k,v in service_mapping.items():
            if name.casefold().replace('_','').replace('-','') in v.casefold().replace('_','').replace('-','') \
                or v.casefold().replace('_','').replace('-','') in name.casefold().replace('_','').replace('-',''):
                component_id=k
                break
        
        deploy_cfg = svc.get("deploy", {}).get("resources", {})
        limits = deploy_cfg.get("limits", {})
        requests = deploy_cfg.get("reservations", {})

        cpu_requests = requests.get("cpus") or "UNKNOWN"
        memory_requests = requests.get("memory") or "UNKNOWN"
        cpu_limits = limits.get("cpus") or "UNKNOWN"
        memory_limits = limits.get("memory") or "UNKNOWN"
        
        ports = []
        for p in svc.get("ports", []):
            try:
                if isinstance(p, int): ports.append(p)
                elif ":" in p: ports.append(int(p.split(":")[-1]))
                else: ports.append(int(p))
            except ValueError: pass
        
        elements.append({
            "id": f"compose-ctr-{generate_id()}",
            "name": name,
            "imageName": svc.get("image", name).split(":")[0] if svc.get("image") else name,
            "tag": svc.get("image", "latest").split(":")[-1] if svc.get("image") and ":" in svc.get("image") else "latest",
            "exposedPorts": ports,
            "cpuRequests": cpu_requests,
            "memoryRequests": memory_requests,
            "cpuLimits": cpu_limits,
            "memoryLimits": memory_limits,
            "executionEnvironment": {"id": f"{generate_id()}-env", "name": "Docker Compose"},
            "representsDeployedComponentId": component_id
        })
    return elements

def parse_k8s_file(path, service_mapping):
    docs = fi2.get_file_as_yaml(path)
    if not docs: return []
    
    pods = []
    networks = []
    
    for doc in docs:
        if not doc or not isinstance(doc, dict): continue
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {})
        spec = doc.get("spec", {})
        
        if kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]:
            containers_list = []
            template_spec = spec.get("template", {}).get("spec", {}) if "template" in spec else spec
            
            for c in template_spec.get("containers", []):
                container_name = c.get("name")
                component_id = None
                for k,v in service_mapping.items():
                    if container_name.casefold().replace('_','').replace('-','') in v.casefold().replace('_','').replace('-','') \
                        or v.casefold().replace('_','').replace('-','') in container_name.casefold().replace('_','').replace('-',''):
                        component_id=k
                        break

                image_name = c.get("image", "").lower()
                java_version_match = re.search(r"openjdk:(\d+)", image_name)
                java_version = java_version_match.group(1) if java_version_match else "UNKNOWN"
                os_name = "Alpine Linux" if "alpine" in image_name else "Linux"
                
                cpu_requests = c.get("resources", {}).get("requests", {}).get("cpu", "UNKNOWN")
                memory_requests = c.get("resources", {}).get("requests", {}).get("memory", "UNKNOWN")
                cpu_limits = c.get("resources", {}).get("limits", {}).get("cpu", "UNKNOWN")
                memory_limits = c.get("resources", {}).get("limits", {}).get("memory", "UNKNOWN")

                containers_list.append({
                    "id": f"k8s-ctr-{generate_id()}",
                    "name": c.get("name"),
                    "imageName": c.get("image", "N/A").split(":")[0],
                    "tag": c.get("image", "N/A").split(":")[1] if ":" in c.get("image", "N/A") else "latest",
                    "exposedPorts": [p.get("containerPort") for p in c.get("ports", [])] if "ports" in c else [],
                    "cpuRequests": cpu_requests,
                    "memoryRequests": memory_requests,
                    "cpuLimits": cpu_limits,
                    "memoryLimits": memory_limits,
                    "executionEnvironment": {"id": f"{generate_id()}-env", "name": "Kubernetes Pod"},
                    "representsDeployedComponentId": component_id,
                    "operatingSystem": os_name,
                    "javaRuntimeVersion": java_version
                })
            
            pods.append({
                "id": f"k8s-{generate_id()}",
                "type": kind,
                "name": metadata.get("name", "unknown"),
                "containers": containers_list
            })
            
        elif kind == "NetworkPolicy":
            pod_selector = spec.get("podSelector", {}).get("matchLabels", {})
            net_policies = []
            for ingress_rule in spec.get("ingress", []):
                net_policies.append({"id": f"netpol-ing-{generate_id()}", "type": "Ingress", "rulesCount": len(ingress_rule.get("from", [])), "appliesToLabels": list(pod_selector.keys())})
            for egress_rule in spec.get("egress", []):
                net_policies.append({"id": f"netpol-egr-{generate_id()}", "type": "Egress", "rulesCount": len(egress_rule.get("to", [])), "appliesToLabels": list(pod_selector.keys())})
            
            networks.append({
                "id": f"net-{generate_id()}",
                "type": "Network",
                "name": metadata.get("name", "unknown"),
                "networkAccessControlList": [metadata.get("name", "unknown")],
                "networkPolicies": net_policies,
                "subnets": []
            })
            
    return pods, networks

def get_environment_from_path(path):
    """Déduit l'environnement à partir du chemin du fichier."""
    path_parts = path.lower().split(os.sep)
    for part in path_parts:
        if "prod" in part or "production" in part:
            return "PROD"
        if "dev" in part or "development" in part:
            return "DEV"
        if "test" in part or "staging" in part:
            return "STAGING"
    return "UNKNOWN"

def analyze_project(root_path, microservices_dict, dfd):
    service_mapping = {k: v['name'] for k,v in microservices_dict.items()}
    
    environments = {}

    # 1. Parsing de Kubernetes
    k8s_files = fi.search_files(["*.yaml", "*.yml"], path=root_path, getContent=False)
    for fpath in k8s_files:
        env = get_environment_from_path(fpath)
        if env not in environments:
            environments[env] = {
                "id": f"deploy-{generate_id()}",
                "name": f"Déploiement K8s pour {env}",
                "description": f"Déploiement K8s basé sur les manifests trouvés dans l'environnement {env}.",
                "environment": [env],
                "containerOrchestrator": ["KUBERNETES"],
                "deploymentStrategy": "UNKNOWN",
                "rollbackStrategy": "UNKNOWN",
                "deploymentElements": []
            }
            # Créer une structure de cluster et de serveur par défaut pour cet env
            cluster_obj = {"id": f"cluster-{generate_id()}-{env}", "name": f"Cluster K8s - {env}", "orchestratorToolVersion": "UNKNOWN", "resourceLimitsConfigurable": True, "servers": []}
            server_obj = {"id": f"srv-{generate_id()}-{env}", "name": f"Worker Node - {env}", "serverType": "KUBERNETES_NODE", "operatingSystem": "UNKNOWN", "javaRuntimeVersion": "UNKNOWN", "containers": []}
            cluster_obj["servers"].append(server_obj)
            environments[env]["deploymentElements"].append(cluster_obj)
        
        pods, networks = parse_k8s_file(fpath, service_mapping)
        cluster_elements = environments[env]["deploymentElements"][0]
        server_elements = cluster_elements["servers"][0]
        
        # Ajoute les pods aux conteneurs du serveur
        for pod in pods:
            server_elements["containers"].extend(pod["containers"])

        # Ajoute les réseaux
        if networks:
            # Vérifie si un élément 'Network' existe déjà
            network_exists = False
            for elem in environments[env]["deploymentElements"]:
                if elem["type"] == "Network":
                    elem["networkPolicies"].extend(networks[0]["networkPolicies"])
                    network_exists = True
                    break
            if not network_exists:
                environments[env]["deploymentElements"].extend(networks)

    # 2. Parsing de Docker Compose
    compose_files = fi.search_files(["docker-compose*.yml"], path=root_path, getContent=False)
    for fpath in compose_files:
        env = get_environment_from_path(fpath)
        if env not in environments:
            environments[env] = {
                "id": f"deploy-{generate_id()}",
                "name": f"Stack Docker Compose pour {env}",
                "description": f"Déploiement Docker Compose basé sur les fichiers trouvés dans l'environnement {env}.",
                "environment": [env],
                "containerOrchestrator": ["DOCKER_COMPOSE"],
                "deploymentStrategy": "UNKNOWN",
                "rollbackStrategy": "UNKNOWN",
                "deploymentElements": []
            }
            cluster_obj = {"id": f"cluster-{generate_id()}-{env}", "name": f"Docker Compose Stack - {env}", "orchestratorToolVersion": "docker-compose", "resourceLimitsConfigurable": True, "servers": []}
            server_obj = {"id": f"srv-{generate_id()}-{env}", "name": f"Docker Host - {env}", "serverType": "VIRTUAL_MACHINE", "operatingSystem": "UNKNOWN", "javaRuntimeVersion": "UNKNOWN", "containers": []}
            cluster_obj["servers"].append(server_obj)
            environments[env]["deploymentElements"].append(cluster_obj)

        containers = parse_compose(fpath, service_mapping)
        server_elements = environments[env]["deploymentElements"][0]["servers"][0]
        server_elements["containers"].extend(containers)

    # 3. Parsing des Dockerfiles
    dockerfiles = fi.search_files(["Dockerfile"], path=root_path, getContent=False)
    for fpath in dockerfiles:
        env = get_environment_from_path(fpath)
        if env not in environments:
            environments[env] = {
                "id": f"deploy-{generate_id()}",
                "name": f"Déploiement Docker pour {env}",
                "description": f"Déploiement Docker basé sur les Dockerfiles trouvés dans l'environnement {env}.",
                "environment": [env],
                "containerOrchestrator": ["DOCKER"],
                "deploymentStrategy": "UNKNOWN",
                "rollbackStrategy": "UNKNOWN",
                "deploymentElements": []
            }
            cluster_obj = {"id": f"cluster-{generate_id()}-{env}", "name": f"Docker Local Env - {env}", "orchestratorToolVersion": "docker", "resourceLimitsConfigurable": False, "servers": []}
            server_obj = {"id": f"srv-{generate_id()}-{env}", "name": f"Local Machine - {env}", "serverType": "LOCAL_MACHINE", "operatingSystem": "UNKNOWN", "javaRuntimeVersion": "UNKNOWN", "containers": []}
            cluster_obj["servers"].append(server_obj)
            environments[env]["deploymentElements"].append(cluster_obj)
        
        service_name_deduced = tech_sw.detect_microservice(fpath, dfd)
        
        container = parse_dockerfile(fpath, service_name_deduced, service_mapping)
        server_elements = environments[env]["deploymentElements"][0]["servers"][0]
        server_elements["containers"].append(container)
    
    # Finalisation et formatage de la sortie
    final_result = list(environments.values())

    return final_result

### TEST ###
if __name__ == "__main__":
    microservices_data = {
        0: {'name': 'api-gateway', 'image': 'image_placeholder', 'type': 'service', 'properties': {'zuul_route_serviceId': 'article-service', 'load_balancer': 'Ribbon', 'Port': '${PORT:8765}'}, 'stereotype_instances': ['security_vulnerability', 'gateway', 'infrastructural', 'load_balancer'], 'tagged_values': [('Port', 8765), ('Gateway', 'Zuul'), ('Load Balancer', 'Ribbon'), ('Security Risk', ['No OAuth or Token Security', 'No auth logic found'])]},
        1: {'name': 'article-service', 'image': 'image_placeholder', 'type': 'service', 'properties': {'Port': '${PORT:8080}', 'load_balancer': 'Ribbon'}, 'stereotype_instances': ['internal', 'local_logging', 'circuit_breaker', 'security_vulnerability'], 'tagged_values': [('Port', 8080), ('Logging Technology', 'Lombok'), ('Circuit Breaker', 'Hystrix'), ('Security Risk', ['No OAuth or Token Security', 'No auth logic found'])]},
        2: {'name': 'discovery', 'image': 'image_placeholder', 'type': 'service', 'properties': {'Port': '${PORT:8761}'}, 'stereotype_instances': ['security_vulnerability', 'service_registry', 'infrastructural', 'isContainerised'], 'tagged_values': [('Port', 8761), ('Service Registry', 'Eureka'), ('Security Risk', ['Insecure Eureka Registry', 'No OAuth or Token Security', 'No auth logic found'])]},
        3: {'name': 'author-service', 'image': 'image_placeholder', 'type': 'service', 'properties': {'load_balancer': 'Ribbon', 'Port': '${PORT:8081}'}, 'stereotype_instances': ['internal', 'local_logging', 'circuit_breaker', 'security_vulnerability'], 'tagged_values': [('Port', 8081), ('Logging Technology', 'Lombok'), ('Circuit Breaker', 'Hystrix'), ('Security Risk', ['No OAuth or Token Security', 'No auth logic found'])]}
    }
    
    project_path = "./" 
    
    deployment_dict = analyze_project(project_path, microservices_data)
    
    print(json.dumps(deployment_dict, indent=2))