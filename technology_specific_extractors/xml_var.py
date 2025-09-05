import xml.etree.ElementTree as ET
import re

def extract_properties(root, ns):
    """Récupère toutes les propriétés du POM."""
    props = {}

    # Propriétés standards Maven
    for tag in ["groupId", "artifactId", "version", "packaging", "name"]:
        el = root.find(f"m:{tag}", ns)
        if el is not None and el.text:
            props[f"project.{tag}"] = el.text.strip()

    # Propriétés définies dans <properties>
    for prop in root.findall("m:properties/*", ns):
        props[prop.tag.split("}")[1]] = prop.text.strip() if prop.text else ""

    return props

def substitute(text, props):
    """Remplace ${...} par la valeur correspondante."""
    if not text:
        return text
    return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), text)

def resolve_tree(element, props):
    """Parcourt récursivement l'arbre XML et remplace les variables."""
    if element.text:
        element.text = substitute(element.text, props)
    if element.tail:
        element.tail = substitute(element.tail, props)
    for child in element:
        resolve_tree(child, props)

def resolve_pom(pom_file):
    tree = ET.parse(pom_file)
    root = tree.getroot()
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}

    props = extract_properties(root, ns)
    resolve_tree(root, props)

    return tree, props

if __name__ == "__main__":
    tree, props = resolve_pom("pom.xml")

    print("=== Propriétés détectées ===")
    for k, v in props.items():
        print(f"{k} = {v}")

    # print("\n=== Exemple: build/finalName résolu ===")
    # ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    # final_name = tree.getroot().find("m:build/m:finalName", ns)
    # if final_name is not None:
    #     print(final_name.text)

    # # (Optionnel) Sauvegarder le POM avec variables remplacées
    # tree.write("pom_resolu.xml", encoding="utf-8", xml_declaration=True)
