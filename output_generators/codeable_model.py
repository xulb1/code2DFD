import os
from pathlib import Path

import tmp.tmp as tmp


# the used metamodel is microservice_dfds_metamodel.py

def output_codeable_model(microservices: dict, information_flows: dict, external_components: dict):
    """Entry function to creation of codeable models. Calls all necessary helper functions and outputs the codeable model"""

    parts = Path(tmp.tmp_config["Analysis Settings"]["output_path"]).parts
    model_name = f"{parts[-2]}_{parts[-1]}"

    file_content = f"{header()}\"{model_name}\""

    # CodeableModels needs the name of one of the nodes for its final invocation, is written into this var
    last_node = str()
    allComponents = str()

    # Microservices
    file_content, last_node, allComponents = output_uml_entities(microservices, "microservices", file_content, allComponents)
    # External Components
    file_content, last_node, allComponents = output_uml_entities(external_components, "external_components", file_content, allComponents)
    # Information Flows
    file_content, last_node, _ = output_uml_entities(information_flows, "information_flows", file_content, allComponents=None)

    file_content += f"allComponents = [{allComponents[:-2]}]"
    file_content += footer()

    output_path = str()
    output_path = create_file(model_name, file_content)
    return file_content, output_path

def output_uml_entities(entities: dict, entity_type: str, file_content, allComponents: str):
    last_node = str()
    new_line = ""
    
    for m in entities.values():
        # Tagged Values
        tagged_values = dict()
        if "tagged_values" in m:
            for t in m["tagged_values"]:
                if t[0].casefold() == "port" and isinstance(t[1], int):
                    tagged_values[t[0]] = int(t[1])
                else:
                    tagged_values[t[0]] = t[1]
        
        # Stereotypes
        stereotypes = set()
        if "stereotype_instances" in m:
            if type(m["stereotype_instances"]) in [set, list]:
                for s in m["stereotype_instances"]:
                    stereotypes.add(s)
            else:
                stereotypes.add(m["stereotype_instances"])
            
        if "properties" in m:
            if m["properties"]:
                if isinstance(m["properties"], dict):
                    for k,v in m["properties"].items():
                        tagged_values[k] = str(v)
                else:
                    stereotypes.add(str(m["properties"]))

        if stereotypes:
            stereotypes = str(list(stereotypes)).replace("'", "")
                
        if entity_type=="information_flows":
            sender = str(m["sender"]).replace("-", "_")
            receiver = str(m["receiver"]).replace("-", "_")

            if stereotypes and tagged_values:
                new_line = "\nadd_links({" + sender + ": " + receiver + "}, stereotype_instances = " + str(stereotypes) + ", tagged_values = " + str(tagged_values) + ")"
            elif stereotypes:
                new_line = "\nadd_links({" + sender + ": " + receiver + "}, stereotype_instances = " + str(stereotypes) + ")"
            else:
                new_line = "\nadd_links({" + sender + ": " + receiver + "})"
        
        else:
            name = str(m["name"]).replace("-", "_")
            
            if entity_type=="external_components":
                entity = "external_component"
            elif entity_type=="microservices":
                entity = "service"
                last_node = name
                
            # Create entry
            if stereotypes and tagged_values:
                new_line = f"\n{name} = CClass({entity}, \"{m["name"]}\", stereotype_instances = {stereotypes}, tagged_values = {tagged_values})"
            elif stereotypes:
                new_line = f"\n{name} = CClass({entity}, \"{m["name"]}\", stereotype_instances = {stereotypes})"
            else:
                new_line = f"\n{name} = CClass({entity}, \"{m["name"]}\")"
            allComponents += f"{name}, "
        
        file_content += new_line
    
    return file_content, last_node, allComponents


def create_file(model_name: str, content: str):
    """Writes content to file.
    """
    model_name = model_name.replace("-", "_")
    output_path = tmp.tmp_config["Analysis Settings"]["output_path"]
    filename = f"{model_name}.py"
    output_path = os.path.join(output_path, filename)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as file:
        file.write(content)

    return output_path


def header():
    return "from codeable_models import CClass, CBundle, add_links, CStereotype, CMetaclass, CEnum, CAttribute \n\
from metamodels.microservice_dfds_metamodel import * \n\
from plant_uml_renderer import PlantUMLGenerator \n\
plantuml_path = \"../../plantuml.jar\" \n\
output_directory = \".\" \n\
model_name = "


def footer():
    return "\nmodel = CBundle(model_name, elements = allComponents\n\
def run():\n\
    generator = PlantUMLGenerator()\n\
    generator.plant_uml_jar_path = plantuml_path\n\
    generator.directory = output_directory\n\
    generator.object_model_renderer.left_to_right = True\n\
    generator.generate_object_models(model_name, [model, {}])\n\
    print(f\"Generated models in {generator.directory!s}/\" + model_name)\n\
if __name__ == \"__main__\":\n\
    run()"
