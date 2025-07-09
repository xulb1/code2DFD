import ast
import os.path
from pathlib import Path

import tmp.tmp as tmp


plantuml_new = str()


def convert(codeable_models_path: str) -> str:
    """Creates (good looking) PlantUML file out of CodeableModels file.
    """

    global plantuml_new

    output_file_path = tmp.tmp_config["Analysis Settings"]["output_path"]
    parts = Path(output_file_path).parts
    filename = f"{parts[-2]}--{parts[-1]}_uml.txt"
    output_file_path = os.path.join(output_file_path, filename)

    add_header()

    with open(codeable_models_path, 'r') as input_file:
        codeable_models = input_file.readlines()

    # Call appropriate conversion functions for each line
    for line in codeable_models:
        if "CClass(external_component" in line:
            add_entity(line, "external_entity")
        elif "CClass(service" in line:
            if "stereotype_instances" in line:
                if "database" in line.split("stereotype_instances")[1].split(",")[0]:
                    add_entity(line, "database")
                else:
                    add_entity(line, "service")
            else:
                add_entity(line, "service")
        elif "add_links(" in line:
            add_entity(line, "flow")

    add_footer()

    write_output(output_file_path)

    return plantuml_new, output_file_path


def add_header():
    """Adds the header of the file.
    """

    global plantuml_new

    plantuml_new += """
@startuml
skinparam monochrome true
skinparam ClassBackgroundColor White
skinparam defaultFontName Arial
skinparam defaultFontSize 11


digraph dfd2{
    node[shape=record]
"""

    return 0


def add_entity(line: str, entity_type: str):
    """Takes line for flows, services, external entities or databases from old format, parses it, creates line in new format, and appends it to output string.
    """

    global plantuml_new

    # Parse old line
    stereotypes = set()
    tagged_values = set()
    
    if entity_type=="flow":
        sender = line.split("}")[0].split(":")[0].split("{")[1].strip()
        receiver = line.split("}")[0].split(":")[1].strip()
    else:
        name = line.split("=")[0].strip()
    
    if "stereotype_instances" in line:
        stereotypes = line.split("stereotype_instances =")[1].split("]")[0].split("[")[1].split(",")
    if "tagged_values" in line:
        if entity_type=="service":
            tagged_values = line.split("tagged_values =")[1].strip().strip(")")
            try:
                data = ast.literal_eval(tagged_values)
                tagged_values = [f"{repr(k)}: {repr(v).replace("{","\\{").replace("}","\\}")}" for k, v in data.items()]
            except Exception as e:
                tagged_values = tagged_values.split("}")[0].split("{")[1].split(",")
                print("ERROR",e)
        else:
            tagged_values = line.split("tagged_values =")[1].split("}")[0].split("{")[1].split(",")
    
    # Create new line
    if entity_type=="flow":
        new_line = f"        {sender} -> {receiver} [label = \" "
    elif entity_type=="service":
        new_line = f"        {name} [label = \"{{Service: {name} | "
    elif entity_type=="database":
        new_line = f"        {name} [label = \"|{{Service: {name} | "
    else:
        new_line = f"        {name} [label = \"{{External Entity: {name} | "
    
    for stereotype in stereotypes:
        new_line += f"--{stereotype.strip()}--\\n"
    if tagged_values:
        if entity_type=="flow":
            for tagged_value in tagged_values:
                new_line += f"{tagged_value.replace("\"", "")}\\n"
        else:
            for tagged_value in tagged_values:
                if ":" in tagged_value:
                    tag = tagged_value.split(":")[0].strip()
                    value = ":".join(v.strip().strip("\"") for v in tagged_value.split(":")[1:])
                    new_line += f"{tag}: {value}\\n"
    
    if entity_type=="flow":
        new_line += "\"]\n"
    elif entity_type=="service":
        new_line += "}\" shape = Mrecord];\n"
    elif entity_type=="database":
        new_line += "}\"]\n"
    else:
        new_line += "}\"];\n"

    # Append new line
    plantuml_new += new_line

    return


def add_footer():
    """Adds the footer of the file.
    """

    global plantuml_new
    plantuml_new += """
}
@enduml
"""

    return 0


def write_output(output_file_path):
    """Writes the new format to a file.
    """

    global plantuml_new

    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    with open(output_file_path, 'w+') as output_file:
        output_file.write(plantuml_new)
