"""Converts codeablemodels into proper plantuml and lets it render
"""

import plantuml

import output_generators.codeable_models_to_plantuml as codeable_models_to_plantuml


def output_png(codeable_models_path: str):
    """Converts CodeableModels output into different PlantUML graphics and renders it as PNG.
    """

    new_plantuml, new_plantuml_path = codeable_models_to_plantuml.convert(codeable_models_path)

    generator = plantuml.PlantUML(url="http://www.plantuml.com/plantuml/img/")
    try:
        generator.processes_file(filename=new_plantuml_path)
    except Exception:
        print("\033[91mNo connection to the PlantUML server possible or malformed input to the server.\033[0m")
