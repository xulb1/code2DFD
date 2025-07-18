import ast

from output_generators.logger import logger
# Component extractors
import technology_specific_extractors.docker_compose.dcm_entry as dcm
import technology_specific_extractors.gradle.grd_entry as grd
import technology_specific_extractors.maven.mvn_entry as mvn
# Flow extractors
import technology_specific_extractors.database_connections.dbc_entry as dbc
import technology_specific_extractors.implicit_connections.imp_entry as imp
import technology_specific_extractors.feign_client.fgn_entry as fgn
import technology_specific_extractors.resttemplate.rst_entry as rst
import technology_specific_extractors.rabbitmq.rmq_entry as rmq
import technology_specific_extractors.html.html_entry as html
import technology_specific_extractors.kafka.kfk_entry as kfk

import tmp.tmp as tmp

import inspect
import os

def get_microservices(dfd) -> dict:
    """Calls get_microservices from correct container technology or returns existing list.
    """

    # stack = inspect.stack()
    # appelant = stack[1]
    # fichier = os.path.basename(appelant.filename)  # Juste le nom du fichier
    # fonction = appelant.function
    # print(f"\033[34mAppelée depuis la fonction '{fonction}' dans le fichier '{fichier}'\033[0m")
    
    if tmp.tmp_config.has_option("DFD", "microservices"):
        return ast.literal_eval(tmp.tmp_config["DFD"]["microservices"])
    
    
    print("\033[34mAnalyse des microservices ...\033[0m")
    logger.info("Microservices not set yet, start extraction")

    mvn.set_microservices(dfd)
    grd.set_microservices(dfd)
    dcm.set_microservices(dfd)
    if tmp.tmp_config.has_option("DFD", "microservices"):
        return ast.literal_eval(tmp.tmp_config["DFD"]["microservices"])


def get_information_flows(dfd) -> dict:
    """Calls get_information_flows from correct communication technology.
    """
    # stack = inspect.stack()
    # appelant = stack[1]
    # fichier = os.path.basename(appelant.filename)
    # fonction = appelant.function
    # print(f"\033[32mAppelée depuis la fonction '{fonction}' dans le fichier '{fichier}'\033[0m")
    
    if tmp.tmp_config.has_option("DFD", "information_flows"):
        return ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])
    
    print("\033[32mAnalyse des flows ...\033[0m")
    logger.info("Information flows not set yet, start extraction")
    communication_techs_list = ast.literal_eval(tmp.tmp_config["Technology Profiles"]["communication_techs_list"])
    for com_tech in communication_techs_list:
        eval(com_tech[1]).set_information_flows(dfd)

    if tmp.tmp_config.has_option("DFD", "information_flows"):
        return ast.literal_eval(tmp.tmp_config["DFD"]["information_flows"])


def detect_microservice(file_path: str, dfd) -> str:
    """Calls detect_microservices from correct microservice detection technology.
    """
    # stack = inspect.stack()
    # appelant = stack[1]
    # fichier = os.path.basename(appelant.filename)
    # fonction = appelant.function
    # print(f"\033[31mDetect_microservice appelée depuis la fonction '{fonction}' dans le fichier '{fichier}'\033[0m")
    
    microservice = mvn.detect_microservice(file_path, dfd)
    if microservice: print("mvn")
    if not microservice:
        microservice = grd.detect_microservice(file_path, dfd)
        if microservice: print("grd")
    if not microservice:
        microservice = dcm.detect_microservice(file_path, dfd)
        if microservice: print("dcm")
    return microservice
