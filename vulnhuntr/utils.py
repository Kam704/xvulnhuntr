import logging
import re
import time
from pathlib import Path

from rich import print

from vulnhuntr.data_model import *
from vulnhuntr.enums import *

logger = logging.getLogger("xvulnhuntr")

def extract_between_tags(tag: str, string: str, strip: bool = False) -> list[str]:
    """
    https://github.com/anthropics/anthropic-cookbook/blob/main/misc/how_to_enable_json_mode.ipynb
    """
    ext_list = re.findall(f"<{tag}>(.+?)</{tag}>", string, re.DOTALL)
    if strip:
        ext_list = [e.strip() for e in ext_list]
    return ext_list

def write_response(config: dict, response: str, vulnerability_type: VulnType = None):
    if not config["write"]:
        return

    file_name = str(int(time.time() * 1000)) # when running tests locally we need higher precision (milliseconds) to avoid file overwrites 
    if vulnerability_type != None:
        file_name = file_name + "_" + vulnerability_type.value
    file_path = Path(config["write_folder"]) / file_name
    with open(file_path,"w") as file:
        file.write(response)

def print_definitions(definitions, config):
    if config["verbosity"] < 2:
        return

    for definition in definitions.definitions:
        if definition.source != None:
            if '\n' in definition.source:
                lines = definition.source.split('\n')
                snippet = lines[0] + '\n' + lines[1]
            else:
                snippet = definition.source[:75]
        
        logger.debug(f"Name: {definition.name}")
        logger.debug(f"Context search: {definition.context_name_requested}")
        if definition.file_path != None:
            logger.debug(f"File Path: {definition.file_path}")
        if definition.source != None:
            logger.debug(f"First two lines from source: {snippet}\n")


def print_readable(report: Response, config: dict) -> None:
    if not config["reporting"]:
        return

    logger.info('=' * 40)
    logger.info("Begin report")
    logger.info('=' * 40)
    for attr, value in vars(report).items():
        logger.info(f"{attr}:")
        if isinstance(value, str):
            # For multiline strings, add indentation
            lines = value.split('\n')
            for line in lines:
                print(f"  {line}")
        elif isinstance(value, list):
            # For lists, print each item on a new line
            for item in value:
                print(f"  - {item}")
        else:
            # For other types, just print the value
            logger.info(f"  {value}")
        logger.info('-' * 40)
    logger.info("\n\n\n")  # Add an empty line between attributes

def get_absolute_path(path_string: str):
    if path_string == None:
        return None
    path = Path(path_string)
    if path.is_absolute():
        return Path(path_string)
    else:
        return str(Path.cwd() / path)