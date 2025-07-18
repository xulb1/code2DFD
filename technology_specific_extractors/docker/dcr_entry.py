import os

import tmp.tmp as tmp


def detect_port(path: str) -> int:
    """Extracts port from Dockerfile.
    """

    port = False
    local_repo_path = tmp.tmp_config["Repository"]["local_path"]

    dirs = [os.scandir(os.path.join(local_repo_path, os.path.dirname(path)))]

    while dirs:
        dir = dirs.pop()
        for entry in dir:
            if entry.is_file() and entry.name.casefold() == "dockerfile":
                with open(entry.path, "r") as file:
                    lines = file.readlines()
                for line in lines:
                    line = line.casefold()
                    if "expose" in line:
                        port = line.split("expose")[1].split("/")[0].strip()
            elif entry.is_dir():
                dirs.append(os.scandir(entry.path))

    return port
