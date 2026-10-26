import os
from flask import request, send_file


def read_report():
    # ruleid: team.path-traversal, team.path-request-taint, team.audit.file-path-api
    contents = open(request.args.get("filename")).read()
    return contents


def unpack(tar, directory):
    # ruleid: team.archive-extract-all
    tar.extractall(directory)


def get_index_path(index):
    # ruleid: team.path-from-parameter
    return os.path.join(INDEXDIR, index)


def download():
    name = request.args["name"]
    # ruleid: team.path-request-taint
    return send_file(os.path.join(UPLOAD_DIR, name))


# ---- v4.1
def save(name, tmp):
    # ruleid: team.py.audit.pathlib-api
    target = Path(name)
    # ruleid: team.py.audit.pathlib-api
    shutil.move(tmp, name)
    return target
