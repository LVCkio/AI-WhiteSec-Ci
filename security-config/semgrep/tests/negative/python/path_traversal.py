import os
from flask import request, send_file, send_from_directory


def read_fixed():
    # ok: team.path-traversal, team.path-request-taint
    contents = open("/var/data/report.txt").read()
    return contents


def unpack(tar, directory):
    # ok: team.archive-extract-all
    tar.extractall(directory, filter="data")


def get_safe_path(name):
    # ok: team.path-from-parameter
    return os.path.join(INDEXDIR, os.path.basename(name))


def get_fixed_path():
    # ok: team.path-from-parameter
    return os.path.join(INDEXDIR, "index.json")


def download_safe():
    name = request.args["name"]
    # ok: team.path-request-taint
    return send_file(os.path.join(UPLOAD_DIR, secure_filename(name)))


def avatar(filename):
    # ok: team.path-from-parameter
    return send_from_directory(AVATAR_DIR, filename)


# ---- v4.1
def config_path():
    # ok: team.py.audit.pathlib-api
    here = Path(__file__)
    # ok: team.py.audit.pathlib-api
    cfg = Path("/etc/app/config.ini")
    return here, cfg


# ---- v4.6.1: chuoi chua code khong phai loi goi that
def docs_v461(name):
    # ok: team.path-traversal
    example = "open(request.args['filename'])"
    # ok: team.path-traversal
    contents = open(os.path.join(BASE_DIR, name)).read()
    return example, contents
