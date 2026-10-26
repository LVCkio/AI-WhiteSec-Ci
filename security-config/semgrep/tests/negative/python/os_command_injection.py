import os
import shlex
import subprocess
from flask import request


def maintenance(src, dst):
    # ok: team.os-command-injection, team.audit.process-api, team.py.cmdi-taint
    os.system("service nginx restart")
    # ok: team.os-command-injection
    subprocess.run(["echo", "hello"], check=True)
    # ok: team.os-command-string-building
    subprocess.call(["convert", src, dst])
    # ok: team.os-command-injection
    os.getcwd()


def ping():
    host = request.args["host"]
    # ok: team.py.cmdi-taint
    os.system("ping -c 1 " + shlex.quote(host))


def ping_checked():
    host = validate_host(request.args["host"])
    # ok: team.py.cmdi-taint
    os.system("ping -c 1 " + host)


# ---- v4.6.1: chuoi chua code khong phai loi goi that
# ok: team.os-command-injection
EXAMPLE = "subprocess.run(cmd, shell=True)"
