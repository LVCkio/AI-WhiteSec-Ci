import os
import subprocess
from flask import request


def run(command, cmd, program, args, src, dst):
    # ruleid: team.os-command-injection, team.audit.process-api
    os.system(command)
    # ruleid: team.os-command-injection, team.audit.process-api
    subprocess.check_output(cmd, shell=True)
    # ruleid: team.os-command-injection
    os.execvp(program, args)
    # ruleid: team.os-command-string-building, team.audit.process-api
    subprocess.call(f"convert {src} {dst}")


def ping():
    host = request.args["host"]
    # ruleid: team.py.cmdi-taint, team.os-command-injection
    os.system("ping -c 1 " + host)
