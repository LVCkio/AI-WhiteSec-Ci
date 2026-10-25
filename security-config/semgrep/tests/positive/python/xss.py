import jinja2
from flask import request, make_response


def views(user_input, name, url, title):
    # ruleid: team.xss-unsafe-html
    html = mark_safe(user_input)
    # ruleid: team.xss-html-string-building
    row = "<td>" + name + "</td>"
    # ruleid: team.xss-html-string-building
    link = f'<a href="{url}">{title}</a>'
    # ruleid: team.xss-unsafe-html
    env = jinja2.Environment(loader=None, autoescape=False)
    # ruleid: team.audit.html-output-api
    return HttpResponse(row)


def not_found(req):
    # ruleid: team.xss-response-formatting
    return HttpResponse("Not here yet: %s" % req.path, status=410)


def hello():
    name = request.args.get("name", "")
    # ruleid: team.py.xss-taint, team.xss-response-formatting
    return make_response("<h1>Hello " + name + "</h1>")


# ---- v4.1
def make_env(loader, body):
    # ruleid: team.py.xss-jinja-autoescape-default
    env = jinja2.Environment(loader=loader)
    # ruleid: team.py.audit.response-body
    return flask.Response(body, mimetype="text/html")
