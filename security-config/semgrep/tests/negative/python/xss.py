import jinja2
from flask import request, render_template, make_response
from markupsafe import escape


def page():
    name = request.args.get("name", "")
    # ok: team.py.xss-taint, team.audit.html-output-api
    return render_template("hello.html", name=name)


def greet():
    name = escape(request.args.get("name", ""))
    # ok: team.py.xss-taint
    return make_response("<h1>Hello " + name + "</h1>")


def plain(user_input):
    # ok: team.xss-unsafe-html
    html = escape(user_input)
    # ok: team.xss-unsafe-html
    env = jinja2.Environment(loader=None, autoescape=True)
    # ok: team.xss-html-string-building
    title = "Report for " + user_input
    # ok: team.audit.html-output-api, team.xss-response-formatting
    return HttpResponse("Saved")


# ---- v4.1
def make_env(loader, data):
    # ok: team.py.xss-jinja-autoescape-default
    env = jinja2.Environment(loader=loader, autoescape=True)
    # ok: team.py.audit.response-body
    return flask.Response(json.dumps(data), mimetype="application/json")
