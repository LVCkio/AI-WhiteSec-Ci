from flask import request


def report(cursor, user_id):
    # ok: team.sql-injection, team.sql-string-building, team.audit.sql-api
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    # ok: team.sql-string-building
    message = f"Could not load {user_id}"
    # ok: team.audit.sql-api
    runner.execute(job)
    return message


def lookup(cursor):
    uid = int(request.args["id"])
    # ok: team.py.sqli-taint, team.sql-injection
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    name = validate_username(request.args["name"])
    # ok: team.py.sqli-taint
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
