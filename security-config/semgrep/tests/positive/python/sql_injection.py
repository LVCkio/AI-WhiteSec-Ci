from flask import request


def report(cursor, user_id, owner, day):
    # ruleid: team.sql-injection, team.sql-string-building
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # ruleid: team.sql-string-building
    query = "SELECT name FROM items WHERE owner = '" + owner + "'"
    # ruleid: team.sql-string-building
    sql = "DELETE FROM logs WHERE day < %s" % day
    # ruleid: team.audit.sql-api
    cursor.execute(query)
    return sql


def lookup(cursor):
    name = request.args.get("name")
    # ruleid: team.py.sqli-taint
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


# ---- v4.6.1: rule AST (thay pattern-regex)
def report_v461(cursor, session, owner, day, name):
    # ruleid: team.sql-injection
    cursor.execute("SELECT * FROM items WHERE owner = '%s'" % owner)
    # ruleid: team.sql-injection
    cursor.executemany("DELETE FROM logs WHERE day < " + day, [])
    # ruleid: team.sql-injection
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    # ruleid: team.sql-injection
    session.execute(text("SELECT * FROM users WHERE name = '" + name + "'"))
