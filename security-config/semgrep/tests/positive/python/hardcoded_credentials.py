import jwt

# ruleid: team.hardcoded-credentials
password = "correct-horse-battery"
# ruleid: team.hardcoded-credentials
SECRET_KEY = "d8f7a6s5d4f3"
# ruleid: team.hardcoded-auth-header
headers = {"Authorization": "Bearer AD3UdRPPgdzUvZ3gpmmICiBlrDp37e"}
# ruleid: team.hardcoded-auth-header
token = jwt.encode(payload, "Company9942%", algorithm="HS256")


def login(username, password):
    # ruleid: team.py.hardcoded-password-compare
    if password == "Winter2024!":
        return True
    return False


# ---- v4.6.1: rule AST (thay pattern-regex)
# ruleid: team.hardcoded-credentials
DB_CONFIG = {"password": "S3cr3tPass"}
# ruleid: team.hardcoded-credentials
conn = connect(host="db", api_key="AKIA1234ABCD")


def configure(settings):
    # ruleid: team.hardcoded-credentials
    settings.secret_key = "flask-secret-0042"


# ruleid: team.hardcoded-auth-header
session.headers["Authorization"] = "Token 9f8e7d6c5b4a3f2e"
