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
