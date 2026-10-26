import os
import jwt

# ok: team.hardcoded-credentials
password = os.environ["APP_PASSWORD"]
# ok: team.hardcoded-auth-header
token = jwt.encode(payload, settings.JWT_KEY, algorithm="HS256")
# ok: team.hardcoded-auth-header
headers = {"Authorization": "Bearer " + token}


def login(username, password, stored):
    # ok: team.py.hardcoded-password-compare
    if password == "":
        return False
    # ok: team.py.hardcoded-password-compare
    if username == "admin":
        return check_password_hash(stored, password)
    return False


# ---- v4.6.1: chuoi/comment khong phai gan gia tri
# ok: team.hardcoded-credentials
HELP = "Set password = 'hunter22' in your local config"
# ok: team.hardcoded-credentials
api_key = os.getenv("API_KEY", "")
# ok: team.hardcoded-auth-header
DOC = '{"Authorization": "Bearer AD3UdRPPgdzUvZ3gpmmICiBlrDp37e"}'
