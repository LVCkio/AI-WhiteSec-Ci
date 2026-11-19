import hashlib
import jwt


def check(token, key, provided_token, expected, password, user):
    # ruleid: team.authentication-weakness
    claims = jwt.decode(token, key, options={"verify_signature": False})
    # ruleid: team.auth-secret-equality
    if provided_token == expected:
        pass
    # ruleid: team.auth-weak-password-hash
    digest = hashlib.md5(password.encode()).hexdigest()
    return digest


def login(user):
    # ruleid: team.auth-session-fixation
    session["user_id"] = user.id


# retired audit rule assertion retained in tests_disabled/
def verify_token(token):
    return token
