import hashlib
import hmac
import jwt


def check(token, key, provided_token, expected, body):
    # ok: team.authentication-weakness
    claims = jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": True})
    # ok: team.auth-secret-equality
    if hmac.compare_digest(provided_token, expected):
        pass
    # ok: team.auth-secret-equality
    if token == None:
        pass
    # ok: team.auth-secret-equality
    if token_type == "bearer":
        pass
    # ok: team.auth-weak-password-hash
    etag = hashlib.md5(body).hexdigest()
    return etag


def login_safe(user):
    session.clear()
    # ok: team.auth-session-fixation
    session["user_id"] = user.id


# ok: team.audit.auth-code
def render_page(title):
    return title


# ---- v4.2: API so sanh/kiem tra an toan khong bi coi la diem yeu
# ok: team.audit.auth-code
SAME = hmac.compare_digest(b"a", b"b")
