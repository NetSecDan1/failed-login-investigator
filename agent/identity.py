"""Caller identity for the agent runtime.

The runtime's inbound authorizer should already have validated the bearer token. This module verifies it
again inside the application (signature, issuer, audience, expiry), so the scope decision never depends on
a single control at the edge. Identity is never taken from the prompt or from anything the model produces.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import scope  # noqa: E402

ALGORITHMS = ["RS256"]


def _bearer(headers):
    for name, value in (headers or {}).items():
        if name.lower() == "authorization" and isinstance(value, str) and value[:7].lower() == "bearer ":
            return value[7:].strip()
    return None


def verified_claims(headers, payload=None, key_resolver=None):
    """Return verified token claims, or raise scope.Denied('unauthenticated').

    JWT_ISSUER, JWT_AUDIENCE and JWT_JWKS_URL configure verification. With no issuer configured, test claims
    in the payload are accepted only when ALLOW_TEST_CLAIMS=true, which is for local development.
    """
    issuer = os.environ.get("JWT_ISSUER", "")
    if not issuer:
        if os.environ.get("ALLOW_TEST_CLAIMS", "false").lower() == "true" and isinstance((payload or {}).get("claims"), dict):
            return payload["claims"]
        raise scope.Denied("unauthenticated", "No verified caller identity.")
    token = _bearer(headers)
    if not token:
        raise scope.Denied("unauthenticated", "No verified caller identity.")
    try:
        import jwt
        if key_resolver is None:
            key = jwt.PyJWKClient(os.environ["JWT_JWKS_URL"]).get_signing_key_from_jwt(token).key
        else:
            key = key_resolver(token)
        return jwt.decode(token, key, algorithms=ALGORITHMS, issuer=issuer, audience=os.environ["JWT_AUDIENCE"],
                          options={"require": ["exp", "iss", "aud"]})
    except scope.Denied:
        raise
    except Exception:
        # Do not tell the caller why. The reason is the same to them either way.
        raise scope.Denied("unauthenticated", "No verified caller identity.") from None
