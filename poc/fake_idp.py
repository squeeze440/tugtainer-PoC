"""
Minimal fake OIDC provider used ONLY to prove that tugtainer's backend
(backend/modules/auth/providers/auth_oidc_provider.py::_exchange_oidc_code)
accepts an id_token's claims via jwt.get_unverified_claims() WITHOUT any
signature verification.

Serves:
  GET  /.well-known/openid-configuration
  POST /token   -> returns an id_token signed with a throwaway/garbage key
                   (i.e. NOT the key tugtainer would ever be configured to trust)
"""
import base64
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST_PORT = 9999


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forged_id_token(sub: str = "attacker@evil.example", extra_claims: dict | None = None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": "http://tugtainer-audit-idp:9999",
        "sub": sub,
        "email": sub,
        "aud": "totally-wrong-client-id-not-tugtainers",  # wrong audience - should be rejected if aud were checked
        "exp": now - 3600,  # ALREADY EXPIRED - should be rejected if exp were checked
        "iat": now - 7200,
    }
    if extra_claims:
        payload.update(extra_claims)
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
    # Sign with a garbage key the relying party could never know / never configured to trust.
    garbage_sig = b64url(b"THIS_IS_NOT_A_VALID_SIGNATURE_JUST_RANDOM_BYTES_000000")
    return f"{signing_input}.{garbage_sig}"


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            self._json({
                "issuer": "http://tugtainer-audit-idp:9999",
                "authorization_endpoint": "http://tugtainer-audit-idp:9999/authorize",
                "token_endpoint": "http://tugtainer-audit-idp:9999/token",
                "userinfo_endpoint": "http://tugtainer-audit-idp:9999/userinfo",
                "jwks_uri": "http://tugtainer-audit-idp:9999/jwks",
            })
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/token":
            token = forged_id_token()
            print(f"[fake-idp] issuing FORGED id_token (bad sig, wrong aud, expired):\n{token}\n", flush=True)
            self._json({
                "access_token": "fake-access-token-not-real",
                "token_type": "Bearer",
                "id_token": token,
            })
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, fmt, *args):
        print("[fake-idp] " + (fmt % args), flush=True)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", HOST_PORT), Handler)
    print(f"[fake-idp] listening on :{HOST_PORT}", flush=True)
    server.serve_forever()
