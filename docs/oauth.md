# OAuth2/OIDC SSO Flow

## Overview

FOKS implements OAuth2 Authorization Code flow with PKCE and OIDC ID token validation.
The flow spans three participants: the **client** (CLI agent), the **FOKS server**, and the
**Identity Provider (IdP)** (e.g., Google, Okta).

## Flow Diagram

```
Client (CLI)                    FOKS Server                        IdP (Google, Okta, etc.)
    |                               |                                   |
    |  1. PrepOAuth2Session()       |                                   |
    |  - generate nonce binding     |                                   |
    |  - generate PKCE verifier     |                                   |
    |  - generate session ID        |                                   |
    |                               |                                   |
    |  2. InitOAuth2Session(id,     |                                   |
    |     nonce, pkce_verifier)     |                                   |
    |------------------------------>|                                   |
    |                               |  3. Store session in DB           |
    |                               |     (nonce, pkce_verifier,        |
    |                               |      config_id)                   |
    |                               |                                   |
    |                    tiny URI   |                                   |
    |<------------------------------|                                   |
    |                               |                                   |
    |  4. Open browser to           |                                   |
    |     tiny URI                  |                                   |
    |--------------.                |                                   |
    |              |                |                                   |
    |              v                |                                   |
    |           Browser ----------->|                                   |
    |                               |  5. Fetch OIDC discovery doc      |
    |                               |-----------------------------.     |
    |                               |                             |     |
    |                               |                             v     |
    |                               |  6. GET /.well-known/openid-configuration
    |                               |-------------------------------------->|
    |                               |     {authorization_endpoint,          |
    |                               |      token_endpoint,                  |
    |                               |      jwks_uri,                        |
    |                               |      scopes_supported, ...}           |
    |                               |<--------------------------------------|
    |                               |                                   |
    |                               |  7. Build auth URI:               |
    |                               |     ?client_id=...                |
    |                               |     &redirect_uri=...             |
    |                               |     &scope=openid email profile   |
    |                               |     &code_challenge=SHA256(verifier)
    |                               |     &nonce=HASH(binding)          |
    |                               |     &state=session_id             |
    |                               |                                   |
    |           Browser <-- 302 ----|                                   |
    |              |                                                    |
    |              |  8. User authenticates                             |
    |              |----------------------------------------------->   |
    |              |                                                |   |
    |              |                                    Login page  |   |
    |              |                                    Consent     |   |
    |              |                                                |   |
    |              |  9. Redirect to callback                       |   |
    |              |     ?code=AUTH_CODE&state=session_id            |   |
    |              |<----------------------------------------------|   |
    |              |                |                                   |
    |           Browser ----------->|                                   |
    |                               |                                   |
    |                               |  10. Exchange code for tokens     |
    |                               |  POST token_endpoint              |
    |                               |    grant_type=authorization_code  |
    |                               |    code=AUTH_CODE                  |
    |                               |    client_id=...                   |
    |                               |    client_secret=... (if set)      |
    |                               |    code_verifier=PKCE_VERIFIER     |
    |                               |-------------------------------------->|
    |                               |                                       |
    |                               |     {access_token, id_token,          |
    |                               |      refresh_token, expires_in}       |
    |                               |<--------------------------------------|
    |                               |                                   |
    |                               |  11. Validate ID token (JWT)      |
    |                               |  - Fetch JWKS from jwks_uri       |
    |                               |  - Verify RS256 signature         |
    |                               |  - Check aud == client_id         |
    |                               |  - Check nonce matches            |
    |                               |  - Extract: email, username,      |
    |                               |    issuer, subject                |
    |                               |                                   |
    |                               |  12. Store tokens in DB           |
    |                               |                                   |
    |                               |  13. Enqueue token set to         |
    |                               |      OAuth2 queue (wake poller)   |
    |                               |                                   |
    |  14. PollOAuth2Session        |                                   |
    |      Completion()             |                                   |
    |------------------------------>|                                   |
    |                               |  15. Dequeue tokens               |
    |                               |      Reserve username (if signup) |
    |   tokens + username           |                                   |
    |   reservation                 |                                   |
    |<------------------------------|                                   |
    |                               |                                   |
    |  16. Validate ID token        |                                   |
    |      (client-side check)      |                                   |
    |  - Verify signature via JWKS  |                                   |
    |  - Check nonce matches        |                                   |
    |    binding from step 1        |                                   |
    |                               |                                   |
    |  17. Sign OAuth2 binding      |                                   |
    |      with device key          |                                   |
    |                               |                                   |
    |  18. Signup(eldest_link,      |                                   |
    |      sso_binding, username    |                                   |
    |      reservation, ...)        |                                   |
    |------------------------------>|                                   |
    |                               |  19. Verify binding, create user  |
    |          success              |                                   |
    |<------------------------------|                                   |
```

## Security Mechanisms

### PKCE (Proof Key for Code Exchange)

Prevents authorization code interception.

1. Client generates a random 20-byte **verifier**, base64url-encoded
2. Client sends `SHA256(verifier)` as `code_challenge` in the auth request
3. Server sends the original **verifier** in the token exchange POST
4. IdP verifies that `SHA256(verifier) == code_challenge`

PKCE is always used, regardless of whether a `client_secret` is configured.

### Nonce Binding

Binds the ID token to this specific FOKS session, preventing token replay/substitution.

1. Client creates a **binding**: `{FQUser, TreeRoot, Rand[16]}`
2. Hashes the binding to produce a **nonce**
3. Nonce is sent in the auth request; the IdP embeds it in the ID token
4. Both client and server verify the nonce in the returned ID token matches

### Device Key Signature

During signup, the client signs the `{IDToken, Binding}` tuple with its device key.
This cryptographically proves that the device that initiated the OAuth2 flow is the same
one completing signup.

## IdP Compatibility

Different IdPs have different behaviors:

| Feature              | Standard OIDC           | Google                     |
|----------------------|-------------------------|----------------------------|
| Refresh tokens       | `offline_access` scope  | `access_type=offline` param|
| Access token format  | Often JWT               | Opaque string              |
| Username claim       | `preferred_username`    | Not provided (use email)   |

The code handles these differences by:
- Checking `scopes_supported` from the OIDC discovery document before requesting `offline_access`
- Only validating the **ID token** as a JWT (access tokens may be opaque)
- Falling back to the email local part when `preferred_username` is absent

## Key Files

| File | Role |
|------|------|
| `lib/sso/oauth2.go` | OIDC discovery, ID token validation, PKCE, nonce hashing |
| `server/shared/oauth2.go` | Server-side session management, token exchange, DB storage |
| `server/shared/queue.go` | Queue-based async signaling (OAuth2Poke/OAuth2Wait) |
| `server/engine/reg.go` | Registration RPCs (InitOAuth2Session, PollOAuth2SessionCompletion) |
| `client/agent/signup.go` | Client-side flow orchestration |
