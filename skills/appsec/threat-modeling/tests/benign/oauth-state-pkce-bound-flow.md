# Benign fixture: OAuth callback bound to state, nonce, and PKCE

This design should not produce a sequence-state finding.

## Flow

1. The application creates a server-side login transaction with:
   - random `state`
   - OIDC nonce
   - PKCE code verifier hash
   - redirect URI
   - tenant id
   - 10 minute expiry
2. The browser is sent to the identity provider with `state`, nonce, and PKCE challenge.
3. The callback handler rejects the request unless:
   - `state` matches an unexpired server-side transaction
   - the authorization code has not been used before
   - the PKCE verifier matches the stored challenge
   - issuer, audience, nonce, subject, and tenant match the transaction
4. The login transaction is deleted before the session is created.
5. The session id is rotated after authentication.

## Expected skill behavior

The skill should record the sequence evidence and classify the flow as controlled because the state transition from callback to authenticated session is single-use, tenant-bound, and fail-closed.
