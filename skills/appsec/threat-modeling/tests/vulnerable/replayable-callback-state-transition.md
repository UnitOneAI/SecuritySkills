# Vulnerable fixture: replayable callback applies privileged state

This design should produce a High sequence-state finding.

## Flow

1. A user starts an admin invitation acceptance flow.
2. The application emails a link containing `invite_id=12345`.
3. The callback handler checks that the invite exists, but it does not bind the invite to:
   - the recipient account
   - the tenant
   - a nonce
   - a one-time token
   - an expiry timestamp
4. The callback immediately grants the `admin` role.
5. The invite remains valid after use so the same URL can be replayed from another browser.
6. If the invite creator loses admin rights before the callback is replayed, the callback still grants the role because authorization was checked only when the invite was created.

## Expected skill behavior

The skill should flag the transition from `invite pending` to `admin granted` because the final state can be reached through replay, stale authorization, and cross-account rebinding.
