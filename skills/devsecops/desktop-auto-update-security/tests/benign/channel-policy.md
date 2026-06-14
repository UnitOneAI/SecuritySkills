# Desktop Update Channel Policy

- Stable releases use `https://updates.example.com/stable`.
- Beta releases use `https://updates.example.com/beta`.
- Downgrades are disabled by default.
- Emergency rollback requires a signed release, a time-boxed incident ticket, and approval from release engineering.
- Signing credentials are injected by CI and are not committed to the repository.
