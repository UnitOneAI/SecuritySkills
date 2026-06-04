class SafeWelcomeCreditService {
    private final SafeCreditLedger credits;
    private final SafeClaimRepository claims;

    SafeWelcomeCreditService(SafeCreditLedger credits, SafeClaimRepository claims) {
        this.credits = credits;
        this.claims = claims;
    }

    void claim(SafeAccount account) {
        boolean inserted = claims.insertUnique(account.id(), "welcome-credit");
        if (!inserted) {
            return;
        }
        credits.issue(account.id(), 25);
    }
}

interface SafeCreditLedger {
    void issue(String accountId, int amount);
}

interface SafeClaimRepository {
    boolean insertUnique(String accountId, String claimType);
}

class SafeAccount {
    private final String id;

    SafeAccount(String id) {
        this.id = id;
    }

    String id() {
        return id;
    }
}
