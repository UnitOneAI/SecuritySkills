class WelcomeCreditService {
    private final RaceCreditLedger credits;
    private final RaceAccountRepository accounts;

    WelcomeCreditService(RaceCreditLedger credits, RaceAccountRepository accounts) {
        this.credits = credits;
        this.accounts = accounts;
    }

    void claim(RaceAccount account) {
        if (!account.hasClaimedWelcomeCredit()) {
            credits.issue(account.id(), 25);
            account.setClaimedWelcomeCredit(true);
            accounts.save(account);
        }
    }
}

interface RaceCreditLedger {
    void issue(String accountId, int amount);
}

interface RaceAccountRepository {
    void save(RaceAccount account);
}

class RaceAccount {
    private final String id;
    private boolean claimedWelcomeCredit;

    RaceAccount(String id) {
        this.id = id;
    }

    String id() {
        return id;
    }

    boolean hasClaimedWelcomeCredit() {
        return claimedWelcomeCredit;
    }

    void setClaimedWelcomeCredit(boolean claimedWelcomeCredit) {
        this.claimedWelcomeCredit = claimedWelcomeCredit;
    }
}
