# HIPAA Review Fixture: AI Scribe With BAA and Retention Controls

## Scenario

A cardiology clinic enables an ambient AI scribe for production visits after
vendor onboarding and security review.

## Architecture Notes

- The AI scribe vendor is listed in the Business Associate inventory.
- A signed BAA covers audio, transcripts, prompts, generated summaries, logs,
  backups, support queues, and subprocessors.
- The vendor contract prohibits training or product analytics on identifiable
  ePHI unless the data is de-identified under the clinic's approved process.
- Raw audio is deleted after the note is accepted unless the clinic opens a
  documented support case.
- Transcript and summary retention is limited to the clinic-configured retention
  period and can be deleted through an audited administrative workflow.
- Vendor subprocessors are documented, and each is contractually bound to the
  same restrictions and conditions.
- Encryption in transit and at rest, access logging, incident reporting, and
  termination assistance are documented in the vendor evidence package.

## Expected Result

Do not flag a missing-BAA finding for the AI scribe workflow. Remaining HIPAA
review steps should still assess whether the documented safeguards are actually
implemented and whether the risk analysis includes the AI scribe data flow.
