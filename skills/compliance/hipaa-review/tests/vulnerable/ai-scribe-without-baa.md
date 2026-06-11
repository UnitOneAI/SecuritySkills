# HIPAA Review Fixture: AI Scribe Without BAA Coverage

## Scenario

A cardiology clinic enables an ambient AI scribe for production visits. The
mobile app records physician-patient conversations, sends audio to the vendor,
receives a transcript and visit summary, and stores the final note in the EHR.

## Architecture Notes

- Raw visit audio is uploaded to the AI scribe vendor.
- Transcript text and generated summaries contain patient names, diagnoses,
  medications, and procedure history.
- The vendor retains raw audio for 30 days for quality review.
- The vendor may use transcripts for product improvement unless the customer
  opts out.
- Support staff at the vendor can review failed transcription jobs.
- The clinic's BAA inventory lists the EHR, billing vendor, and cloud hosting
  provider, but does not list the AI scribe vendor.
- No BAA, subprocessor list, retention schedule, deletion process, or incident
  reporting obligation is documented for the AI scribe vendor.

## Expected Finding

Flag a High HIPAA organizational requirement gap. The AI scribe vendor creates,
receives, maintains, or transmits ePHI on behalf of the clinic, but the service
is not in the BAA inventory and lacks written assurances required under
164.308(b)(4) and 164.314(a)(2)(i).
