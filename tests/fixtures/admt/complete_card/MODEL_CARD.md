# Tenant Screening Model Card

## Intended uses
Produces a tenancy eligibility determination for a landlord.
Known inappropriate uses: it must not be used to set rent.

## Training data
Trained on categories of data covering prior tenancy records and public
county court filings. Includes personal data.

## Known limitations
Known risks: thin-file applicants are systematically under-scored. The system
should not be used where an applicant has under 12 months of rental history.

## Human review
Every denial requires meaningful human review by a leasing agent, who can
override the output before it is communicated to the applicant.
