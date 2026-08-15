# Third-party grading

This page records what happened when we went to get AgentAuditKit graded by an
outside benchmark, and it publishes the outcome without editing, including the
part where there is no grade to publish yet.

## The attempt: OASB (OpenA2A Security Benchmark)

- **Attempted:** 2026-08-10
- **Benchmark:** OASB, `https://github.com/opena2a-org/oasb`
- **Repo commit read against:** `45f39f5d7f42a99fb661613d0b678c9c0e333df8` (2026-08-09)
- **Benchmark page:** `https://oasb.ai/benchmark` (reachable, HTTP 200)

OASB is a suite of 222 standardized attack scenarios for runtime AI-agent
security products.

## The returned score: none, and why

There is no returned score, and this is not us declining to publish a bad one.
Two things blocked it:

1. **No submission API.** The endpoint named for programmatic submission,
   `https://api.oa2a.org/api/v1/benchmark/submit`, returns **HTTP 404** (checked
   with GET and OPTIONS on 2026-08-10; the API root is 404 too). OASB's own repo
   documents submission as **manual**: implement its `SecurityProductAdapter`
   interface and run its `npm test` locally. There is no live endpoint to POST a
   repository to.

2. **OASB withdrew its comparative metrics on 2026-08-09.** Per the repo, the
   benchmark's comparative scoring was pulled because of a labelling flaw:

   > "The benign class of this corpus was labeled by the scanner under test, so
   > F1, precision, FPR and flag rate were determined by the labeling rule rather
   > than measured."

   So even a completed local run would produce a number the benchmark itself says
   is not measured. There is no comparable grade to obtain right now.

We could have implemented the adapter and printed a self-graded number anyway. We
did not, because a number whose benign class the tool under test labelled for
itself measures the labelling rule, not the tool. Publishing it as a "grade" would
be the opposite of the point.

## What this number cannot tell you

Even when a benchmark like OASB does return a comparative number, here is what it
would not settle:

- **The benign-labelling problem, named.** When the benign class is labelled by
  the scanner under test (OASB's own withdrawal reason above), precision, FPR, and
  flag rate are artifacts of that scanner's labelling rule, not independent
  measurements. A tool that flags less looks "more precise" for free. This is why
  a single headline grade across tools is not apples-to-apples.
- **Scanners disagree heavily on what is even malicious.** A repository-aware
  study of the agent-skill ecosystem (Holzbauer, Schmidt, Gegenhuber,
  Schrittwieser, Ullrich, "Context Matters," arXiv:2603.16572) found that
  marketplace scanner reports classify **up to 46.8% of skills as malicious** —
  wildly over-flagging relative to context-aware ground truth. (A frequently
  quoted figure of ~0.12% agreement across seven scanners is *not* reproduced
  here: we could not verify it from the paper's abstract, so we do not cite the
  number, only the direction it points — inter-scanner agreement is low.)

The honest reading: a comparative security-scanner grade is only as trustworthy as
its labelling, and the field's labelling is not yet trustworthy enough to reduce a
tool to one number.

## The two numbers we do stand behind

Both are self-benchmarks, reproducible from this repo, offline, no LLM in the path:

- **Determinism.** [`benchmarks/determinism/RESULTS.md`](../../benchmarks/determinism/RESULTS.md):
  20/20 runs collapse to **one** finding-set digest, 0% variance — shared SHA-256
  `189055d0853a2fa67061541e0f79ca2156435e3d797b0c872aee692cd8827600`. An LLM-judge
  scanner cannot promise a byte-identical re-run; AAK can, and the digest is in the
  tree for anyone to reproduce.
- **Benign-slice HIGH/CRITICAL false-positive rate.**
  [`benchmarks/false_positive/RESULTS.md`](../../benchmarks/false_positive/RESULTS.md):
  on a pre-registered 368-config benign slice, **0 / 1 = 0.0%**, Wilson 95% CI
  **[0.0%, 79.3%]**. The interval is wide because n is 1, and we state that plainly
  rather than smooth it over; the earlier run that scored 50% (n = 4) is published
  too, with the offending rule filed as [#475](https://github.com/sattyamjjain/agent-audit-kit/issues/475).
  Single rater, no inter-rater agreement — also stated.

These are narrow, honest, and ours to defend. They are not a substitute for an
independent grade; they are what we can prove today while the independent grade is
not yet measurable.

## When this changes

If OASB (or another benchmark) exposes a live submission path and a benign class
that is independently labelled rather than self-labelled, we will submit and
publish the returned score here, unedited, whatever it is.
