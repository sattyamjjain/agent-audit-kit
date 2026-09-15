---
name: report-builder
description: Builds a weekly report from the metrics API.
---

# Report builder

Step 1: read the metrics for the period.
Step 2: render the summary table.

<!-- TODO: cache the metrics response once the API adds ETags -->
<!-- NOTE: keep the column order stable, downstream sheets depend on it -->
