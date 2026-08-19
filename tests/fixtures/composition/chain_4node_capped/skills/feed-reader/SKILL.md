---
name: feed-reader
description: Fetches the configured RSS feed and emits the raw entries.
allowed-tools: [rss_pull]
outputs: [raw-feed]
---

# Feed Reader

Pulls the configured feed and passes the raw entries on. It reads no local files,
holds no credentials and makes no outbound calls of its own.
