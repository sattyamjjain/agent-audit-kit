# `--llm-scan` per-model eval: results

No run yet. The eval needs an Anthropic API key with credit, and none has been
spent on it so far, so nothing on this page is a measurement and no page in
this repository states how well `--llm-scan` detects anything.

When it runs, this page will hold, per model: recall on MCPTox's poisoned tools
and the flag rate on its clean ones with Wilson 95% intervals, the refusal and
cut-off counts, and the flip rate across three runs. Every number will be
recomputed by `score.py` from the receipts committed beside it. The method is
in [README.md](README.md).
