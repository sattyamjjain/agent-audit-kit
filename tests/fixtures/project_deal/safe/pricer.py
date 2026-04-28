"""Safe: same pricing function but decorated with @aak.parity.check."""
from __future__ import annotations

import os

import stripe  # noqa: F401 — commerce hint, drives scope gate
from anthropic import Anthropic

from agent_audit_kit.parity import check as parity_check


client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])


@parity_check(dimensions=["model"], metric="price", max_drift_pct=1.5)
def set_price(item: dict, model: str) -> dict:
    rsp = client.messages.create(
        model=model,
        max_tokens=64,
        messages=[{"role": "user", "content": f"Price this: {item}"}],
    )
    return {"price": float(rsp.content[0].text)}
