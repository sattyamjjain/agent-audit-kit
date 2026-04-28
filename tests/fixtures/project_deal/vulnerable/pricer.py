"""Vulnerable: pricing function calls Anthropic with templated model
without @parity.check. Commerce context via stripe import.
"""
from __future__ import annotations

import os

import stripe  # commerce hint
from anthropic import Anthropic


client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])


def set_price(item: dict, model: str) -> dict:
    """Cross-tier pricing without parity check."""
    rsp = client.messages.create(
        model=model,
        max_tokens=64,
        messages=[{"role": "user", "content": f"Price this: {item}"}],
    )
    return {"price": float(rsp.content[0].text)}
