"""Vulnerable shape: refusal text is returned and re-fed into next prompt."""
from __future__ import annotations


def handle_refusal(refusal: str) -> str:
    # Returns the verbatim refusal — caller will inject it into next prompt.
    return refusal


def next_round(prev_refusal: str, messages: list[str]) -> list[str]:
    refusal = prev_refusal
    messages.append(refusal)  # prompt sink — refusal flows verbatim
    return messages
