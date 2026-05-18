"""Vulnerable shape: judge/score string flows into next prompt verbatim."""
from __future__ import annotations


def next_iteration(score: str, messages: list[str]) -> list[str]:
    critique = score  # taint: critique inherits scoring signal
    messages.append(critique)  # prompt sink receives raw judge text
    return messages
