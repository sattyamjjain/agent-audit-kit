"""Vulnerable: all four CrewAI CVE shapes in one module.

Triggers the meta-rule AAK-CREWAI-CHAIN-2026-04-001 along with each
of CVE-2026-2275, 2285, 2286, 2287.
"""
from __future__ import annotations

from crewai import Agent, Crew, Task  # type: ignore[import-not-found]
from crewai_tools import (  # type: ignore[import-not-found]
    CodeInterpreterTool,
    JSONSearchTool,
    RagTool,
)


def build_pipeline(request) -> Crew:
    user_input = request.json()
    code_tool = CodeInterpreterTool(unsafe_mode=True)  # CVE-2026-2275 + 2287
    json_tool = JSONSearchTool(file_path=user_input["template_path"])  # CVE-2026-2285
    rag_tool = RagTool(url=user_input["docs_url"])  # CVE-2026-2286

    agent = Agent(role="researcher", tools=[code_tool, json_tool, rag_tool])
    task = Task(description="research", agent=agent, inputs=user_input)
    return Crew(agents=[agent], tasks=[task])
