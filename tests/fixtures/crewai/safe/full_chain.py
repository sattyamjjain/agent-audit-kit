"""Safe: same four CrewAI shapes but every tool is gated by an
agent_audit_kit.sanitizers.crewai guard."""
from __future__ import annotations

import docker  # type: ignore[import-not-found]
from crewai import Agent, Crew, Task  # type: ignore[import-not-found]
from crewai_tools import (  # type: ignore[import-not-found]
    CodeInterpreterTool,
    JSONSearchTool,
    RagTool,
)

from agent_audit_kit.sanitizers.crewai import (
    assert_codeinterp_safe_mode,
    require_docker_liveness,
    validate_jsonloader_path,
    validate_rag_url,
)


PROJECT_ROOT = "/srv/agent/templates"
DOCS_ALLOWLIST = ["docs.example.com", "internal.docs.example.com"]


def build_pipeline(request) -> Crew:
    user_input = request.json()
    assert_codeinterp_safe_mode(False)
    require_docker_liveness(docker.from_env())
    code_tool = CodeInterpreterTool(unsafe_mode=False, docker_required=True)
    json_tool = JSONSearchTool(
        file_path=str(validate_jsonloader_path(
            user_input["template_path"], root=PROJECT_ROOT
        ))
    )
    rag_tool = RagTool(
        url=validate_rag_url(user_input["docs_url"], allowlist=DOCS_ALLOWLIST)
    )
    agent = Agent(role="researcher", tools=[code_tool, json_tool, rag_tool])
    task = Task(description="research", agent=agent, inputs=user_input)
    return Crew(agents=[agent], tasks=[task])
