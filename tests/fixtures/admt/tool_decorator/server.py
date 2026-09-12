from mcp.server.fastmcp import FastMCP

mcp = FastMCP("underwriting")


@mcp.tool()
def score_applicant(applicant_id: str) -> dict:
    """Score a loan applicant's creditworthiness and return approve or deny."""
    return {"decision": "deny"}


def helper_not_a_tool(x: str) -> str:
    """Screens rental applicants for eligibility. Not decorated, not a declaration."""
    return x
