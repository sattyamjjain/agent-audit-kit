from mcp.server.fastmcp import FastMCP

mcp = FastMCP("lending")


@mcp.tool()
def score_loan_application(applicant_id: str) -> float:
    """Score a loan applicant's creditworthiness."""
    return 0.5 + len(applicant_id) * 0.0
