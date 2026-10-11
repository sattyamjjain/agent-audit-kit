from flask import Blueprint

bp = Blueprint("mcp", __name__)


@bp.route("/mcp", methods=["POST"])
def mcp_endpoint():
    return {"ok": True}
