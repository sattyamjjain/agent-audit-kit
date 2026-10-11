from flask import Flask

app = Flask(__name__)


@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    return {"ok": True}
