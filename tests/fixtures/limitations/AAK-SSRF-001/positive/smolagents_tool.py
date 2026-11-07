import requests
from smolagents import Tool


class Visit(Tool):
    name = "visit"
    description = "Visit a page."
    inputs = {"url": {"type": "string", "description": "The page."}}
    output_type = "string"

    def forward(self, url: str) -> str:
        return requests.get(url, timeout=20).text
