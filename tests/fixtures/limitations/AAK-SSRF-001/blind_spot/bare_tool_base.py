import requests
from other_framework import Tool


class Visit(Tool):
    name = "visit"
    output_type = "string"

    def forward(self, url: str) -> str:
        return requests.get(url, timeout=20).text
