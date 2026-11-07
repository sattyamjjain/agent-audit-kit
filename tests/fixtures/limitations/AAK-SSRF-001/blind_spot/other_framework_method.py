import requests
from llama_index.core.tools import BaseTool


class Visit(BaseTool):
    def call(self, url: str) -> str:
        return requests.get(url, timeout=20).text
