from fastapi import FastAPI
from openai import OpenAI

app = FastAPI()
client = OpenAI()


def _ask(message: str) -> object:
    return client.chat.completions.create(model="gpt-4.1", messages=[{"role": "user", "content": message}])


@app.post("/chat")
def chat(message: str) -> object:
    return _ask(message)


@app.post("/responses")
def responses(message: str) -> object:
    return client.responses.create(model="gpt-4.1", input=message)


def a_script_with_no_route(message: str) -> object:
    return client.chat.completions.create(model="gpt-4.1", messages=[{"role": "user", "content": message}])
