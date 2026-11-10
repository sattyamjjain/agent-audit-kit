from fastapi import FastAPI
from openai import OpenAI

app = FastAPI()
client = OpenAI()


@app.post("/chat")
def chat(message: str) -> object:
    return client.chat.completions.create(model="gpt-4.1", messages=[{"role": "user", "content": message}])
