from langchain_community.utilities import SQLDatabase
from openai import OpenAI

client = OpenAI()
db = SQLDatabase.from_uri("sqlite:///shop.db")


def answer(question: str) -> str:
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": question}],
    )
    sql = reply.choices[0].message.content
    return db.run(sql)
