import sqlite3

from openai import OpenAI

client = OpenAI()
conn = sqlite3.connect("shop.db")


def answer(question: str) -> list:
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": question}],
    )
    sql = reply.choices[0].message.content
    return conn.execute(sql).fetchall()
