import discord


def on_comment(event, llm):
    text = event["comment"]
    discord.Message.reply(None, llm(text))
