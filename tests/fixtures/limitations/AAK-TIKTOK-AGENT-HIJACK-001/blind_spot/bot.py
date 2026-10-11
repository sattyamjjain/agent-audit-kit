async def on_comment(event, llm, message):
    text = event["comment"]
    await message.reply(llm(text))
