from app import work
from a2a.utils import new_agent_text_message


async def run(queue) -> None:
    try:
        await work()
    except Exception as e:
        await queue.enqueue_event(new_agent_text_message(str(e)))
