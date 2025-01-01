import asyncio
from aiohttp_sse_client import client as sse_client
from threading import Thread

async def sse():
    async with sse_client.EventSource(
        'http://127.0.0.1:3000?sess_id=lbownik'
    ) as event_source:
        try:
            async for event in event_source:
                print(event.message, event.data)
        except ConnectionError:
            pass

asyncio.run(sse())