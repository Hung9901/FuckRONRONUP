import uvicorn
from app.core.event_loop import install

if __name__ == "__main__":
    activated = install()
    loop = "uvloop" if activated else "asyncio"
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        loop=loop,
    )
