import asyncio
import contextlib
import threading

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from src.alert_store import alert_store
from src.rule_ids import start_sniffing

BROADCAST_SECONDS = 1.0

connected_clients: set[WebSocket] = set()


async def broadcast_loop() -> None:
    last_count = 0
    while True:
        alerts = alert_store.list()
        if len(alerts) != last_count and connected_clients:
            last_count = len(alerts)
            dead = []
            for ws in connected_clients:
                try:
                    await ws.send_json(alerts)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                connected_clients.discard(ws)
        await asyncio.sleep(BROADCAST_SECONDS)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    task = asyncio.create_task(broadcast_loop())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="ids-sentinel", lifespan=lifespan)


@app.get("/alerts")
def get_alerts() -> list[dict]:
    return alert_store.list()


@app.websocket("/alerts/ws")
async def alerts_ws(websocket: WebSocket) -> None:
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        await websocket.send_json(alert_store.list())
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        connected_clients.discard(websocket)
