# notify.py
from typing import Set, Dict, Any
from fastapi import WebSocket
import json
import asyncio

class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        # prune closed sockets
        dead = []
        for ws in list(self.active_connections):
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)

manager = ConnectionManager()

async def emit(stage: str, tx_id: str, payload: Dict[str, Any] | None = None):
    data = {"type": "tx_event", "stage": stage, "tx_id": tx_id}
    if payload:
        data.update(payload)
    await manager.broadcast(data)
