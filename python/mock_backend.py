"""Stand-in for your teammates' backend, so the pipeline works end to end today.

  uvicorn mock_backend:app --port 8000
  python bridge.py --port COM5 --url http://localhost:8000/ingest

Open http://localhost:8000/latest in a browser to see what arrived.
"""
from collections import deque

from fastapi import FastAPI, Request

app = FastAPI()
received = deque(maxlen=200)


@app.post("/ingest")
async def ingest(request: Request):
    msg = await request.json()
    received.append(msg)
    print(f"{msg.get('timestamp')} {msg.get('rover_id')} {msg.get('checkpoint')} "
          f"label={msg.get('label')} motion={msg.get('motion_score')}")
    return {"ok": True, "count": len(received)}


@app.get("/latest")
def latest(n: int = 20):
    return list(received)[-n:]
