"""
Serializes VPS builds so only one is ever being created at a time, with a
fixed pacing delay between builds. This is what fixes the LXD
"context deadline exceeded" crashes — those happen when many people click
Create at once and every request fires its own concurrent LXD API call,
overwhelming LXD's local SQLite backend. Routing every build through one
worker thread eliminates that entirely.

NOTE: the queue itself lives in memory. If the app process restarts, anyone
still waiting in line will need to click Create again — acceptable tradeoff
for a lightweight in-process queue, but worth knowing.
"""

import threading
import time
from collections import deque

SLOT_SECONDS = 15

_lock = threading.Lock()
_queue = deque()  # list of {"user_id":, "vps_id":}


def enqueue(user_id, vps_id):
    with _lock:
        _queue.append({"user_id": user_id, "vps_id": vps_id})


def get_position(vps_id):
    """1-indexed position in line, or 0 if not currently queued (already building/done)."""
    with _lock:
        for i, entry in enumerate(_queue):
            if entry["vps_id"] == vps_id:
                return i + 1
    return 0


def queue_length():
    with _lock:
        return len(_queue)


def peek_all():
    """For the admin panel — snapshot of who's waiting, in order."""
    with _lock:
        return list(_queue)


def _worker(build_fn):
    while True:
        entry = None
        with _lock:
            if _queue:
                entry = _queue.popleft()
        if entry:
            print(f"[QUEUE] Building vps_id={entry['vps_id']} for user_id={entry['user_id']} "
                  f"({queue_length()} still waiting)")
            try:
                build_fn(entry["vps_id"], entry["user_id"])
            except Exception as e:
                print(f"[QUEUE] build_fn raised unexpectedly: {e}")
            time.sleep(SLOT_SECONDS)
        else:
            time.sleep(1)


def start_queue_worker(build_fn):
    """build_fn(vps_id, user_id) — the function that actually builds a VPS and
    writes the result to the DB. Passed in rather than imported to avoid a
    circular import with app.py."""
    t = threading.Thread(target=_worker, args=(build_fn,), daemon=True)
    t.start()
