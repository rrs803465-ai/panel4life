"""
Multi-node support: each panel deployment ("node") can be paired with other
nodes so that:
  1. Admins can see/connect nodes from the admin panel using an 8-digit code.
  2. The "same IP can't make a second VPS" rule is enforced ACROSS all
     paired nodes, not just the local one.
  3. A short-lived notification fires (browser Notification + in-page
     banner) when a new node successfully connects.

HONEST LIMITATION: the "notification" here is NOT real push-to-phone
infrastructure (that needs a service worker + Web Push/VAPID + the browser
running the panel in the background). This fires via the browser's
Notification API + an in-page banner, driven by base.html polling
/api/notifications/latest — it only reaches someone while they have a panel
tab open. That's the honest scope of what's buildable safely right now.

PAIRING TRUST MODEL (keep this in mind — it's adequate, not bulletproof):
  - Each node generates one random 8-digit NODE_CODE at process start,
    printed to the console/log and shown in its own admin panel. This code
    is the ONLY thing that authenticates a pairing request — whoever has it
    (i.e. whoever the admin trusted enough to share it with, e.g. over
    Discord) can pair. It's regenerated every restart, which limits how
    long a leaked code stays useful, but it is not cryptographically
    hardened beyond that.
  - After pairing, both sides share a random shared_secret used to
    authenticate the ongoing mesh API calls (check_ip). This is symmetric —
    either side can call the other with it — which is what makes the
    connection "vice versa" without needing separate codes each direction.

AVAILABILITY VS STRICTNESS TRADEOFF (also worth knowing): cross-node IP
checks FAIL OPEN per peer — if a peer node is unreachable/slow, that peer is
just skipped rather than blocking VPS creation network-wide. A strict
fail-closed design would mean one dead node freezes VPS creation on every
other node too, which is a worse outage than occasionally missing an alt
check against an unreachable peer.
"""

import os
import time
import secrets
import requests

# Regenerated every time app.py starts. Give this to another node's admin
# (e.g. over Discord) so they can connect to this node from THEIR admin panel.
NODE_CODE = f"{secrets.randbelow(100_000_000):08d}"

# This node's own externally-reachable base URL (no trailing slash), e.g.
# "https://node1.yourdomain.com". REQUIRED for pairing to work — the node
# you're connecting to needs to call back to you, and there's no reliable
# way to auto-detect your own public URL from inside the process.
NODE_PUBLIC_URL = os.environ.get("NODE_PUBLIC_URL", "").rstrip("/")

_MESH_TIMEOUT = 4  # seconds — short on purpose so one slow peer can't stall a request


def init_mesh_tables(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE NOT NULL,
        shared_secret TEXT NOT NULL,
        label TEXT,
        connected_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    """)
    db.commit()


def add_notification(db, message):
    db.execute("INSERT INTO notifications(message, created_at) VALUES(?,?)",
               (message, int(time.time())))
    db.commit()


def pair_with_node(db, remote_url, remote_code):
    """
    Called from the admin panel on THIS node to connect to another node.
    Returns (ok: bool, message: str).
    """
    remote_url = remote_url.rstrip("/")
    if not NODE_PUBLIC_URL:
        return False, ("This node's own public URL isn't configured — set the NODE_PUBLIC_URL "
                        "environment variable to this node's externally-reachable URL and restart "
                        "before pairing (the other node needs to be able to reach you back).")
    try:
        resp = requests.post(
            f"{remote_url}/api/node/pair",
            json={"code": remote_code, "my_url": NODE_PUBLIC_URL},
            timeout=_MESH_TIMEOUT,
        )
    except Exception as e:
        return False, f"Could not reach {remote_url}: {e}"

    if resp.status_code != 200:
        try:
            err = resp.json().get("error", resp.text[:200])
        except Exception:
            err = resp.text[:200]
        return False, f"Pairing rejected by {remote_url}: {err}"

    data = resp.json()
    shared_secret = data.get("shared_secret")
    if not shared_secret:
        return False, "Remote node didn't return a shared secret — pairing incomplete."

    db.execute(
        "INSERT INTO nodes(url, shared_secret, connected_at) VALUES(?,?,?) "
        "ON CONFLICT(url) DO UPDATE SET shared_secret=excluded.shared_secret, connected_at=excluded.connected_at",
        (remote_url, shared_secret, int(time.time()))
    )
    add_notification(db, f"Node connected! Please refer to Discord for the new node URL. ({remote_url})")
    db.commit()
    return True, f"Connected to {remote_url}."


def accept_pairing(db, submitted_code, requester_url):
    """
    Called by the /api/node/pair route (i.e. this node is the one being
    connected TO). Validates the code the requester supplied against this
    node's own live NODE_CODE. Returns (ok, shared_secret_or_error_message).
    """
    if submitted_code != NODE_CODE:
        return False, "Incorrect node code."
    if not requester_url:
        return False, "Missing requester URL."

    shared_secret = secrets.token_hex(32)
    db.execute(
        "INSERT INTO nodes(url, shared_secret, connected_at) VALUES(?,?,?) "
        "ON CONFLICT(url) DO UPDATE SET shared_secret=excluded.shared_secret, connected_at=excluded.connected_at",
        (requester_url.rstrip("/"), shared_secret, int(time.time()))
    )
    add_notification(db, f"Node connected! Please refer to Discord for the new node URL. ({requester_url.rstrip('/')})")
    db.commit()
    return True, shared_secret


def verify_peer_secret(db, peer_url, secret):
    """Used by internal mesh endpoints to authenticate an incoming request
    as coming from an already-paired node."""
    if not peer_url or not secret:
        return False
    row = db.execute("SELECT shared_secret FROM nodes WHERE url=?", (peer_url.rstrip("/"),)).fetchone()
    return bool(row and row["shared_secret"] == secret)


def list_nodes(db):
    return db.execute("SELECT * FROM nodes ORDER BY connected_at DESC").fetchall()


def check_ip_across_mesh(db, ip):
    """
    Asks every paired node whether the given IP already owns a VPS there.
    Returns (found: bool, node_url_or_None). Fails open per-peer — an
    unreachable node is skipped, not treated as a hit or a hard error.
    """
    for node in list_nodes(db):
        try:
            resp = requests.get(
                f"{node['url']}/api/node/check_ip",
                params={"ip": ip},
                headers={"X-Node-Url": NODE_PUBLIC_URL, "X-Node-Secret": node["shared_secret"]},
                timeout=_MESH_TIMEOUT,
            )
            if resp.status_code == 200 and resp.json().get("has_vps"):
                return True, node["url"]
        except Exception as e:
            print(f"[MESH] check_ip against {node['url']} failed (skipping, fail-open): {e}")
            continue
    return False, None
