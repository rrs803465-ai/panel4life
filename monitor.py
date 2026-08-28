import threading, time, sqlite3
from vps import handle_high_cpu

DB = "panel.db"

CPU_THRESHOLD = 90.0


def watch():
    while True:
        try:
            con = sqlite3.connect(DB)
            c = con.cursor()
            c.execute("SELECT container_id FROM vps WHERE status='running'")
            for (cid,) in c.fetchall():
                if not cid:
                    continue

                result = handle_high_cpu(cid, threshold=CPU_THRESHOLD)

                if result["action"] == "suspended":
                    c.execute("UPDATE vps SET status='suspended' WHERE container_id=?", (cid,))
                    con.commit()
                    print(f"[MONITOR] SUSPENDED {cid[:12]} — CPU {result['cpu_percent']}% — "
                          f"verified mining activation: {result['reasons']}")
                elif result["action"] == "flagged_for_review":
                    # Multiple weak signals but no verified activation command —
                    # do NOT touch the container, just log for a human to check.
                    print(f"[MONITOR] FLAGGED (not suspended) {cid[:12]} — CPU {result['cpu_percent']}% — "
                          f"weak signals: {result['reasons']}")
                elif result["action"] == "none" and result["cpu_percent"] >= CPU_THRESHOLD:
                    print(f"[MONITOR] {cid[:12]} at {result['cpu_percent']}% CPU — "
                          f"no mining evidence, left running")

            con.close()
        except Exception as e:
            print(f"[MONITOR] err: {e}")
        time.sleep(15)


def start_monitor():
    t = threading.Thread(target=watch, daemon=True)
    t.start()
