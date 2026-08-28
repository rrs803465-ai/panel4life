import sqlite3, getpass, time
from werkzeug.security import generate_password_hash

DB = "panel.db"


def init():
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        signup_ip TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        recovery_code_hash TEXT,
        recovery_code_shown INTEGER DEFAULT 0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vps(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        container_id TEXT NOT NULL,
        ssh_command TEXT,
        status TEXT DEFAULT 'creating',
        creator_ip TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_regen INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id))""")
    con.commit()

    c.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    if c.fetchone()[0] == 0:
        print("=== First-run admin setup ===")
        u = input("Admin username: ").strip()
        p = getpass.getpass("Admin password: ")
        c.execute("""INSERT INTO users(username,password,signup_ip,is_admin,created_at)
                     VALUES(?,?,?,1,?)""",
                  (u, generate_password_hash(p), "127.0.0.1", int(time.time())))
        con.commit()
        print(f"Admin '{u}' created — ready to log in.")
        print("Note: like any account, on first LOGIN (not here) you'll be shown")
        print("a one-time recovery code by the panel itself — save it then.")
    else:
        print("Admin already exists — nothing to do.")
    con.close()


if __name__ == "__main__":
    init()
