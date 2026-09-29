import sqlite3
import time

from . import config


def _c():
    c = sqlite3.connect(config.db_path())
    c.row_factory = sqlite3.Row
    c.executescript("""CREATE TABLE IF NOT EXISTS proposals(id INTEGER PRIMARY KEY, ip TEXT, action TEXT, target TEXT,
      confidence REAL, reasoning TEXT, status TEXT, note TEXT);
      CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, pid INTEGER, who TEXT, event TEXT, ts REAL);""")
    return c

def save(ip, p, status, note):
    with _c() as c:
        cur = c.execute("INSERT INTO proposals(ip,action,target,confidence,reasoning,status,note) VALUES(?,?,?,?,?,?,?)",
                        (ip, p.action, p.target, p.confidence, p.reasoning, status, note))
        c.execute("INSERT INTO audit(pid,who,event,ts) VALUES(?,?,?,?)", (cur.lastrowid, "agent", f"proposed:{status}", time.time()))
        return cur.lastrowid

def has_open(ip):
    with _c() as c:
        return c.execute("SELECT 1 FROM proposals WHERE ip=?", (ip,)).fetchone() is not None

def list_(status=None):
    with _c() as c:
        q, a = ("SELECT * FROM proposals WHERE status=?", (status,)) if status else ("SELECT * FROM proposals", ())
        return [dict(r) for r in c.execute(q, a)]

def get(pid):
    with _c() as c:
        r = c.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
        return dict(r) if r else None

def set_status(pid, status, who):
    with _c() as c:
        c.execute("UPDATE proposals SET status=? WHERE id=?", (status, pid))
        c.execute("INSERT INTO audit(pid,who,event,ts) VALUES(?,?,?,?)", (pid, who, status, time.time()))

def audit():
    with _c() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit ORDER BY id")]
