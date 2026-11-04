import sqlite3
import threading
import time


class Database:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA secure_delete=ON")
        except Exception:
            pass
        self._init()

    def _init(self):
        with self.lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS identity (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    name TEXT NOT NULL,
                    group_key_hash TEXT NOT NULL,
                    ed_private_hex TEXT NOT NULL,
                    ed_public_hex TEXT NOT NULL,
                    totp_secret_hex TEXT NOT NULL,
                    tcp_port INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS contacts (
                    name TEXT PRIMARY KEY,
                    ip TEXT,
                    port INTEGER,
                    ed_public_hex TEXT NOT NULL,
                    chat_started INTEGER NOT NULL DEFAULT 0,
                    incoming_request INTEGER NOT NULL DEFAULT 0,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    pending INTEGER NOT NULL DEFAULT 0,
                    clear_pending INTEGER NOT NULL DEFAULT 0,
                    added_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contact_name TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp REAL NOT NULL
                );
                """
            )
            try:
                self.conn.execute(
                    "ALTER TABLE contacts ADD COLUMN pending INTEGER NOT NULL DEFAULT 0"
                )
            except sqlite3.OperationalError:
                pass
            try:
                self.conn.execute(
                    "ALTER TABLE contacts ADD COLUMN clear_pending INTEGER NOT NULL DEFAULT 0"
                )
            except sqlite3.OperationalError:
                pass
            self.conn.commit()

    def get_identity(self):
        with self.lock:
            row = self.conn.execute("SELECT * FROM identity WHERE id = 1").fetchone()
            return dict(row) if row else None

    def create_identity(
        self,
        name,
        group_key_hash,
        ed_private_hex,
        ed_public_hex,
        totp_secret_hex,
        tcp_port,
    ):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO identity "
                "(id, name, group_key_hash, ed_private_hex, ed_public_hex, "
                "totp_secret_hex, tcp_port) VALUES (1, ?, ?, ?, ?, ?, ?)",
                (
                    name,
                    group_key_hash,
                    ed_private_hex,
                    ed_public_hex,
                    totp_secret_hex,
                    tcp_port,
                ),
            )
            self.conn.commit()

    def update_tcp_port(self, port):
        with self.lock:
            self.conn.execute("UPDATE identity SET tcp_port = ? WHERE id = 1", (port,))
            self.conn.commit()

    def get_contacts(self):
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM contacts ORDER BY name"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_contact(self, name):
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM contacts WHERE name = ?", (name,)
            ).fetchone()
            return dict(row) if row else None

    def upsert_contact(self, name, ip, port, ed_public_hex):
        with self.lock:
            existing = self.conn.execute(
                "SELECT name FROM contacts WHERE name = ?", (name,)
            ).fetchone()
            if existing:
                self.conn.execute(
                    "UPDATE contacts SET ip=?, port=?, ed_public_hex=?, added_at=? "
                    "WHERE name=?",
                    (ip, port, ed_public_hex, time.time(), name),
                )
            else:
                self.conn.execute(
                    "INSERT INTO contacts "
                    "(name, ip, port, ed_public_hex, chat_started, "
                    "incoming_request, blocked, added_at) "
                    "VALUES (?, ?, ?, ?, 0, 0, 0, ?)",
                    (name, ip, port, ed_public_hex, time.time()),
                )
            self.conn.commit()

    def set_contact_state(
        self,
        name,
        chat_started=None,
        incoming_request=None,
        blocked=None,
        pending=None,
        clear_pending=None,
        ip=None,
        port=None,
    ):
        with self.lock:
            fields = []
            values = []
            if chat_started is not None:
                fields.append("chat_started=?")
                values.append(int(chat_started))
            if incoming_request is not None:
                fields.append("incoming_request=?")
                values.append(int(incoming_request))
            if blocked is not None:
                fields.append("blocked=?")
                values.append(int(blocked))
            if pending is not None:
                fields.append("pending=?")
                values.append(int(pending))
            if clear_pending is not None:
                fields.append("clear_pending=?")
                values.append(int(clear_pending))
            if ip is not None:
                fields.append("ip=?")
                values.append(ip)
            if port is not None:
                fields.append("port=?")
                values.append(port)
            if not fields:
                return
            values.append(name)
            self.conn.execute(
                f"UPDATE contacts SET {', '.join(fields)} WHERE name=?", values
            )
            self.conn.commit()

    def add_message(self, contact_name, direction, content):
        with self.lock:
            self.conn.execute(
                "INSERT INTO messages (contact_name, direction, content, timestamp) "
                "VALUES (?, ?, ?, ?)",
                (contact_name, direction, content, time.time()),
            )
            self.conn.commit()

    def get_messages(self, contact_name, limit=500):
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM messages WHERE contact_name = ? "
                "ORDER BY id DESC LIMIT ?",
                (contact_name, limit),
            ).fetchall()
            return [dict(r) for r in reversed(rows)]

    def clear_messages(self, contact_name):
        with self.lock:
            self.conn.execute(
                "DELETE FROM messages WHERE contact_name = ?", (contact_name,)
            )
            self.conn.commit()

    def delete_message(self, message_id):
        with self.lock:
            self.conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))
            self.conn.commit()

    def delete_contact(self, contact_name):
        with self.lock:
            self.conn.execute(
                "DELETE FROM contacts WHERE name = ?", (contact_name,)
            )
            self.conn.execute(
                "DELETE FROM messages WHERE contact_name = ?", (contact_name,)
            )
            self.conn.commit()

    def reset_all(self):
        with self.lock:
            self.conn.execute("DELETE FROM messages")
            self.conn.execute("DELETE FROM contacts")
            self.conn.execute("DELETE FROM identity")
            self.conn.commit()
            try:
                self.conn.execute("VACUUM")
            except Exception:
                pass

    def close(self):
        with self.lock:
            try:
                self.conn.close()
            except Exception:
                pass