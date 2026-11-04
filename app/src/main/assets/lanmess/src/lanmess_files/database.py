import sqlite3
import threading
import time

from .crypto import (
    compute_name_hash,
    decrypt_json,
    derive_lookup_key,
    encrypt_json,
    group_key_hash,
    x25519_generate,
    x25519_private_to_bytes,
    x25519_public_to_bytes,
)


SCHEMA_VERSION = 3


class Database:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(
            self.path, check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA secure_delete=ON")
            self.conn.execute("PRAGMA foreign_keys=ON")
        except Exception:
            pass
        self.key = None
        self.lookup_key = None
        self._init_schema()

    def _init_schema(self):
        with self.lock:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS meta "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self.conn.commit()

            version = self._get_meta("schema_version")
            if version == str(SCHEMA_VERSION):
                self._create_v3_tables()
                return

            cur = self.conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='identity'"
            )
            if not cur.fetchone():
                self._create_v3_tables()
                self._set_meta(
                    "schema_version", str(SCHEMA_VERSION)
                )
                return

            cols = [
                r[1]
                for r in self.conn.execute(
                    "PRAGMA table_info(identity)"
                ).fetchall()
            ]

            if "data_enc" in cols:
                self._set_meta("schema_version", "2")
            else:
                self._set_meta("schema_version", "1")

    def _create_v3_tables(self):
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS meta "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS identity ("
            "id INTEGER PRIMARY KEY CHECK (id = 1),"
            "data_enc TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS contacts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "name_hash TEXT UNIQUE NOT NULL,"
            "data_enc TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS messages ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "contact_id INTEGER NOT NULL,"
            "data_enc TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_contact "
            "ON messages(contact_id, id)"
        )
        self.conn.commit()

    def _get_meta(self, key):
        try:
            row = self.conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else None
        except sqlite3.OperationalError:
            return None

    def _set_meta(self, key, value):
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS meta "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) "
            "VALUES (?, ?)",
            (key, value),
        )
        self.conn.commit()

    def has_identity(self):
        with self.lock:
            try:
                row = self.conn.execute(
                    "SELECT 1 FROM identity WHERE id = 1 LIMIT 1"
                ).fetchone()
                return row is not None
            except sqlite3.OperationalError:
                return False

    def unlock(self, group_key):
        with self.lock:
            version = self._get_meta("schema_version")
            if version in ("1", "2"):
                if not self._migrate_to_v3(
                    group_key, version
                ):
                    return False
                version = str(SCHEMA_VERSION)
            if version != str(SCHEMA_VERSION):
                return False
            if not self._unlock_v3(group_key):
                return False
            return True

    def _unlock_v3(self, group_key):
        row = self.conn.execute(
            "SELECT data_enc FROM identity WHERE id = 1"
        ).fetchone()
        if not row:
            return False
        try:
            data = decrypt_json(
                group_key, row["data_enc"], b"identity"
            )
        except Exception:
            return False
        if "x25519_private_hex" not in data:
            sk = x25519_generate()
            data["x25519_private_hex"] = (
                x25519_private_to_bytes(sk).hex()
            )
            data["x25519_public_hex"] = (
                x25519_public_to_bytes(
                    sk.public_key()
                ).hex()
            )
            enc = encrypt_json(group_key, data, b"identity")
            self.conn.execute(
                "UPDATE identity SET data_enc = ? "
                "WHERE id = 1",
                (enc,),
            )
            self.conn.commit()
        self.key = group_key
        self.lookup_key = derive_lookup_key(group_key)
        return True

    def _migrate_to_v3(self, group_key, from_version):
        try:
            if from_version == "1":
                row = self.conn.execute(
                    "SELECT * FROM identity WHERE id = 1"
                ).fetchone()
                if not row:
                    return False
                row_dict = dict(row)
                expected_hash = row_dict.get(
                    "group_key_hash", ""
                )
                if (
                    group_key_hash(group_key) != expected_hash
                ):
                    return False
                self._migrate_v1_to_v3(group_key)
            else:
                row = self.conn.execute(
                    "SELECT data_enc FROM identity "
                    "WHERE id = 1"
                ).fetchone()
                if not row:
                    return False
                try:
                    decrypt_json(
                        group_key,
                        row["data_enc"],
                        b"identity",
                    )
                except Exception:
                    return False
                self._migrate_v2_to_v3(group_key)
            self._set_meta(
                "schema_version", str(SCHEMA_VERSION)
            )
            return True
        except Exception:
            return False

    def _migrate_v1_to_v3(self, group_key):
        lookup_key = derive_lookup_key(group_key)
        identity_row = dict(
            self.conn.execute(
                "SELECT * FROM identity WHERE id = 1"
            ).fetchone()
        )
        contacts_rows = [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM contacts"
            ).fetchall()
        ]
        messages_rows = [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM messages"
            ).fetchall()
        ]

        with self.conn:
            self.conn.execute(
                "CREATE TABLE identity_v3 ("
                "id INTEGER PRIMARY KEY CHECK (id = 1),"
                "data_enc TEXT NOT NULL)"
            )
            self.conn.execute(
                "CREATE TABLE contacts_v3 ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "name_hash TEXT UNIQUE NOT NULL,"
                "data_enc TEXT NOT NULL)"
            )
            self.conn.execute(
                "CREATE TABLE messages_v3 ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "contact_id INTEGER NOT NULL,"
                "data_enc TEXT NOT NULL)"
            )

            x_sk = x25519_generate()
            identity_data = {
                "name": identity_row["name"],
                "ed_private_hex": identity_row[
                    "ed_private_hex"
                ],
                "ed_public_hex": identity_row[
                    "ed_public_hex"
                ],
                "totp_secret_hex": identity_row[
                    "totp_secret_hex"
                ],
                "tcp_port": int(identity_row["tcp_port"]),
                "x25519_private_hex": (
                    x25519_private_to_bytes(x_sk).hex()
                ),
                "x25519_public_hex": (
                    x25519_public_to_bytes(
                        x_sk.public_key()
                    ).hex()
                ),
            }
            identity_enc = encrypt_json(
                group_key, identity_data, b"identity"
            )
            self.conn.execute(
                "INSERT INTO identity_v3 (id, data_enc) "
                "VALUES (1, ?)",
                (identity_enc,),
            )

            name_to_id = {}
            for c in contacts_rows:
                name = c["name"]
                name_hash = compute_name_hash(
                    lookup_key, name
                )
                contact_data = {
                    "name": name,
                    "ip": c.get("ip"),
                    "port": c.get("port"),
                    "ed_public_hex": c["ed_public_hex"],
                    "x25519_public_hex": "",
                    "chat_started": int(
                        c.get("chat_started", 0)
                    ),
                    "incoming_request": int(
                        c.get("incoming_request", 0)
                    ),
                    "blocked": int(c.get("blocked", 0)),
                    "pending": int(c.get("pending", 0)),
                    "clear_pending": int(
                        c.get("clear_pending", 0)
                    ),
                    "out_counter": 0,
                    "last_counter_in": 0,
                    "added_at": float(
                        c.get("added_at", time.time())
                    ),
                }
                aad = (
                    b"contact:" + name_hash.encode()
                )
                data_enc = encrypt_json(
                    group_key, contact_data, aad
                )
                cur = self.conn.execute(
                    "INSERT INTO contacts_v3 "
                    "(name_hash, data_enc) VALUES (?, ?)",
                    (name_hash, data_enc),
                )
                name_to_id[name] = cur.lastrowid

            for m in messages_rows:
                contact_id = name_to_id.get(
                    m["contact_name"]
                )
                if not contact_id:
                    continue
                msg_data = {
                    "direction": m["direction"],
                    "content": m["content"],
                    "timestamp": float(m["timestamp"]),
                }
                aad = (
                    b"message:" + str(contact_id).encode()
                )
                data_enc = encrypt_json(
                    group_key, msg_data, aad
                )
                self.conn.execute(
                    "INSERT INTO messages_v3 "
                    "(contact_id, data_enc) VALUES (?, ?)",
                    (contact_id, data_enc),
                )

            self.conn.execute("DROP TABLE messages")
            self.conn.execute("DROP TABLE contacts")
            self.conn.execute("DROP TABLE identity")
            self.conn.execute(
                "ALTER TABLE identity_v3 RENAME TO identity"
            )
            self.conn.execute(
                "ALTER TABLE contacts_v3 RENAME TO contacts"
            )
            self.conn.execute(
                "ALTER TABLE messages_v3 RENAME TO messages"
            )
            self.conn.execute(
                "CREATE INDEX idx_messages_contact "
                "ON messages(contact_id, id)"
            )

    def _migrate_v2_to_v3(self, group_key):
        lookup_key = derive_lookup_key(group_key)
        identity_row = self.conn.execute(
            "SELECT data_enc FROM identity WHERE id = 1"
        ).fetchone()
        identity_data = decrypt_json(
            group_key, identity_row["data_enc"], b"identity"
        )
        x_sk = x25519_generate()
        identity_data["x25519_private_hex"] = (
            x25519_private_to_bytes(x_sk).hex()
        )
        identity_data["x25519_public_hex"] = (
            x25519_public_to_bytes(x_sk.public_key()).hex()
        )
        identity_enc = encrypt_json(
            group_key, identity_data, b"identity"
        )

        contact_rows = [
            dict(r)
            for r in self.conn.execute(
                "SELECT id, name_hash, data_enc FROM contacts"
            ).fetchall()
        ]

        with self.conn:
            self.conn.execute(
                "UPDATE identity SET data_enc = ? "
                "WHERE id = 1",
                (identity_enc,),
            )
            for r in contact_rows:
                aad = (
                    b"contact:" + r["name_hash"].encode()
                )
                try:
                    cdata = decrypt_json(
                        group_key, r["data_enc"], aad
                    )
                except Exception:
                    continue
                cdata.setdefault("x25519_public_hex", "")
                cdata.setdefault("out_counter", 0)
                cdata.setdefault("last_counter_in", 0)
                new_enc = encrypt_json(
                    group_key, cdata, aad
                )
                self.conn.execute(
                    "UPDATE contacts SET data_enc = ? "
                    "WHERE id = ?",
                    (new_enc, r["id"]),
                )

    def create_identity(
        self,
        name,
        group_key,
        ed_private_hex,
        ed_public_hex,
        totp_secret_hex,
        tcp_port,
        x25519_private_hex,
        x25519_public_hex,
    ):
        with self.lock:
            if self._get_meta("schema_version") in (
                "1",
                "2",
            ):
                self.reset_all()
            self._set_meta(
                "schema_version", str(SCHEMA_VERSION)
            )
            self.key = group_key
            self.lookup_key = derive_lookup_key(group_key)
            data = {
                "name": name,
                "ed_private_hex": ed_private_hex,
                "ed_public_hex": ed_public_hex,
                "totp_secret_hex": totp_secret_hex,
                "tcp_port": int(tcp_port),
                "x25519_private_hex": x25519_private_hex,
                "x25519_public_hex": x25519_public_hex,
            }
            enc = encrypt_json(group_key, data, b"identity")
            self.conn.execute(
                "INSERT OR REPLACE INTO identity "
                "(id, data_enc) VALUES (1, ?)",
                (enc,),
            )
            self.conn.commit()

    def get_identity(self):
        with self.lock:
            if self.key is None:
                return None
            row = self.conn.execute(
                "SELECT data_enc FROM identity WHERE id = 1"
            ).fetchone()
            if not row:
                return None
            try:
                return decrypt_json(
                    self.key, row["data_enc"], b"identity"
                )
            except Exception:
                return None

    def update_tcp_port(self, port):
        with self.lock:
            if self.key is None:
                return
            row = self.conn.execute(
                "SELECT data_enc FROM identity WHERE id = 1"
            ).fetchone()
            if not row:
                return
            try:
                data = decrypt_json(
                    self.key, row["data_enc"], b"identity"
                )
            except Exception:
                return
            data["tcp_port"] = int(port)
            enc = encrypt_json(self.key, data, b"identity")
            self.conn.execute(
                "UPDATE identity SET data_enc = ? "
                "WHERE id = 1",
                (enc,),
            )
            self.conn.commit()

    def _name_hash(self, name):
        return compute_name_hash(self.lookup_key, name)

    def get_contacts(self):
        with self.lock:
            if self.key is None or self.lookup_key is None:
                return []
            result = []
            for row in self.conn.execute(
                "SELECT id, name_hash, data_enc FROM contacts"
            ):
                try:
                    data = decrypt_json(
                        self.key,
                        row["data_enc"],
                        b"contact:"
                        + row["name_hash"].encode(),
                    )
                    data["_id"] = row["id"]
                    result.append(data)
                except Exception:
                    continue
            result.sort(key=lambda c: c.get("name", ""))
            return result

    def get_contact(self, name):
        with self.lock:
            if (
                not name
                or self.key is None
                or self.lookup_key is None
            ):
                return None
            name_hash = self._name_hash(name)
            row = self.conn.execute(
                "SELECT id, data_enc FROM contacts "
                "WHERE name_hash = ?",
                (name_hash,),
            ).fetchone()
            if not row:
                return None
            try:
                data = decrypt_json(
                    self.key,
                    row["data_enc"],
                    b"contact:" + name_hash.encode(),
                )
                data["_id"] = row["id"]
                return data
            except Exception:
                return None

    def upsert_contact(
        self,
        name,
        ip,
        port,
        ed_public_hex,
        x25519_public_hex=None,
    ):
        with self.lock:
            if (
                not name
                or self.key is None
                or self.lookup_key is None
            ):
                return
            name_hash = self._name_hash(name)
            aad = b"contact:" + name_hash.encode()
            row = self.conn.execute(
                "SELECT id, data_enc FROM contacts "
                "WHERE name_hash = ?",
                (name_hash,),
            ).fetchone()
            if row:
                try:
                    data = decrypt_json(
                        self.key, row["data_enc"], aad
                    )
                except Exception:
                    return
                data["ip"] = ip
                data["port"] = port
                data["ed_public_hex"] = ed_public_hex
                if x25519_public_hex is not None:
                    data["x25519_public_hex"] = (
                        x25519_public_hex
                    )
                data["added_at"] = time.time()
                enc = encrypt_json(self.key, data, aad)
                self.conn.execute(
                    "UPDATE contacts SET data_enc = ? "
                    "WHERE id = ?",
                    (enc, row["id"]),
                )
            else:
                data = {
                    "name": name,
                    "ip": ip,
                    "port": port,
                    "ed_public_hex": ed_public_hex,
                    "x25519_public_hex": (
                        x25519_public_hex or ""
                    ),
                    "chat_started": 0,
                    "incoming_request": 0,
                    "blocked": 0,
                    "pending": 0,
                    "clear_pending": 0,
                    "out_counter": 0,
                    "last_counter_in": 0,
                    "added_at": time.time(),
                }
                enc = encrypt_json(self.key, data, aad)
                self.conn.execute(
                    "INSERT INTO contacts "
                    "(name_hash, data_enc) VALUES (?, ?)",
                    (name_hash, enc),
                )
            self.conn.commit()

    def set_contact_state(self, name, **kwargs):
        with self.lock:
            if (
                not name
                or self.key is None
                or self.lookup_key is None
            ):
                return
            name_hash = self._name_hash(name)
            aad = b"contact:" + name_hash.encode()
            row = self.conn.execute(
                "SELECT id, data_enc FROM contacts "
                "WHERE name_hash = ?",
                (name_hash,),
            ).fetchone()
            if not row:
                return
            try:
                data = decrypt_json(
                    self.key, row["data_enc"], aad
                )
            except Exception:
                return
            int_fields = {
                "chat_started",
                "incoming_request",
                "blocked",
                "pending",
                "clear_pending",
                "out_counter",
                "last_counter_in",
            }
            for k in (
                "chat_started",
                "incoming_request",
                "blocked",
                "pending",
                "clear_pending",
                "out_counter",
                "last_counter_in",
                "ip",
                "port",
                "x25519_public_hex",
            ):
                if k not in kwargs:
                    continue
                v = kwargs[k]
                if v is None:
                    continue
                data[k] = int(v) if k in int_fields else v
            enc = encrypt_json(self.key, data, aad)
            self.conn.execute(
                "UPDATE contacts SET data_enc = ? "
                "WHERE id = ?",
                (enc, row["id"]),
            )
            self.conn.commit()

    def _contact_id(self, name):
        if not name or self.lookup_key is None:
            return None
        name_hash = self._name_hash(name)
        row = self.conn.execute(
            "SELECT id FROM contacts WHERE name_hash = ?",
            (name_hash,),
        ).fetchone()
        return row["id"] if row else None

    def add_message(self, contact_name, direction, content):
        with self.lock:
            if self.key is None:
                return
            contact_id = self._contact_id(contact_name)
            if not contact_id:
                return
            data = {
                "direction": direction,
                "content": content,
                "timestamp": time.time(),
            }
            aad = b"message:" + str(contact_id).encode()
            enc = encrypt_json(self.key, data, aad)
            self.conn.execute(
                "INSERT INTO messages (contact_id, data_enc) "
                "VALUES (?, ?)",
                (contact_id, enc),
            )
            self.conn.commit()

    def get_messages(self, contact_name, limit=500):
        with self.lock:
            if self.key is None or not contact_name:
                return []
            contact_id = self._contact_id(contact_name)
            if not contact_id:
                return []
            aad = b"message:" + str(contact_id).encode()
            results = []
            for r in self.conn.execute(
                "SELECT id, data_enc FROM messages "
                "WHERE contact_id = ? "
                "ORDER BY id DESC LIMIT ?",
                (contact_id, limit),
            ):
                try:
                    data = decrypt_json(
                        self.key, r["data_enc"], aad
                    )
                    data["id"] = r["id"]
                    data["contact_name"] = contact_name
                    results.append(data)
                except Exception:
                    continue
            return list(reversed(results))

    def clear_messages(self, contact_name):
        with self.lock:
            contact_id = self._contact_id(contact_name)
            if not contact_id:
                return
            self.conn.execute(
                "DELETE FROM messages WHERE contact_id = ?",
                (contact_id,),
            )
            self.conn.commit()

    def delete_message(self, message_id):
        with self.lock:
            self.conn.execute(
                "DELETE FROM messages WHERE id = ?",
                (message_id,),
            )
            self.conn.commit()

    def delete_contact(self, contact_name):
        with self.lock:
            contact_id = self._contact_id(contact_name)
            if not contact_id:
                return
            self.conn.execute(
                "DELETE FROM messages WHERE contact_id = ?",
                (contact_id,),
            )
            self.conn.execute(
                "DELETE FROM contacts WHERE id = ?",
                (contact_id,),
            )
            self.conn.commit()

    def reset_all(self):
        with self.lock:
            try:
                self.conn.execute(
                    "DROP TABLE IF EXISTS messages"
                )
                self.conn.execute(
                    "DROP TABLE IF EXISTS contacts"
                )
                self.conn.execute(
                    "DROP TABLE IF EXISTS identity"
                )
                self.conn.execute(
                    "DROP TABLE IF EXISTS meta"
                )
                self.conn.commit()
            except Exception:
                pass
            self._create_v3_tables()
            self._set_meta(
                "schema_version", str(SCHEMA_VERSION)
            )
            self.key = None
            self.lookup_key = None
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