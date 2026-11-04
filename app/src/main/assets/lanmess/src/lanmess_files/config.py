from pathlib import Path

APP_NAME = "LANMess"
APP_VERSION = "1.1.1"
DISCOVERY_PORT = 50505
DISCOVERY_INTERVAL = 2.0
DISCOVERY_TTL = 15.0
TCP_PORT_RANGE = (50510, 50600)
LOGIN_CODE_PERIOD = 60
LOGIN_CODE_DIGITS = 8
PBKDF2_ITERATIONS = 600_000
GROUP_SALT = b"lanmess-group-key-v1"
LOOKUP_SALT = b"lanmess-lookup-v1"
REQUEST_TIMEOUT = 6.0
CONTROL_REPLAY_WINDOW = 60.0
MAX_MESSAGE_LEN = 8192
MIN_GROUP_CODE_LEN = 12
MAX_GROUP_CODE_LEN = 256
ADD_RATE_LIMIT_SECONDS = 0.5
MSG_RATE_LIMIT_SECONDS = 0.1
MAX_SERVER_CONNECTIONS = 64
BASE_DIR = Path.home() / ".lanmess"
DB_PATH = BASE_DIR / "lanmess.db"


def ensure_dirs():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        BASE_DIR.chmod(0o700)
    except Exception:
        pass
    if DB_PATH.exists():
        try:
            DB_PATH.chmod(0o600)
        except Exception:
            pass