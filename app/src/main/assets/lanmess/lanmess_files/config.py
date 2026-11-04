from pathlib import Path

APP_NAME = "LANMess"
APP_VERSION = "1.0.0"
DISCOVERY_PORT = 50505
DISCOVERY_INTERVAL = 2.0
DISCOVERY_TTL = 15.0
TCP_PORT_RANGE = (50510, 50600)
LOGIN_CODE_PERIOD = 60
LOGIN_CODE_DIGITS = 8
PBKDF2_ITERATIONS = 200_000
GROUP_SALT = b"lanmess-group-key-v1"
REQUEST_TIMEOUT = 6.0
BASE_DIR = Path.home() / ".lanmess"
DB_PATH = BASE_DIR / "lanmess.db"


def ensure_dirs():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        BASE_DIR.chmod(0o700)
    except Exception:
        pass