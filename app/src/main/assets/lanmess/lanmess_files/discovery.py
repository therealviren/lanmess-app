import asyncio
import json
import socket
import time

from .config import (
    DISCOVERY_INTERVAL,
    DISCOVERY_PORT,
    DISCOVERY_TTL,
)


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, on_packet):
        self.on_packet = on_packet

    def datagram_received(self, data, addr):
        try:
            msg = json.loads(data.decode("utf-8"))
        except Exception:
            return
        if not isinstance(msg, dict):
            return
        if msg.get("app") != "lanmess":
            return
        try:
            self.on_packet(addr[0], msg)
        except Exception:
            pass


class Discovery:
    def __init__(self):
        self.peers = {}
        self.transport = None

    async def start(self):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        try:
            sock.bind(("", DISCOVERY_PORT))
        except Exception:
            sock.bind(("", 0))
        sock.setblocking(False)
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(self._on_packet), sock=sock
        )

    def _on_packet(self, ip, msg):
        name = msg.get("name")
        if not isinstance(name, str) or not name:
            return
        tcp_port = msg.get("tcp_port")
        if not isinstance(tcp_port, int) or tcp_port <= 0:
            return
        self.peers[name] = {
            "ip": ip,
            "tcp_port": tcp_port,
            "code_tag": str(msg.get("code_tag", "")),
            "last_seen": time.time(),
        }

    def get_live_peers(self):
        now = time.time()
        return {
            n: i
            for n, i in self.peers.items()
            if now - i["last_seen"] < DISCOVERY_TTL
        }

    def find_by_name(self, name):
        return self.get_live_peers().get(name)

    def find_by_code_tag(self, tag, exclude_name=None):
        for name, info in self.get_live_peers().items():
            if name == exclude_name:
                continue
            if info["code_tag"] == tag:
                return name, info
        return None, None

    async def broadcaster(self, name, tcp_port, get_code_tag):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)
        while True:
            try:
                tag = get_code_tag()
                payload = json.dumps(
                    {
                        "app": "lanmess",
                        "version": 1,
                        "name": name,
                        "tcp_port": tcp_port,
                        "code_tag": tag,
                    }
                ).encode("utf-8")
                sock.sendto(payload, ("255.255.255.255", DISCOVERY_PORT))
                sock.sendto(payload, ("127.0.0.1", DISCOVERY_PORT))
            except Exception:
                pass
            await asyncio.sleep(DISCOVERY_INTERVAL)