import asyncio
import json

from .config import REQUEST_TIMEOUT


async def send_request(ip, port, payload, timeout=REQUEST_TIMEOUT):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except Exception:
        return None
    try:
        writer.write((json.dumps(payload) + "\n").encode("utf-8"))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line:
            return None
        try:
            return json.loads(line.decode("utf-8"))
        except Exception:
            return None
    except Exception:
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


class Server:
    def __init__(self, port, handler):
        self.port = port
        self.handler = handler
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(
            self._client, "0.0.0.0", self.port
        )

    async def _client(self, reader, writer):
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not line:
                return
            try:
                msg = json.loads(line.decode("utf-8"))
            except Exception:
                return
            peer = writer.get_extra_info("peername")
            if peer:
                msg["_peer_ip"] = peer[0]
            resp = await self.handler(msg)
            if resp is not None:
                writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def stop(self):
        if self.server is not None:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass