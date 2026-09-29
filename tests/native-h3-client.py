"""Independent HTTP/3 client for the native IPv6 lab; never installed."""
import asyncio
import sys

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.complete = asyncio.get_running_loop().create_future()
        self.body = bytearray()
        self.status = None
        self.stream = None

    def quic_event_received(self, event):
        for response in self.http.handle_event(event):
            if not isinstance(response, (HeadersReceived, DataReceived)):
                continue
            if response.stream_id != self.stream:
                continue
            if isinstance(response, HeadersReceived):
                self.status = dict(response.headers).get(b":status")
            else:
                self.body.extend(response.data)
            if response.stream_ended and not self.complete.done():
                self.complete.set_result((self.status, bytes(self.body)))

    async def request(self, name):
        self.stream = self._quic.get_next_available_stream_id()
        self.http.send_headers(self.stream, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", name.encode("ascii")), (b":path", b"/"),
        ], end_stream=True)
        self.transmit()
        return await self.complete


async def main():
    ip, port, name, ca = sys.argv[1:]
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    config.server_name = name
    config.load_verify_locations(cafile=ca)
    async with connect(ip, int(port), configuration=config, create_protocol=Client) as client:
        status, body = await client.request(name)
        if status != b"200" or body != b"native IPv6 HTTP/3":
            raise RuntimeError(f"unexpected HTTP/3 response: {status!r}, {body!r}")
        print("native IPv6 HTTP/3", flush=True)


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), 5))
