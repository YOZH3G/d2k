"""Independent aioquic HTTP/3 endpoint; test-only, never installed on a router."""
import asyncio
import sys

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated


class Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.http = H3Connection(self._quic)
        if self.http is None:
            return
        for request in self.http.handle_event(event):
            if isinstance(request, HeadersReceived):
                print("HTTP/3 request", request.headers, flush=True)
                self.http.send_headers(request.stream_id, [(b":status", b"200")])
                self.http.send_data(request.stream_id, b"native IPv6 HTTP/3", end_stream=True)
                self.transmit()


async def main():
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(sys.argv[1], sys.argv[2])
    server = await serve("::1", 4444, configuration=config, create_protocol=Server)
    print("HTTP/3 ready on [::1]:4444", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        server.close()


if __name__ == "__main__":
    asyncio.run(main())
