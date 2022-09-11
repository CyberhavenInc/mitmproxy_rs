from typing import Awaitable, Callable, Optional

class Server:
    def getsockname(self) -> tuple[str, int]: ...
    def send_datagram(self, data: bytes, src_addr: tuple[str, int], dst_addr: tuple[str, int]) -> None: ...
    def close(self) -> None: ...
    async def wait_closed(self) -> None: ...

class Configuration:
    @staticmethod
    def generate(listen_port: int = 51820, peers: int = 1) -> Configuration: ...
    def to_json(self) -> str: ...
    def pretty_print(self, address: list[str], allowed_ips: list[str], endpoint: tuple[str, int]) -> list[str]: ...
    @staticmethod
    def from_json(string: str) -> Configuration: ...
    @staticmethod
    def custom(server_listen_port: int, server_private_key: str, client_private_keys: list[str]) -> Configuration: ...

class TcpStream:
    async def read(self, n: int) -> bytes: ...
    def write(self, data: bytes): ...
    async def drain(self) -> None: ...
    def write_eof(self): ...
    def close(self): ...
    def get_extra_info(self, name: str) -> tuple[str, int]: ...
    def __repr__(self) -> str: ...

async def start_server(
    host: str,
    cfg: Configuration,
    handle_connection: Callable[[TcpStream], Awaitable[None]],
    receive_datagram: Callable[[bytes, tuple[str, int], tuple[str, int]], None],
) -> Server: ...
