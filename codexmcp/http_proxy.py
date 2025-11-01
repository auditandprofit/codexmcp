"""HTTP Basic Auth proxy for the Codex MCP CLI server."""
from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hmac
import logging
import shlex
import signal
from dataclasses import dataclass
from typing import Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple

from aiohttp import ClientSession, ClientWebSocketResponse, WSMsgType, web

logger = logging.getLogger(__name__)


@dataclass
class ProxyConfig:
    """Runtime configuration for the HTTP proxy."""

    listen_host: str
    listen_port: int
    upstream_http_scheme: str
    upstream_ws_scheme: str
    upstream_host: str
    upstream_port: int
    username: Optional[str]
    password: Optional[str]

    @property
    def upstream_base(self) -> str:
        return f"{self.upstream_http_scheme}://{self.upstream_host}:{self.upstream_port}"

    def websocket_url(self, rel_url: str) -> str:
        return f"{self.upstream_ws_scheme}://{self.upstream_host}:{self.upstream_port}{rel_url}"


class CodexServerProcess:
    """Context manager that launches the Codex CLI MCP server."""

    def __init__(self, command: Sequence[str]) -> None:
        if not command:
            raise ValueError("Codex command must not be empty")
        self._command = list(command)
        self._process: Optional[asyncio.subprocess.Process] = None
        self._stdout_task: Optional[asyncio.Task[None]] = None
        self._stderr_task: Optional[asyncio.Task[None]] = None

    async def __aenter__(self) -> "CodexServerProcess":
        logger.info("Launching Codex MCP server: %s", shlex.join(self._command))
        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert self._process.stdout and self._process.stderr
        loop = asyncio.get_running_loop()
        self._stdout_task = loop.create_task(
            self._log_stream(self._process.stdout, logging.INFO, "stdout")
        )
        self._stderr_task = loop.create_task(
            self._log_stream(self._process.stderr, logging.WARNING, "stderr")
        )
        return self

    async def _log_stream(
        self,
        stream: asyncio.StreamReader,
        level: int,
        name: str,
    ) -> None:
        try:
            while not stream.at_eof():
                line = await stream.readline()
                if not line:
                    break
                logger.log(level, "[codex %s] %s", name, line.decode().rstrip())
        except asyncio.CancelledError:
            pass

    async def __aexit__(self, exc_type, exc, tb) -> None:
        tasks = [t for t in (self._stdout_task, self._stderr_task) if t]
        if self._process and self._process.returncode is None:
            logger.info("Stopping Codex MCP server")
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=10)
            except (asyncio.TimeoutError, ProcessLookupError):
                logger.warning("Codex MCP server did not exit in time; killing it")
                with contextlib.suppress(ProcessLookupError):
                    self._process.kill()
                    await self._process.wait()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def wait(self) -> int:
        if not self._process:
            raise RuntimeError("Process not started")
        return await self._process.wait()


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Launch the Codex MCP CLI server and expose it over HTTP with Basic Auth."
        )
    )
    parser.add_argument(
        "--listen-host",
        default="0.0.0.0",
        help="Host interface for the HTTP proxy (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=8000,
        help="Port for the HTTP proxy (default: 8000)",
    )
    parser.add_argument(
        "--upstream-host",
        default="127.0.0.1",
        help="Host where the Codex server listens (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--upstream-port",
        type=int,
        default=3333,
        help="Port where the Codex server listens (default: 3333)",
    )
    parser.add_argument(
        "--upstream-scheme",
        choices=("http", "https", "ws", "wss"),
        default="http",
        help=(
            "Scheme to use when proxying to Codex. "
            "Use http/https for REST endpoints or ws/wss for pure websocket servers."
        ),
    )
    parser.add_argument(
        "--username",
        help="HTTP Basic Auth username. If omitted, authentication is disabled.",
    )
    parser.add_argument(
        "--password",
        help="HTTP Basic Auth password. Required when --username is provided.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level for the proxy (default: INFO)",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command used to launch the Codex MCP server (e.g. codex mcp server)",
    )
    args = parser.parse_args(argv)
    if args.username and not args.password:
        parser.error("--password must be provided when --username is set")
    if not args.command:
        parser.error("A Codex MCP server command must be provided after '--'")
    return args


def build_config(args: argparse.Namespace) -> ProxyConfig:
    if args.upstream_scheme in {"http", "https"}:
        http_scheme = args.upstream_scheme
        ws_scheme = "wss" if args.upstream_scheme == "https" else "ws"
    else:
        ws_scheme = args.upstream_scheme
        http_scheme = "https" if args.upstream_scheme == "wss" else "http"
    return ProxyConfig(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_http_scheme=http_scheme,
        upstream_ws_scheme=ws_scheme,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        username=args.username,
        password=args.password,
    )


def _extract_basic_auth(credentials: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        method, payload = credentials.split(" ", 1)
    except ValueError:
        return None, None
    if method.lower() != "basic":
        return None, None
    try:
        decoded = base64.b64decode(payload, validate=True).decode("utf-8")
    except Exception:
        return None, None
    if ":" not in decoded:
        return None, None
    username, password = decoded.split(":", 1)
    return username, password


def _is_authorised(request: web.Request, config: ProxyConfig) -> bool:
    if not config.username:
        return True
    header = request.headers.get("Authorization")
    if not header:
        return False
    username, password = _extract_basic_auth(header)
    if username is None or password is None:
        return False
    return hmac.compare_digest(username, config.username) and hmac.compare_digest(
        password, config.password or ""
    )


def _unauthorised_response() -> web.Response:
    resp = web.Response(status=401, text="Authentication required")
    resp.headers["WWW-Authenticate"] = 'Basic realm="Codex MCP"'
    return resp


def _filter_request_headers(headers: Mapping[str, str]) -> MutableMapping[str, str]:
    excluded = {"host", "content-length", "connection"}
    return {k: v for k, v in headers.items() if k.lower() not in excluded}


def _copy_response_headers(headers: Iterable[Tuple[str, str]]) -> MutableMapping[str, str]:
    excluded = {"content-length", "transfer-encoding", "connection"}
    result: MutableMapping[str, str] = {}
    for key, value in headers:
        if key.lower() in excluded:
            continue
        result[key] = value
    return result


def _close_message_payload(msg) -> Tuple[int, bytes]:  # type: ignore[no-untyped-def]
    code = msg.data if isinstance(msg.data, int) else 1000
    extra = getattr(msg, "extra", b"")
    if isinstance(extra, str):
        message = extra.encode("utf-8")
    elif isinstance(extra, bytes):
        message = extra
    else:
        message = b""
    return code, message


async def handle_proxy_request(
    request: web.Request,
    session: ClientSession,
    config: ProxyConfig,
) -> web.StreamResponse:
    if not _is_authorised(request, config):
        return _unauthorised_response()

    if request.headers.get("Upgrade", "").lower() == "websocket":
        return await _handle_websocket(request, session, config)

    upstream_url = f"{config.upstream_base}{request.rel_url}"
    headers = _filter_request_headers(request.headers)
    data = request.content.iter_chunked(64 * 1024) if request.can_read_body else None

    async with session.request(
        request.method,
        upstream_url,
        headers=headers,
        data=data,
        allow_redirects=False,
    ) as upstream_response:
        response_headers = _copy_response_headers(upstream_response.headers.items())
        stream_response = web.StreamResponse(
            status=upstream_response.status, headers=response_headers
        )
        await stream_response.prepare(request)
        async for chunk in upstream_response.content.iter_chunked(64 * 1024):
            await stream_response.write(chunk)
        await stream_response.write_eof()
        return stream_response


async def _handle_websocket(
    request: web.Request,
    session: ClientSession,
    config: ProxyConfig,
) -> web.StreamResponse:
    upstream_url = config.websocket_url(str(request.rel_url))
    client_ws = web.WebSocketResponse()
    await client_ws.prepare(request)

    ws_headers = _filter_request_headers(request.headers)
    async with session.ws_connect(upstream_url, headers=ws_headers) as upstream_ws:
        async def forward(
            source: web.WebSocketResponse | ClientWebSocketResponse,
            target: web.WebSocketResponse | ClientWebSocketResponse,
        ) -> None:
            try:
                async for msg in source:
                    if msg.type == WSMsgType.TEXT:
                        await target.send_str(msg.data)
                    elif msg.type == WSMsgType.BINARY:
                        await target.send_bytes(msg.data)
                    elif msg.type == WSMsgType.PING:
                        await target.ping(msg.data)
                    elif msg.type == WSMsgType.PONG:
                        await target.pong(msg.data)
                    elif msg.type in {WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED}:
                        code, message = _close_message_payload(msg)
                        await target.close(code=code, message=message)
                        break
                    elif msg.type == WSMsgType.ERROR:
                        exc = getattr(source, "exception", lambda: None)()
                        if exc:
                            logger.warning("WebSocket error: %s", exc)
                        await target.close()
                        break
            except asyncio.CancelledError:
                pass

        send_to_upstream = asyncio.create_task(forward(client_ws, upstream_ws))
        send_to_client = asyncio.create_task(forward(upstream_ws, client_ws))
        done, pending = await asyncio.wait(
            {send_to_upstream, send_to_client},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            with contextlib.suppress(Exception):
                task.result()

    return client_ws


async def run_proxy(args: argparse.Namespace) -> None:
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))
    config = build_config(args)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    registered_signals = []

    def request_shutdown() -> None:
        if not stop_event.is_set():
            logger.info("Shutdown requested")
            stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_shutdown)
        except NotImplementedError:
            continue
        else:
            registered_signals.append(sig)

    try:
        async with CodexServerProcess(args.command) as codex:
            async with ClientSession() as session:
                app = web.Application()

                async def handler(request: web.Request) -> web.StreamResponse:
                    return await handle_proxy_request(request, session, config)

                app.router.add_route("*", "/{tail:.*}", handler)
                runner = web.AppRunner(app)
                await runner.setup()
                site = web.TCPSite(runner, config.listen_host, config.listen_port)
                await site.start()
                logger.info(
                    "Proxy listening on %s:%s and forwarding to %s",
                    config.listen_host,
                    config.listen_port,
                    config.upstream_base,
                )

                codex_wait_task = asyncio.create_task(codex.wait(), name="codex-wait")
                stop_task = asyncio.create_task(stop_event.wait(), name="proxy-stop")
                exit_code: Optional[int] = None
                try:
                    done, pending = await asyncio.wait(
                        {codex_wait_task, stop_task},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if codex_wait_task in done:
                        exit_code = codex_wait_task.result()
                        if exit_code != 0:
                            logger.error(
                                "Codex MCP server exited with code %s", exit_code
                            )
                        else:
                            logger.info("Codex MCP server exited")
                        request_shutdown()
                    else:
                        logger.info("Proxy shutdown requested")
                finally:
                    for task in (codex_wait_task, stop_task):
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(
                        codex_wait_task, stop_task, return_exceptions=True
                    )
                    await runner.cleanup()
                if exit_code not in (None, 0):
                    raise SystemExit(exit_code)
    finally:
        for sig in registered_signals:
            with contextlib.suppress(NotImplementedError):
                loop.remove_signal_handler(sig)


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = parse_args(argv)
    asyncio.run(run_proxy(args))


if __name__ == "__main__":
    main()
