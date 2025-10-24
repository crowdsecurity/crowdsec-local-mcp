import logging
import shutil
import subprocess
import tempfile
from collections import OrderedDict
from pathlib import Path
from typing import Any
from collections.abc import Callable

import mcp.server.stdio
from mcp import types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

SCRIPT_DIR = Path(__file__).parent
PROMPTS_DIR = SCRIPT_DIR / "prompts"
LOG_FILE_PATH = Path(tempfile.gettempdir()) / "crowdsec-mcp.log"
_DOCKER_CLI_CHECK: bool | None = None
_DOCKER_COMPOSE_CMD: list[str] | None = None
_DOCKER_PERMISSION_TOKENS = (
    "permission denied",
    "docker daemon",
    "got permission denied",
    "is the docker daemon running",
    "cannot connect to the docker daemon",
)


def _configure_logger() -> logging.Logger:
    """Configure and return the module-level logger."""
    LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("crowdsec-mcp")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(LOG_FILE_PATH, encoding="utf-8")
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


LOGGER = _configure_logger()
server = Server("crowdsec-prompt-server")

ToolHandler = Callable[[dict[str, Any] | None], list[types.TextContent]]
ResourceReader = Callable[[], str]


class MCPRegistry:
    """Central registry for tool and resource integrations."""

    def __init__(self) -> None:
        self._tool_handlers: dict[str, ToolHandler] = {}
        self._tools: OrderedDict[str, types.Tool] = OrderedDict()
        self._resources: OrderedDict[str, types.Resource] = OrderedDict()
        self._resource_readers: dict[str, ResourceReader] = {}

    def register_tools(
        self,
        handlers: dict[str, ToolHandler],
        tool_definitions: list[types.Tool],
    ) -> None:
        for name, handler in handlers.items():
            if name in self._tool_handlers:
                raise ValueError(f"Tool handler already registered for '{name}'")
            self._tool_handlers[name] = handler

        for tool in tool_definitions:
            if tool.name in self._tools:
                raise ValueError(f"Tool definition already registered for '{tool.name}'")
            self._tools[tool.name] = tool

    def register_resources(
        self,
        resources: list[types.Resource],
        readers: dict[str, ResourceReader],
    ) -> None:
        for resource in resources:
            if resource.uri in self._resources:
                raise ValueError(f"Resource already registered for '{resource.uri}'")
            self._resources[resource.uri] = resource

        for uri, reader in readers.items():
            if uri in self._resource_readers:
                raise ValueError(f"Resource reader already registered for '{uri}'")
            self._resource_readers[uri] = reader

    @property
    def tools(self) -> list[types.Tool]:
        return list(self._tools.values())

    @property
    def resources(self) -> list[types.Resource]:
        return list(self._resources.values())

    def get_tool_handler(self, name: str) -> ToolHandler:
        try:
            return self._tool_handlers[name]
        except KeyError as exc:
            raise ValueError(f"Unknown tool: {name}") from exc

    def get_resource_reader(self, uri: str) -> ResourceReader:
        try:
            return self._resource_readers[uri]
        except KeyError as exc:
            raise ValueError(f"Unknown resource: {uri}") from exc


REGISTRY = MCPRegistry()


def docker_permission_hint(*outputs: str) -> str:
    """Return a standard hint if Docker output indicates permission/daemon issues."""
    combined = "\n".join(part for part in outputs if part).lower()
    if not combined:
        return ""
    if any(token in combined for token in _DOCKER_PERMISSION_TOKENS):
        return (
            "\nHint: Ensure the Docker daemon is running and that the current user has permission to run Docker commands."
        )
    return ""


def ensure_docker_cli() -> None:
    """Ensure the Docker CLI is available and executable."""
    global _DOCKER_CLI_CHECK
    if _DOCKER_CLI_CHECK:
        return

    docker_path = shutil.which("docker")
    if not docker_path:
        raise RuntimeError(
            "Docker is required but the `docker` executable was not found on PATH. "
            "Install Docker Desktop or Docker Engine and ensure the `docker` CLI is accessible."
        )

    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Docker is required but the `docker` executable could not be executed. "
            "Install Docker and ensure the CLI is on PATH."
        ) from exc
    except PermissionError as exc:
        raise RuntimeError(
            "Docker was found but is not executable by the current process. "
            "Adjust permissions or run as a user allowed to execute Docker commands."
        ) from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        hint = (
            "Docker appears to be installed but `docker info` failed. "
            "Ensure the Docker daemon is installed correctly and the current user can execute Docker commands."
        )
        if detail:
            hint = f"{hint} Details: {detail}"
        raise RuntimeError(hint) from exc

    LOGGER.info("Docker CLI detected at %s", docker_path)
    _DOCKER_CLI_CHECK = True


def ensure_docker_compose_cli() -> list[str]:
    """Ensure a Docker Compose CLI is available and executable; return the command."""
    global _DOCKER_COMPOSE_CMD
    if _DOCKER_COMPOSE_CMD is not None:
        return _DOCKER_COMPOSE_CMD

    ensure_docker_cli()

    candidates = [["docker", "compose"], ["docker-compose"]]
    errors: list[str] = []

    for candidate in candidates:
        command_display = " ".join(candidate)
        try:
            result = subprocess.run(
                candidate + ["version"],
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            errors.append(f"`{command_display}` command not found: {exc}")
            continue
        except PermissionError as exc:
            errors.append(
                f"`{command_display}` is present but not executable: {exc}\n"
                "Hint: Adjust permissions or execute the command as a user allowed to run Docker."
            )
            continue
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or str(exc)).strip()
            hint = docker_permission_hint(detail)
            message = f"`{command_display}` failed to run: {detail or 'unknown error'}{hint}"
            errors.append(message)
            continue

        if result.returncode == 0:
            _DOCKER_COMPOSE_CMD = candidate
            LOGGER.info("Docker Compose CLI detected: %s", command_display)
            return candidate

    detail_suffix = f" Details: {'; '.join(errors)}" if errors else ""
    raise RuntimeError(
        "Docker Compose is required but could not be executed. Install Docker Desktop or Docker Engine and ensure "
        "`docker compose` or `docker-compose` is available on PATH." + detail_suffix
    )


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    LOGGER.info("Listing available tools")
    return REGISTRY.tools


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict[str, Any] | None
) -> list[types.TextContent]:
    LOGGER.info("handle_call_tool invoked for tool '%s'", name)
    handler = REGISTRY.get_tool_handler(name)
    return handler(arguments)


@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    LOGGER.info("Listing available resources")
    return REGISTRY.resources


@server.read_resource()
async def handle_read_resource(uri: str) -> str:
    LOGGER.info("Reading resource content for %s", uri)
    reader = REGISTRY.get_resource_reader(uri)
    return reader()


async def main() -> None:
    """Main entry point for the MCP server."""
    LOGGER.info("Starting MCP stdio server")
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="crowdsec-prompt-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
    LOGGER.info("MCP stdio server stopped")
