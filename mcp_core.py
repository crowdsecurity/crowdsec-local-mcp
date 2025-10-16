import logging
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

SCRIPT_DIR = Path(__file__).parent
PROMPTS_DIR = SCRIPT_DIR / "prompts"
LOG_FILE_PATH = SCRIPT_DIR / "crowdsec-mcp.log"


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

ToolHandler = Callable[[Optional[Dict[str, Any]]], List[types.TextContent]]
ResourceReader = Callable[[], str]


class MCPRegistry:
    """Central registry for tool and resource integrations."""

    def __init__(self) -> None:
        self._tool_handlers: Dict[str, ToolHandler] = {}
        self._tools: "OrderedDict[str, types.Tool]" = OrderedDict()
        self._resources: "OrderedDict[str, types.Resource]" = OrderedDict()
        self._resource_readers: Dict[str, ResourceReader] = {}

    def register_tools(
        self,
        handlers: Dict[str, ToolHandler],
        tool_definitions: List[types.Tool],
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
        resources: List[types.Resource],
        readers: Dict[str, ResourceReader],
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
    def tools(self) -> List[types.Tool]:
        return list(self._tools.values())

    @property
    def resources(self) -> List[types.Resource]:
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


@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    LOGGER.info("Listing available tools")
    return REGISTRY.tools


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: Optional[Dict[str, Any]]
) -> List[types.TextContent]:
    LOGGER.info("handle_call_tool invoked for tool '%s'", name)
    handler = REGISTRY.get_tool_handler(name)
    return handler(arguments)


@server.list_resources()
async def handle_list_resources() -> List[types.Resource]:
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
