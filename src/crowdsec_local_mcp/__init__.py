"""CrowdSec MCP package."""

from .mcp_core import main

try:
    from ._version import __version__
except ModuleNotFoundError:  # pragma: no cover - generated during release
    __version__ = "0.0.0"

__all__ = ["__version__", "main"]
