#!/usr/bin/env python3

# Use `uv run --project . <command>` to run this module directly for testing.

import asyncio

from .mcp_core import LOGGER, main

# Import modules for their registration side effects.
from . import mcp_waf  # noqa: F401

try:
    from . import mcp_scenarios  # noqa: F401
except ModuleNotFoundError:
    LOGGER.warning("Scenario module not available; scenario tools disabled")


def run() -> None:
    """Entry-point used by console scripts."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
