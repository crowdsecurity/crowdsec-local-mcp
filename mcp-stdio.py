#!/usr/bin/env python3

import asyncio

from mcp_core import LOGGER, main

# Import modules for their registration side effects.
import mcp_waf  # noqa: F401

try:
    import mcp_scenarios  # noqa: F401
except ModuleNotFoundError:
    LOGGER.warning("Scenario module not available; scenario tools disabled")


if __name__ == "__main__":
    asyncio.run(main())
