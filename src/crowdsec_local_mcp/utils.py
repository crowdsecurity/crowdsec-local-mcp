import subprocess

from .mcp_core import LOGGER

_COMPOSE_CMD_CACHE: list[str] | None = None
_COMPOSE_STACK_PROCESS: subprocess.Popen | None = None


def detect_compose_command() -> list[str]:
    """Detect whether docker compose or docker-compose is available."""
    global _COMPOSE_CMD_CACHE
    if _COMPOSE_CMD_CACHE is not None:
        return _COMPOSE_CMD_CACHE

    candidates = [["docker", "compose"], ["docker-compose"]]

    for candidate in candidates:
        try:
            result = subprocess.run(
                candidate + ["version"],
                check=True,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                _COMPOSE_CMD_CACHE = candidate
                LOGGER.info("Detected compose command: %s", " ".join(candidate))
                return candidate
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError:
            continue

    LOGGER.error(
        "Failed to detect Docker Compose command; ensure Docker is installed and available"
    )
    raise RuntimeError(
        "Docker Compose is required but was not found. Install Docker and ensure `docker compose` or `docker-compose` is available."
    )