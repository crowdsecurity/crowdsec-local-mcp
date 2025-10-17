import argparse
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SERVER_KEY = "crowdsec-local-mcp"
SERVER_LABEL = "CrowdSec MCP"


@dataclass
class CLIArgs:
    target: str
    config_path: Optional[Path]
    dry_run: bool
    force: bool
    command_override: Optional[str]
    cwd_override: Optional[Path]


def main(argv: Optional[Iterable[str]] = None) -> None:
    args = _parse_args(argv)
    command, cmd_args = _resolve_runner(args.command_override)
    server_payload = {
        "command": command,
        "args": cmd_args,
        "metadata": {
            "label": SERVER_LABEL,
            "description": "CrowdSec local MCP server",
        },
    }
    if args.cwd_override:
        server_payload["cwd"] = str(args.cwd_override)

    if args.target == "stdio":
        _print_stdio(server_payload)
        return

    if args.target == "claude-desktop":
        _configure_claude(args, server_payload)
    elif args.target == "chatgpt":
        _configure_chatgpt(args, server_payload)
    elif args.target == "vscode":
        _configure_vscode(args, server_payload)
    else:
        raise ValueError(f"Unsupported target '{args.target}'")


def _parse_args(argv: Optional[Iterable[str]]) -> CLIArgs:
    parser = argparse.ArgumentParser(
        prog="init",
        description=(
            "Initialize CrowdSec MCP integration for supported clients "
            "(Claude Desktop, ChatGPT Desktop, Visual Studio Code, or stdio)."
        ),
    )
    parser.add_argument(
        "target",
        choices=("claude-desktop", "chatgpt", "vscode", "stdio"),
        help="Client to configure.",
    )
    parser.add_argument(
        "--config-path",
        type=Path,
        help="Override the configuration file path to update.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the resulting configuration instead of writing it.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Create configuration even if the file is missing.",
    )
    parser.add_argument(
        "--command",
        dest="command_override",
        help=(
            "Override the command used to launch the MCP server. "
            "Defaults to 'uvx run --from crowdsec-local-mcp crowdsec-mcp' or "
            "falls back to the current Python interpreter."
        ),
    )
    parser.add_argument(
        "--cwd",
        dest="cwd_override",
        type=Path,
        help="Set the working directory used when launching the server.",
    )

    parsed = parser.parse_args(argv)
    return CLIArgs(
        target=parsed.target,
        config_path=parsed.config_path,
        dry_run=parsed.dry_run,
        force=parsed.force,
        command_override=parsed.command_override,
        cwd_override=parsed.cwd_override,
    )


def _resolve_runner(command_override: Optional[str]) -> Tuple[str, List[str]]:
    if command_override:
        command_parts = command_override.strip().split()
        if not command_parts:
            raise ValueError("Command override cannot be empty.")
        return command_parts[0], command_parts[1:]

    for executable in ("uvx", "uv"):
        resolved = shutil.which(executable)
        if resolved:
            return resolved, [
                "--from",
                "crowdsec-local-mcp",
                "crowdsec-mcp",
            ]

    python_executable = sys.executable
    if not python_executable:
        raise RuntimeError(
            "Unable to determine a Python interpreter to launch the MCP server."
        )
    return python_executable, ["-m", "crowdsec_local_mcp"]


def _configure_claude(args: CLIArgs, server_payload: Dict[str, object]) -> None:
    config_path = _resolve_path(args.config_path, _claude_candidates())
    _write_mcp_config(
        config_path,
        server_payload,
        args,
        client_name="Claude Desktop",
    )


def _configure_chatgpt(args: CLIArgs, server_payload: Dict[str, object]) -> None:
    config_path = _resolve_path(args.config_path, _chatgpt_candidates())
    _write_mcp_config(
        config_path,
        server_payload,
        args,
        client_name="ChatGPT Desktop",
    )


def _configure_vscode(args: CLIArgs, server_payload: Dict[str, object]) -> None:
    if args.config_path:
        print(
            "Warning: --config-path is ignored for Visual Studio Code; "
            "configuration is applied via the `code` CLI."
        )

    code_cli = shutil.which("code")
    if not code_cli:
        raise FileNotFoundError(
            "Visual Studio Code CLI 'code' not found. Ensure VSCode is installed "
            "and the `code` command is available on your PATH."
        )

    env = os.environ.copy()
    home = str(Path.home())
    # scrub env that can break Node/Electron resolution
    for k in ("NODE_OPTIONS", "NODE_PATH", "ELECTRON_RUN_AS_NODE"):
        env.pop(k, None)
        
    vscode_payload = {
        "name": SERVER_KEY,
        "command": server_payload["command"],
        "args": server_payload["args"],
    }
    if "cwd" in server_payload:
        vscode_payload["cwd"] = server_payload["cwd"]
    command = [code_cli, "--add-mcp", json.dumps(vscode_payload)]

    if args.dry_run:
        printable = " ".join(shlex.quote(part) for part in command)
        print(f"Dry run: {printable}")
        return

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            cwd=home,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout.strip() if exc.stdout else ""
        stderr = exc.stderr.strip() if exc.stderr else ""
        details = []
        if stdout:
            details.append(f"stdout:\n{stdout}")
        if stderr:
            details.append(f"stderr:\n{stderr}")
        detail_msg = "\n".join(details)
        raise RuntimeError(
            "Failed to register MCP server with VSCode "
            f"(exit code {exc.returncode})."
            + (f"\n{detail_msg}" if detail_msg else "")
        ) from exc

    if result.stdout:
        print("`code --add-mcp` stdout:")
        print(result.stdout.rstrip())
    if result.stderr:
        print("`code --add-mcp` stderr:")
        print(result.stderr.rstrip(), file=sys.stderr)

    print("Registered CrowdSec MCP server with Visual Studio Code via `code --add-mcp`.")


def _write_mcp_config(
    config_path: Path,
    server_payload: Dict[str, object],
    args: CLIArgs,
    *,
    client_name: str,
) -> None:
    config, existed = _load_json(config_path, allow_missing=True)
    if not existed and not (args.force or args.dry_run):
        raise FileNotFoundError(
            f"{config_path} does not exist. Re-run with --force to create it "
            "or provide --config-path pointing to an existing configuration file."
        )
    mcp_servers = config.setdefault("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        raise ValueError(f"Expected 'mcpServers' to be an object in {config_path}")

    mcp_servers[SERVER_KEY] = server_payload

    if args.dry_run:
        print(json.dumps(config, indent=2))
        return

    _ensure_directory(config_path)
    _backup_file_if_exists(config_path)
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(f"Configured {client_name} at {config_path}")


def _print_stdio(server_payload: Dict[str, object]) -> None:
    snippet = {
        "server": SERVER_KEY,
        "command": server_payload["command"],
        "args": server_payload["args"],
    }
    cwd = server_payload.get("cwd")
    if cwd is not None:
        snippet["cwd"] = cwd

    print(
        "Use the following configuration with stdio-compatible MCP clients:\n"
        f"{json.dumps(snippet, indent=2)}"
    )


def _load_json(path: Path, *, allow_missing: bool) -> Tuple[Dict[str, object], bool]:
    if not path.exists():
        if allow_missing:
            return {}, False
        raise FileNotFoundError(f"Configuration file {path} does not exist.")

    content = path.read_text(encoding="utf-8")
    if not content.strip():
        return {}, True

    try:
        return json.loads(content), True
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse JSON from {path}: {exc}") from exc


def _resolve_path(explicit: Optional[Path], candidates: List[Path]) -> Path:
    if explicit:
        return explicit.expanduser()

    expanded = [candidate.expanduser() for candidate in candidates]
    for candidate in expanded:
        if candidate.exists():
            return candidate

    if expanded:
        return expanded[0]

    raise ValueError("No configuration path candidates were provided.")


def _ensure_directory(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _backup_file_if_exists(path: Path) -> None:
    if not path.exists():
        return
    backup_path = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup_path)
    print(f"Existing configuration backed up to {backup_path}")


def _claude_candidates() -> List[Path]:
    system = platform.system()
    if system == "Darwin":
        return [
            Path.home()
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        ]
    if system == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home()))
        return [base / "Claude" / "claude_desktop_config.json"]
    return [Path.home() / ".config" / "Claude" / "claude_desktop_config.json"]


def _chatgpt_candidates() -> List[Path]:
    system = platform.system()
    if system == "Darwin":
        return [
            Path.home()
            / "Library"
            / "Application Support"
            / "ChatGPT"
            / "config.json"
        ]
    if system == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home()))
        return [base / "ChatGPT" / "config.json"]
    return [Path.home() / ".config" / "ChatGPT" / "config.json"]


if __name__ == "__main__":
    main()
