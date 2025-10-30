<p align="center">
<img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/crowdsec_logo.png" alt="CrowdSec" title="CrowdSec" width="400" height="260"/>
</p>


**Life is too short to write YAML, just ask nicely!**

> A Model Context Protocol (MCP) server to generate, validate, and deploy CrowdSec WAF rules & Scenarios.


## Features

### WAF Rules Features

- **WAF Rule Generation**: Generate CrowdSec WAF rules from user input or a CVE reference
- **Validation**: Validate syntaxical correctness of WAF rules
- **Linting**: Get warnings and hints to improve your WAF rules
- **Deployment Guide**: Step-by-step deployment instructions
- **Docker Test Harness**: Spin up CrowdSec + nginx + bouncer to exercise rules for false positives/negatives
- **Nuclei Lookup**: Quickly jump to existing templates in the official `projectdiscovery/nuclei-templates` repository for a given CVE

### Scenarios Features

- **CrowdSec Scenarios Generation**: Generate CrowdSec scenarios
- **Validation**: Validate syntaxical correctness of scenarios
- **Linting**: Get warnings and hints to improve your scenarios
- **Deployment Guide**: Step-by-step deployment instructions
- **Docker Test Harness**: Spin up CrowdSec to test scenario behavior

## Demo

### WAF Rules Creation and testing

 - [Rule creation from natural language](https://claude.ai/share/f0f246b2-6b20-4d70-a16c-c6b627ab2d80)
 - [Rule creation from CVE reference](https://claude.ai/share/b6599407-82dd-443c-a12d-9a9825ed99df)

### Scenario Creation and testing

 - [Rule creation on HTTP events](https://claude.ai/share/3658165a-5636-4a7e-8043-01e7a7517200)
 - [Rule creation based on GeoLocation factors](https://claude.ai/share/ff154e66-3c1a-44e6-a464-b694f65bd67e)

## Prerequisites

- [uv](https://docs.astral.sh/uv/) 0.4 or newer, which provides the `uvx` runner used in the examples below.
- Docker with the Compose plugin (Compose v2).

## Installation

You can install the MCP using `uvx` **or** use packaged `.mcpb` file for claude code.

### Quick MCP client setup

- Configure supported clients automatically with `uvx --from crowdsec-local-mcp init <client>`, where `<client>` is one of `claude-desktop`, `chatgpt`, `vscode`, or `stdio`:

```bash
uvx --from crowdsec-local-mcp init claude-desktop
```

Run `uvx --from crowdsec-local-mcp init --help` to see all flags and supported targets.

#### What `init` configures

The `init` helper writes the CrowdSec MCP server definition into the client’s JSON configuration:

- `claude-desktop` → `claude_desktop_config.json`
- `chatgpt` → `config.json` in the ChatGPT Desktop settings directory
- `vscode` → `mcp.json` for VS Code (stable and insiders are both detected)

If the client's configuration file already exists, a `.bak` backup is created before the MCP server block is updated. When the file is missing you can either pass `--force` to create it, or point `--config-path` to a custom location. Combine `--dry-run` with these options to preview the JSON without making any changes.

By default the CLI launches the server with `uvx --from crowdsec-local-mcp crowdsec-mcp`. If neither `uvx` nor `uv` is available, it falls back to your current Python interpreter; you can override the executable with `--command` and the working directory with `--cwd`.

#### Using the `stdio` target

`stdio` does not modify any files. Instead, `init stdio` prints a ready-to-paste JSON snippet that you can drop into any stdio-compatible MCP client configuration. This is useful when you want to manually wire the server into tools that do not have built-in automation support yet.

## Logging

- The MCP server writes its log file to your operating system's temporary directory. On Linux/macOS this is typically `/tmp/crowdsec-mcp.log`; on Windows it resolves via `%TEMP%\crowdsec-mcp.log`.
