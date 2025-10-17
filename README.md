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

 - [Rule creation from natural language with Claude Desktop](https://claude.ai/share/f0f246b2-6b20-4d70-a16c-c6b627ab2d80)
 - [Rule creation from CVE reference](https://claude.ai/share/b6599407-82dd-443c-a12d-9a9825ed99df)

### Scenario Creation and testing

 - XX
 - XX

## Installation

### Quick MCP client setup

- Configure supported clients automatically with `uvx run --from crowdsec-local-mcp init <client>`, where `<client>` is one of `claude-desktop`, `chatgpt`, `vscode`, or `stdio`:

```bash
uvx --from crowdsec-local-mcp init
```

## Logging

- The MCP server writes its log file to your operating system's temporary directory. On Linux/macOS this is typically `/tmp/crowdsec-mcp.log`; on Windows it resolves via `%TEMP%\crowdsec-mcp.log`.

## Pre Requisites

 - Docker + Docker Compose

 - Python >= 3.12

