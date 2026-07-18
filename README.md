# DroidSec Auditor

## Overview

DroidSec Auditor is a NitroStack MCP server for Android and hybrid web application security review. It exposes MCP tools, resources, and prompts that help an AI client inspect extracted mobile app artifacts, detect insecure configuration, identify hardcoded secrets, review local storage, and produce a developer-ready penetration testing report.

## Problem Statement

Mobile and hybrid application teams often miss security issues that live outside normal source review: exported Android components, plaintext tokens in local storage, insecure backup flags, stale web dependencies, and missing browser security headers. DroidSec Auditor packages those checks as MCP primitives so AI-assisted review can be repeatable, explainable, and easy to run during development or hackathon judging.

## Features

- Android manifest checks for debug mode, backup exposure, cleartext traffic, and exported content providers.
- Local SQLite and SharedPreferences inspection for plaintext credentials and session tokens.
- Hardcoded secret detection with live Gitleaks rules and offline fallback patterns.
- JavaScript AST scanning for suspicious secret-like assignments.
- Web package and HTML security checks for vulnerable dependencies and missing CSP.
- Upload ingestion tool with path traversal protection.
- Reusable pentest report prompt for turning findings into remediation guidance.
- NitroStack health check for runtime visibility.

## Architecture

The server uses a modular NitroStack layout:

- `AppModule` bootstraps configuration, health checks, and feature modules.
- `AuditModule` groups all audit tools, resources, and prompts.
- `AuditTools` implements executable security checks.
- `AuditResources` exposes structured app artifact data and secret detection patterns.
- `AuditPrompts` provides report-generation instructions.
- `SystemHealthCheck` reports process uptime, memory, Node.js version, and health status.

## MCP Tools

- `scan_for_hardcoded_keys`: scans mock app storage and resource files for secrets.
- `analyze_content_provider_exposure`: inspects `AndroidManifest.xml` for Android security misconfiguration.
- `extract_plaintext_credentials`: reads the local SQLite fixture for plaintext passwords and session tokens.
- `ingest_file`: accepts a base64 encoded Android or web source file and stores it in an ignored upload directory.
- `scan_js_ast`: parses a JavaScript file and flags suspicious secret-like assignments.
- `audit_web_dependencies`: checks a fixture `package.json` against a vulnerable dependency dictionary.
- `audit_html_security`: checks `index.html` for missing Content Security Policy metadata.

## MCP Resources

- `audit://app-storage`: returns extracted app storage, API configuration rows, SharedPreferences XML, and manifest data as JSON.
- `audit://secret-patterns`: returns live Gitleaks secret rules when available, with an offline fallback rule set.

## MCP Prompts

- `pentest_report`: formats combined tool findings into a formal penetration testing report with remediation guidance.

## Tech Stack

- Node.js 20+
- TypeScript
- NitroStack MCP framework
- Zod schemas through NitroStack decorators
- better-sqlite3
- Acorn and acorn-walk for JavaScript AST analysis

## Installation

```bash
npm install
```

## Configuration

Copy `.env.example` to `.env` for local development if you need to override defaults. Do not commit `.env` files.

```bash
cp .env.example .env
```

## Environment Variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `NITRO_LOG_LEVEL` | No | `info` | Logging verbosity for NitroStack runtime. |
| `NITROSTACK_APP_MODE` | No | `openai` | App compatibility mode. |
| `MCP_TRANSPORT_TYPE` | No | dev: `stdio`, prod: `dual` | Transport mode: `stdio`, `http`, or `dual`. |
| `PORT` | No | `3000` | HTTP transport port when enabled. |
| `HOST` | No | `localhost` | HTTP bind host when enabled. |
| `ENABLE_CORS` | No | `true` | Enables CORS for HTTP transport. |

## Running Locally

```bash
npm run dev
```

Build and start a production-style server:

```bash
npm run build
npm run start:prod
```

## Deploying To NitroCloud

Use this repository as the NitroCloud source repository.

- Install command: `npm install`
- Build command: `npm run build`
- Start command: `npm run start:prod`
- Node.js runtime: `>=20`

Recommended production environment:

```bash
NODE_ENV=production
MCP_TRANSPORT_TYPE=dual
NITRO_LOG_LEVEL=info
NITROSTACK_APP_MODE=openai
```

## Repository Structure

```text
.
├── mock-data/                  # Safe fixture data used by audit tools
├── scripts/                    # Utility scripts for fixture generation
├── src/
│   ├── app.module.ts           # NitroStack root module
│   ├── index.ts                # Server entrypoint
│   ├── health/                 # Runtime health checks
│   ├── modules/audit/          # MCP tools, resources, and prompts
│   └── widgets/                # NitroStack widget source
├── .env.example                # Documented environment variables
├── .gitignore                  # Generated files and secrets exclusion rules
├── package.json
├── package-lock.json
└── tsconfig.json
```

## Future Improvements

- Add configurable target artifact directories instead of relying only on `mock-data`.
- Add CVE-backed dependency analysis through npm audit or OSV.
- Add SARIF or JSON report export for CI pipelines.
- Add automated tests for each MCP tool and resource.
- Add a dedicated security dashboard widget for audit summaries.

## License

This repository is currently marked `UNLICENSED` in `package.json`. Add a formal license file before public reuse if the project will be distributed beyond the hackathon submission.
