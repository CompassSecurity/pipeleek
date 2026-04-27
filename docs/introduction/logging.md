---
title: Logging
description: Learn about Pipeleek's logging system, output formats (console and JSON), log levels, interactive controls, and ELK stack integration for analyzing scan results.
keywords:
  - logging
  - log formats
  - console output
  - JSON output
  - log levels
  - interactive logging
  - ELK integration
  - structured logging
---

## Log Levels

Pipeleek uses structured logging with the following levels:

- `trace`: Most detailed logging, includes all operations
- `debug`: Detailed information for debugging
- `info`: General informational messages
- `warn`: Warning messages for potential issues
- `hit`: **Custom level for security findings** - indicates a potential secret or credential has been detected
- `error`: Error messages for failures

## Log Formats

Pipeleek supports two output formats for logs: **Console** (default) and **JSON**. You can control the format using the `--json` flag.

### Console Format (Default)

The console format is human-readable and color-coded for easy visual parsing. Each log entry displays:

```
2025-12-03T10:15:30Z info Starting scan target=gitlab.com
2025-12-03T10:15:31Z debug Processing repository repo=myorg/myproject
2025-12-03T10:15:32Z hit Secret detected rule=aws-access-token confidence=high
```

**Color coding**: Different colors for each log level (can be disabled with `--color=false`). Coloring is automatically disabled when using a logfile `--logfile`

### JSON Format

The JSON format outputs each log entry as a structured JSON object on a single line, making it ideal for log aggregation systems, parsing, and automation.

```json
{"level":"info","time":"2025-12-03T10:15:30Z","message":"Starting scan","target":"gitlab.com"}
{"level":"debug","time":"2025-12-03T10:15:31Z","message":"Processing repository","repo":"myorg/myproject"}
{"level":"hit","time":"2025-12-03T10:15:32Z","message":"Secret detected","rule":"aws-access-token","confidence":"high"}
```

**Custom hit level**: Security findings are marked with `"level":"hit"`

**Usage:**

```bash
# Enable JSON output
pipeleek gl scan -g https://gitlab.com -t glpat-xxxxx --json
```

## Log File Output

You can direct log output to a file using the `--logfile` or `-l` flag. This works with both console and JSON formats.

```bash
# Console format to file (colors auto-disabled)
pipeleek gl scan -g https://gitlab.com -t glpat-xxxxx -l scan.log

# JSON format to file
pipeleek gl scan -g https://gitlab.com -t glpat-xxxxx --json -l scan.jsonl
```

## Controlling Log Levels

You can control which log messages are displayed using the `--log-level` flag or the `--verbose` shortcut:

```bash
# Set specific log level
pipeleek gl scan -g https://gitlab.com -t glpat-xxxxx --log-level=warn

# Enable debug logging (shortcut)
pipeleek gl scan -g https://gitlab.com -t glpat-xxxxx --verbose

# Available levels: trace, debug, info, warn, error
pipeleek gl scan -g https://gitlab.com -t glpat-xxxxx --log-level=trace
```

**Important:** The `hit` level is always shown regardless of the `--log-level` setting, as it indicates critical security findings.

## Interactive Log Level

You can change interactively between log levels by pressing `t`: Trace, `d`: Debug, `i`: info, `w`: Warn, `e`: Error.

```bash
pipeleek gl scan -g https://gitlab.com -t glpat-[redacted] --truffle-hog-verification=false --verbose
# Human Pressed d on keyboard
2025-09-30T11:42:58Z info New Log level logLevel=debug
```

> **💡Tip:** Some commands like the scan commands support a status shortcut. Pressing `s` will output their current status.

## ELK Integration

To easily analyze the results you can [redirect the pipeleek](https://github.com/deviantony/docker-elk?tab=readme-ov-file#injecting-data) output using `nc` into Logstash.

Setup a local ELK stack using https://github.com/deviantony/docker-elk.

Then you can start a scan:

```bash
pipeleek gl scan --token glpat-[redacted] --gitlab https://gitlab.example.com  --json | nc -q0 localhost 50000
```

Using Kibana you can filter for interesting messages, based on the JSON attributes of the output.

### Docker Compose Example (Shared Config + One-Shot Jobs)

An end-to-end Docker Compose example is available at `examples/compose-elk/`.

It includes:

- One shared Pipeleek config file mounted read-only into all scanner containers
- One-shot scanner services for all scan commands (`gl`, `gh`, `bb`, `ad`, `gitea`, `circle`, `jenkins`)
- Logstash TCP ingestion for Pipeleek JSON lines
- Elasticsearch storage and Kibana visualization

Quick start:

```bash
cd examples/compose-elk
docker compose up -d elasticsearch logstash kibana
docker compose --profile gitlab run --rm scan-gitlab
```

Then open Kibana at `http://localhost:5601` and create a data view for `pipeleek-logs-*`.
