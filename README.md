# System Log Analyzer (stdlib + uv)

CLI tool to parse and analyze syslog-like logs:
- Filters by time range, level, substring, or regex
- Stats (level counts, top apps/messages), grouping by day/hour
- Exports to JSON/CSV
- No external dependencies (stdlib only)

## Quick Start (with uv)

```bash
# From the project root:
uv run python log_analyzer.py --file samples/syslog.sample --stats --top 5

