"""
System Log Analyzer (stdlib-only)

Features:
- Parse common syslog-like lines: "MMM DD HH:MM:SS host app[pid]: LEVEL message"
- Filters: --from, --to, --level, --contains, --regex
- Stats: --stats, --top N (messages/apps), --group-by day|hour
- Export: --export csv|json --out <path>
- Works on any text log (best on /var/log/syslog, auth.log, nginx/syslog-like)

Usage examples:
  uv run python log_analyzer.py --file samples/syslog.sample --stats
  uv run python log_analyzer.py --file /var/log/syslog --level ERROR --top 10
"""

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Iterable, Dict, Any, Tuple

MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1
)}

SYSLOG_RE = re.compile(
    r"""
    ^(?P<mon>[A-Z][a-z]{2})\s+
     (?P<day>\d{1,2})\s+
     (?P<time>\d{2}:\d{2}:\d{2})\s+
     (?P<host>[^\s]+)\s+
     (?P<app>[A-Za-z0-9_.\-\/]+)
     (?:\[(?P<pid>\d+)\])?:
     \s*(?P<msg>.*)$
    """, re.VERBOSE
)

LEVELS = ["DEBUG", "INFO", "NOTICE", "WARN", "WARNING", "ERROR", "ERR", "CRIT", "CRITICAL", "ALERT"]
LEVEL_RE = re.compile(r"\b(" + "|".join(LEVELS) + r")\b", re.IGNORECASE)

CURRENT_YEAR = datetime.now().year

@dataclass
class LogEntry:
    ts: Optional[datetime]
    host: str
    app: str
    pid: Optional[int]
    level: str
    message: str
    raw: str

def parse_line(line: str) -> Optional[LogEntry]:
    m = SYSLOG_RE.match(line.rstrip("\n"))
    if not m:
        return None

    mon = m.group("mon")
    day = int(m.group("day"))
    time_str = m.group("time")
    host = m.group("host")
    app = m.group("app")
    pid = m.group("pid")
    msg = m.group("msg").strip()

    try:
        month = MONTHS.get(mon, 1)
        ts = datetime.strptime(f"{CURRENT_YEAR}-{month:02d}-{day:02d} {time_str}", "%Y-%m-%d %H:%M:%S")
    except Exception:
        ts = None

    level = "INFO"
    lm = LEVEL_RE.search(msg)
    if lm:
        level = lm.group(1).upper().replace("WARNING", "WARN").replace("CRITICAL", "CRIT").replace("ERR", "ERROR")

    return LogEntry(
        ts=ts,
        host=host,
        app=app,
        pid=int(pid) if pid else None,
        level=level,
        message=msg,
        raw=line.rstrip("\n"),
    )

def load_entries(path: Path) -> Iterable[LogEntry]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            e = parse_line(line)
            if e:
                yield e

def in_time_range(e: LogEntry, frm: Optional[datetime], to: Optional[datetime]) -> bool:
    if e.ts is None:
        return True  
    if frm and e.ts < frm:
        return False
    if to and e.ts > to:
        return False
    return True

def filter_entries(
    entries: Iterable[LogEntry],
    frm: Optional[datetime],
    to: Optional[datetime],
    level: Optional[str],
    contains: Optional[str],
    regex: Optional[re.Pattern]
) -> Iterable[LogEntry]:
    for e in entries:
        if not in_time_range(e, frm, to):
            continue
        if level and e.level != level.upper():
            continue
        if contains and contains.lower() not in e.message.lower():
            continue
        if regex and not regex.search(e.message):
            continue
        yield e

def group_key(e: LogEntry, mode: Optional[str]) -> Optional[str]:
    if not mode or not e.ts:
        return None
    if mode == "day":
        return e.ts.strftime("%Y-%m-%d")
    if mode == "hour":
        return e.ts.strftime("%Y-%m-%d %H:00")
    return None

def summarize(entries: Iterable[LogEntry], group_by: Optional[str]) -> Dict[str, Any]:
    level_counter = Counter()
    app_counter = Counter()
    msg_counter = Counter()
    grouped = defaultdict(lambda: Counter())

    n = 0
    for e in entries:
        n += 1
        level_counter[e.level] += 1
        app_counter[e.app] += 1
        msg_key = e.message.split("  ")[0][:160]
        msg_counter[msg_key] += 1
        gk = group_key(e, group_by)
        if gk:
            grouped[gk][e.level] += 1

    return {
        "count": n,
        "levels": level_counter,
        "apps": app_counter,
        "messages": msg_counter,
        "grouped": grouped,
    }

def parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    fmts = ["%Y-%m-%d", "%Y-%m-%d %H:%M:%S"]
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise SystemExit(f"Invalid date format: {s}. Use 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'.")

def export_data(data: Dict[str, Any], kind: str, out: Path) -> None:
    kind = kind.lower()
    out.parent.mkdir(parents=True, exist_ok=True)
    if kind == "json":
        serializable = {
            "count": data["count"],
            "levels": dict(data["levels"]),
            "apps": dict(data["apps"]),
            "messages": dict(data["messages"]),
            "grouped": {k: dict(v) for k, v in data["grouped"].items()},
        }
        out.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
    elif kind == "csv":
        base = out.with_suffix("")
        with (base.with_name(base.name + "_levels").with_suffix(".csv")).open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["level", "count"])
            for k, v in data["levels"].most_common():
                w.writerow([k, v])
        with (base.with_name(base.name + "_apps").with_suffix(".csv")).open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["app", "count"])
            for k, v in data["apps"].most_common():
                w.writerow([k, v])
        with (base.with_name(base.name + "_messages").with_suffix(".csv")).open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["message", "count"])
            for k, v in data["messages"].most_common():
                w.writerow([k, v])
    else:
        raise SystemExit("Supported exports are: json, csv")

def preview(entries: Iterable[LogEntry], limit: int = 10) -> None:
    print(f"\nPreview (first {limit} matches):")
    i = 0
    for e in entries:
        if i >= limit:
            break
        ts = e.ts.strftime("%Y-%m-%d %H:%M:%S") if e.ts else "N/A"
        pid = f"[{e.pid}]" if e.pid is not None else ""
        print(f"{ts} {e.host} {e.app}{pid} {e.level}: {e.message}")
        i += 1
    if i == 0:
        print("(no matches)")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="System Log Analyzer (syslog-like)")
    p.add_argument("--file", type=Path, required=True, help="Path to log file")
    p.add_argument("--from", dest="frm", type=str, help="Start time (YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS')")
    p.add_argument("--to", dest="to", type=str, help="End time (YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS')")
    p.add_argument("--level", type=str, choices=["DEBUG","INFO","NOTICE","WARN","ERROR","CRIT"], help="Filter by level")
    p.add_argument("--contains", type=str, help="Substring filter (case-insensitive)")
    p.add_argument("--regex", type=str, help="Regex filter applied to message")
    p.add_argument("--group-by", type=str, choices=["day","hour"], help="Group counts over time")
    p.add_argument("--top", type=int, default=0, help="Show top N messages and apps")
    p.add_argument("--stats", action="store_true", help="Print stats summary")
    p.add_argument("--export", type=str, choices=["json","csv"], help="Export data")
    p.add_argument("--out", type=Path, help="Export path (file or base name for CSVs)")
    p.add_argument("--preview", type=int, default=10, help="Preview first N matching lines")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    path = args.file
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    frm = parse_dt(args.frm)
    to = parse_dt(args.to)
    rx = re.compile(args.regex) if args.regex else None

    all_entries = list(load_entries(path))
    filtered = list(filter_entries(all_entries, frm, to, args.level, args.contains, rx))

    preview(iter(filtered), limit=args.preview)

    data = summarize(iter(filtered), group_by=args.group_by)

    if args.stats or args.top:
        print("\n--- Stats ---")
        print(f"Matched lines: {data['count']}")
        if data["levels"]:
            print("By level:", ", ".join(f"{k}:{v}" for k, v in data["levels"].most_common()))
        if data["apps"]:
            print("Top apps:", ", ".join(f"{k}:{v}" for k, v in data['apps'].most_common(5)))
        if args.top:
            top_n = args.top
            print(f"\nTop {top_n} messages:")
            for msg, c in data["messages"].most_common(top_n):
                print(f"{c:>5} | {msg}")

        if args.group_by and data["grouped"]:
            print(f"\nGrouped by {args.group_by}:")
            for bucket, counts in sorted(data["grouped"].items()):
                line = ", ".join(f"{k}:{v}" for k, v in counts.most_common())
                print(f"{bucket} -> {line}")

    if args.export:
        if not args.out:
            raise SystemExit("--out is required when using --export")
        export_data(data, args.export, args.out)
        print(f"\nExported {args.export.upper()} to {args.out}")

if __name__ == "__main__":
    main()
