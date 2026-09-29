from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib import request

from .parser import JockyParseError, parse, to_ir
from .runtime import execute


def post_json(url: str, payload: dict) -> str:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with request.urlopen(req, timeout=10) as response:
        return response.read().decode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="JOCKY defensive forensics CLI")
    parser.add_argument("source", type=Path)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--emit-ir", type=Path)
    parser.add_argument("--post")
    args = parser.parse_args()

    try:
        program = parse(args.source.read_text(encoding="utf-8"))
    except (OSError, JockyParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ir = to_ir(program)
    if args.emit_ir:
        args.emit_ir.write_text(json.dumps(ir, indent=2, sort_keys=True), encoding="utf-8")

    report = execute(ir)
    payload = json.dumps(report, indent=2 if args.pretty else None, sort_keys=True)

    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)

    if args.post:
        try:
            print(post_json(args.post, report), file=sys.stderr)
        except Exception as exc:
            print(f"post error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
