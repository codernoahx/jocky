from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any


class JockyParseError(ValueError):
    pass


@dataclass
class Program:
    version: str
    profile: str
    actions: list[dict[str, Any]]
    output: str = "json"


def _split(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=True)
    except ValueError as exc:
        raise JockyParseError(f"Invalid quoting: {exc}") from exc


def _kv(tokens: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise JockyParseError(f"Expected key=value, got: {token}")
        k, v = token.split("=", 1)
        result[k.strip()] = v.strip()
    return result


def parse(source: str) -> Program:
    version = None
    profile = "default"
    actions: list[dict[str, Any]] = []
    output = "json"

    for lineno, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        tokens = _split(line)
        head = tokens[0].lower()

        if head == "jocky":
            if len(tokens) != 2:
                raise JockyParseError(f"Line {lineno}: JOCKY requires a version")
            version = tokens[1]
        elif head == "profile":
            if len(tokens) != 2:
                raise JockyParseError(f"Line {lineno}: profile requires a name")
            profile = tokens[1]
        elif head == "collect":
            allowed = {"host", "users", "processes", "network", "services"}
            if len(tokens) != 2 or tokens[1] not in allowed:
                raise JockyParseError(f"Line {lineno}: unsupported collect target: {tokens[1:]}")
            actions.append({"op": "collect", "target": tokens[1]})
        elif head == "hash":
            if len(tokens) not in (2, 3):
                raise JockyParseError(f"Line {lineno}: hash <path> [sha256]")
            algorithm = tokens[2].lower() if len(tokens) == 3 else "sha256"
            if algorithm != "sha256":
                raise JockyParseError(f"Line {lineno}: only sha256 is supported")
            actions.append({"op": "hash", "path": tokens[1], "algorithm": algorithm})
        elif head == "scan_dir":
            if len(tokens) < 2:
                raise JockyParseError(f"Line {lineno}: scan_dir requires a path")
            options = _kv(tokens[2:]) if len(tokens) > 2 else {}
            try:
                max_depth = int(options.get("max_depth", "1"))
            except ValueError as exc:
                raise JockyParseError(f"Line {lineno}: max_depth must be an integer") from exc
            if max_depth < 0 or max_depth > 8:
                raise JockyParseError(f"Line {lineno}: max_depth must be between 0 and 8")
            actions.append({"op": "scan_dir", "path": tokens[1], "max_depth": max_depth})
        elif head == "output":
            if len(tokens) != 2 or tokens[1] != "json":
                raise JockyParseError(f"Line {lineno}: only output json is supported")
            output = "json"
        else:
            raise JockyParseError(f"Line {lineno}: unknown statement: {tokens[0]}")

    if version is None:
        raise JockyParseError("Missing 'JOCKY <version>' header")
    return Program(version=version, profile=profile, actions=actions, output=output)


def to_ir(program: Program) -> dict[str, Any]:
    return {
        "ir_version": "0.1",
        "language": "JOCKY",
        "language_version": program.version,
        "profile": program.profile,
        "actions": program.actions,
        "output": program.output,
    }
