from __future__ import annotations

import hashlib
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def collect_host() -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "boot_time": datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat(),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "memory_total": psutil.virtual_memory().total,
    }


def collect_users() -> list[dict[str, Any]]:
    rows = []
    for user in psutil.users():
        rows.append({
            "name": user.name,
            "terminal": user.terminal,
            "host": user.host,
            "started": datetime.fromtimestamp(user.started, tz=timezone.utc).isoformat() if user.started else None,
        })
    return rows


def collect_processes() -> list[dict[str, Any]]:
    rows = []
    for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "username", "create_time", "exe", "cmdline"]):
        try:
            info = proc.info
            rows.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "create_time": datetime.fromtimestamp(info["create_time"], tz=timezone.utc).isoformat() if info.get("create_time") else None,
                "exe": info.get("exe"),
                "cmdline": info.get("cmdline"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return rows


def collect_network() -> list[dict[str, Any]]:
    rows = []
    for conn in psutil.net_connections(kind="inet"):
        rows.append({
            "fd": conn.fd,
            "family": str(conn.family),
            "type": str(conn.type),
            "status": conn.status,
            "pid": conn.pid,
            "local": {"ip": conn.laddr.ip, "port": conn.laddr.port} if conn.laddr else None,
            "remote": {"ip": conn.raddr.ip, "port": conn.raddr.port} if conn.raddr else None,
        })
    return rows


def collect_services() -> list[dict[str, Any]]:
    if not hasattr(psutil, "win_service_iter"):
        return [{"supported": False, "message": "Service enumeration is implemented only for Windows in this prototype."}]
    rows = []
    try:
        for svc in psutil.win_service_iter():
            try:
                rows.append({
                    "name": svc.name(),
                    "display_name": svc.display_name(),
                    "status": svc.status(),
                    "start_type": svc.start_type(),
                    "username": svc.username(),
                    "pid": svc.pid(),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as exc:
        return [{"supported": False, "message": f"{type(exc).__name__}: {exc}"}]
    return rows


def sha256_file(path: str) -> dict[str, Any]:
    p = Path(path)
    result: dict[str, Any] = {"path": str(p), "algorithm": "sha256"}
    try:
        stat = p.stat()
    except OSError as exc:
        result.update({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return result
    if not p.is_file():
        result.update({"ok": False, "error": "Path is not a regular file"})
        return result
    digest = hashlib.sha256()
    try:
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        result.update({
            "ok": True,
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "sha256": digest.hexdigest(),
        })
    except OSError as exc:
        result.update({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    return result


def scan_dir(path: str, max_depth: int) -> dict[str, Any]:
    root = Path(path)
    result = {"path": str(root), "max_depth": max_depth, "ok": False, "files": [], "errors": []}
    if not root.exists():
        result["errors"].append("Path does not exist")
        return result
    if not root.is_dir():
        result["errors"].append("Path is not a directory")
        return result

    root_parts = len(root.resolve().parts)
    try:
        for current, dirs, files in os.walk(root):
            current_path = Path(current)
            depth = len(current_path.resolve().parts) - root_parts
            if depth >= max_depth:
                dirs[:] = []
            for name in files:
                file_path = current_path / name
                try:
                    stat = file_path.stat()
                    item = {
                        "path": str(file_path),
                        "size": stat.st_size,
                        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    }
                    item.update(sha256_file(str(file_path)))
                    result["files"].append(item)
                except OSError as exc:
                    result["errors"].append(f"{file_path}: {type(exc).__name__}: {exc}")
        result["ok"] = True
    except OSError as exc:
        result["errors"].append(f"{type(exc).__name__}: {exc}")
    return result


def execute(ir: dict[str, Any]) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "jocky-forensic-report/0.1",
        "generated_at": utc_now(),
        "language": ir.get("language", "JOCKY"),
        "profile": ir.get("profile", "default"),
        "host": {}, "users": [], "processes": [], "network": [], "services": [],
        "hashes": [], "directory_scans": [], "errors": [],
    }

    for action in ir.get("actions", []):
        try:
            if action["op"] == "collect":
                target = action["target"]
                if target == "host": report["host"] = collect_host()
                elif target == "users": report["users"] = collect_users()
                elif target == "processes": report["processes"] = collect_processes()
                elif target == "network": report["network"] = collect_network()
                elif target == "services": report["services"] = collect_services()
            elif action["op"] == "hash":
                report["hashes"].append(sha256_file(action["path"]))
            elif action["op"] == "scan_dir":
                report["directory_scans"].append(scan_dir(action["path"], int(action["max_depth"])))
            else:
                report["errors"].append(f"Unsupported operation: {action.get('op')}")
        except Exception as exc:
            report["errors"].append(f"{type(exc).__name__}: {exc}")
    return report
