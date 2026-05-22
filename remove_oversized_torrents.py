#!/usr/bin/env python3
"""Remove unsafe, ingested, or impossible-to-fit Deluge torrents.

This script is designed to be safe to run every minute from cron. It discovers
the active Deluge download path at runtime, so burst mode can move downloads to
a temporary volume without causing false "not enough space" removals.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

try:
    from deluge_client import DelugeRPCClient
except ImportError as exc:  # pragma: no cover - deployment guard
    raise SystemExit(
        "Missing Python package deluge_client. Install the same package used by "
        "the existing cron job, usually with: python3 -m pip install deluge-client"
    ) from exc


DELUGE_HOST = os.environ.get("DELUGE_HOST", "127.0.0.1")
DELUGE_PORT = int(os.environ.get("DELUGE_PORT", "58846"))
DELUGE_CONFIG_DIR = Path(os.environ.get("DELUGE_CONFIG_DIR", "/var/lib/deluged/config"))
DEFAULT_DOWNLOAD_PATH = Path(os.environ.get("DELUGE_DOWNLOAD_PATH", "/srv/deluge/Downloads"))

BLOCKED_EXTENSIONS = tuple(
    ext.strip().lower()
    for ext in os.environ.get("DELUGE_BLOCKED_EXTENSIONS", ".scr,.rar,.exe,.arj").split(",")
    if ext.strip()
)
INGESTED_LABELS = {
    label.strip().lower()
    for label in os.environ.get("DELUGE_INGESTED_LABELS", "ingested").split(",")
    if label.strip()
}
MIN_FREE_GB = float(os.environ.get("DELUGE_MIN_FREE_GB", "0"))
MIN_FREE_BYTES = int(MIN_FREE_GB * 1024**3)


def normalize(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {normalize(key): normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, tuple):
        return tuple(normalize(item) for item in value)
    return value


def load_localclient_auth(config_dir: Path) -> tuple[str, str]:
    auth_path = config_dir / "auth"
    try:
        lines = auth_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SystemExit(f"Unable to read Deluge auth file {auth_path}: {exc}") from exc

    fallback: tuple[str, str] | None = None
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.rstrip("\n").split(":")
        if len(parts) < 2:
            continue
        user, password = parts[0], parts[1]
        if not user or not password:
            continue
        if fallback is None:
            fallback = (user, password)
        if user == "localclient":
            return user, password

    if fallback is not None:
        return fallback

    raise SystemExit(f"No usable credentials found in {auth_path}")


def get_available_space(path: Path) -> int:
    existing = path
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    statvfs = os.statvfs(existing)
    return max(0, statvfs.f_bavail * statvfs.f_frsize - MIN_FREE_BYTES)


def connect_client() -> DelugeRPCClient:
    user, password = load_localclient_auth(DELUGE_CONFIG_DIR)
    client = DelugeRPCClient(DELUGE_HOST, DELUGE_PORT, user, password)
    client.connect()
    return client


def active_download_path(client: DelugeRPCClient) -> Path:
    try:
        config = normalize(client.call("core.get_config"))
    except Exception as exc:
        print(f"WARN: unable to read Deluge config over RPC: {exc}", file=sys.stderr)
        return DEFAULT_DOWNLOAD_PATH

    configured = config.get("download_location") if isinstance(config, dict) else None
    if isinstance(configured, str) and configured.strip():
        return Path(configured)
    return DEFAULT_DOWNLOAD_PATH


def has_blocked_extension(files: list[Any]) -> str | None:
    for file_info in files:
        normalized = normalize(file_info)
        if not isinstance(normalized, dict):
            continue
        file_path = str(normalized.get("path", ""))
        if file_path.lower().endswith(BLOCKED_EXTENSIONS):
            return file_path
    return None


def remaining_bytes(torrent: dict[str, Any]) -> int:
    total_size = int(torrent.get("total_size") or 0)
    progress = float(torrent.get("progress") or 0.0)
    progress = min(max(progress, 0.0), 100.0)
    return int(total_size * (1.0 - (progress / 100.0)))


def torrent_download_path(torrent: dict[str, Any], default_path: Path) -> Path:
    path = torrent.get("download_location")
    if isinstance(path, str) and path.strip():
        return Path(path)
    return default_path


def remove_torrent(client: DelugeRPCClient, torrent_id: str, reason: str, name: str) -> None:
    print(f"Removing torrent: {name} ({torrent_id}) - {reason}")
    client.call("core.remove_torrent", torrent_id, True)


def main() -> int:
    client = connect_client()
    default_path = active_download_path(client)

    torrents = normalize(
        client.call(
            "core.get_torrents_status",
            {},
            [
                "name",
                "total_size",
                "progress",
                "files",
                "label",
                "download_location",
            ],
        )
    )

    if not isinstance(torrents, dict):
        raise SystemExit("Unexpected Deluge response for core.get_torrents_status")

    removed = 0
    checked = 0

    for torrent_id, raw_data in torrents.items():
        torrent_id = str(torrent_id)
        data = normalize(raw_data)
        if not isinstance(data, dict):
            print(f"WARN: skipping malformed torrent data for {torrent_id}", file=sys.stderr)
            continue

        checked += 1
        name = str(data.get("name") or torrent_id)
        label = str(data.get("label") or "").strip().lower()

        if label in INGESTED_LABELS:
            remove_torrent(client, torrent_id, f"label={label}", name)
            removed += 1
            continue

        blocked_file = has_blocked_extension(data.get("files") or [])
        if blocked_file is not None:
            remove_torrent(client, torrent_id, f"blocked file extension in {blocked_file}", name)
            removed += 1
            continue

        remaining = remaining_bytes(data)
        if remaining <= 0:
            continue

        download_path = torrent_download_path(data, default_path)
        available = get_available_space(download_path)
        if remaining > available:
            remaining_gb = remaining / 1024**3
            available_gb = available / 1024**3
            remove_torrent(
                client,
                torrent_id,
                f"remaining {remaining_gb:.2f} GB exceeds available {available_gb:.2f} GB at {download_path}",
                name,
            )
            removed += 1

    print(f"Checked {checked} torrent(s); removed {removed}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
