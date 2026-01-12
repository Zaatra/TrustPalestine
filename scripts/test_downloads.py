#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from allinone_it_config.app_registry import AppEntry, build_registry
from allinone_it_config.user_settings import SettingsStore, UserSettings
from services.installer import ConfiguredUrlDownloader, HPSADownloader, IVMSDownloader


DEFAULT_MIN_MB = 1.0
DEFAULT_TIMEOUT = 180
DEFAULT_POLL = 1.0


@dataclass(frozen=True)
class ProbeResult:
    label: str
    success: bool
    message: str
    bytes_seen: int = 0


def _safe_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name).lower()


def _is_64bit() -> bool:
    return sys.maxsize > 2**32


def _dir_size_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return total
    for entry in path.rglob("*"):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                continue
    return total


def _terminate_process(proc: subprocess.Popen[object]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return


def _find_winget_executable() -> Path | None:
    exe = shutil.which("winget")
    if exe:
        return Path(exe)
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        candidate = Path(local_appdata) / "Microsoft" / "WindowsApps" / "winget.exe"
        if candidate.exists():
            return candidate
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        base = Path(program_files) / "WindowsApps"
        try:
            candidates = base.glob("Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe/winget.exe")
        except OSError:
            candidates = []
        for candidate in candidates:
            if candidate.exists():
                return candidate
    return None


def _probe_winget_download(
    winget: Path,
    package_id: str,
    dest_dir: Path,
    *,
    min_bytes: int,
    timeout: int,
    poll_interval: float,
    locale: str | None = None,
    source: str | None = None,
    force: bool = False,
) -> ProbeResult:
    label = f"winget:{package_id}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    if not force:
        existing = _dir_size_bytes(dest_dir)
        if existing >= min_bytes:
            return ProbeResult(label, True, f"already have {existing} bytes", existing)
    cmd = [
        str(winget),
        "download",
        "--id",
        package_id,
        "--exact",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
        "--verbose",
        "-d",
        str(dest_dir),
    ]
    if locale:
        cmd.extend(["--locale", locale])
    if source:
        cmd.extend(["--source", source])
    proc = subprocess.Popen(cmd)
    start = time.monotonic()
    reached = False
    bytes_seen = 0
    while True:
        bytes_seen = _dir_size_bytes(dest_dir)
        if bytes_seen >= min_bytes:
            reached = True
            break
        if proc.poll() is not None:
            break
        if time.monotonic() - start > timeout:
            break
        time.sleep(poll_interval)
    if reached:
        _terminate_process(proc)
        return ProbeResult(label, True, f"reached {bytes_seen} bytes; stopping early", bytes_seen)
    if proc.poll() is None:
        _terminate_process(proc)
    bytes_seen = _dir_size_bytes(dest_dir)
    if bytes_seen >= min_bytes:
        return ProbeResult(label, True, f"reached {bytes_seen} bytes", bytes_seen)
    return ProbeResult(label, False, f"stopped at {bytes_seen} bytes", bytes_seen)


def _probe_direct_download(
    url: str,
    dest_path: Path,
    *,
    label: str | None = None,
    min_bytes: int,
    timeout: int,
    force: bool = False,
) -> ProbeResult:
    label = label or f"direct:{dest_path.name}"
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.exists() and not force:
        existing = dest_path.stat().st_size
        if existing >= min_bytes:
            return ProbeResult(label, True, f"already have {existing} bytes", existing)
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Range": f"bytes=0-{max(0, min_bytes - 1)}",
        },
    )
    start = time.monotonic()
    bytes_seen = 0
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            with dest_path.open("wb") as handle:
                while bytes_seen < min_bytes:
                    if time.monotonic() - start > timeout:
                        break
                    chunk = response.read(min(64 * 1024, min_bytes - bytes_seen))
                    if not chunk:
                        break
                    handle.write(chunk)
                    bytes_seen += len(chunk)
    except Exception as exc:
        return ProbeResult(label, False, f"download error: {exc}", bytes_seen)
    if bytes_seen >= min_bytes:
        return ProbeResult(label, True, f"reached {bytes_seen} bytes", bytes_seen)
    return ProbeResult(label, False, f"stopped at {bytes_seen} bytes", bytes_seen)


def _collect_installer_urls(payload: object, urls: list[str]) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key.lower() == "installerurl" and isinstance(value, str):
                urls.append(value)
            else:
                _collect_installer_urls(value, urls)
    elif isinstance(payload, list):
        for item in payload:
            _collect_installer_urls(item, urls)


def _winget_show_urls(
    winget: Path,
    package_id: str,
    *,
    source: str | None = None,
    locale: str | None = None,
) -> list[str]:
    base_cmd = [
        str(winget),
        "show",
        "--id",
        package_id,
        "--exact",
        "--accept-source-agreements",
    ]
    if locale:
        base_cmd.extend(["--locale", locale])
    if source:
        base_cmd.extend(["--source", source])
    json_cmd = base_cmd + ["--output", "json"]
    result = subprocess.run(json_cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=False)
    if result.returncode == 0 and result.stdout.strip():
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = None
        urls: list[str] = []
        if payload is not None:
            _collect_installer_urls(payload, urls)
        if urls:
            return urls
    result = subprocess.run(base_cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=False)
    if result.returncode != 0:
        return []
    return re.findall(r"Installer Url:\s*(https?://\S+)", result.stdout, flags=re.IGNORECASE)


def _winget_packages_for(app: AppEntry) -> list[str]:
    if app.dual_arch:
        ids: list[str] = []
        if app.winget_id_x86:
            ids.append(app.winget_id_x86)
        if _is_64bit() and app.winget_id_x64:
            ids.append(app.winget_id_x64)
        return ids
    if app.winget_id:
        return [app.winget_id]
    return []


def _direct_downloaders(settings: UserSettings) -> dict[str, object]:
    direct = {"iVMS-4200": IVMSDownloader(), "HP Support Asst": HPSADownloader()}
    if settings.crowdstrike_download_url.strip():
        direct["CrowdStrike Falcon Sensor"] = ConfiguredUrlDownloader(
            settings.crowdstrike_download_url.strip(),
            default_filename="crowdstrike_falcon_sensor.exe",
        )
    return direct


def _is_downloadable(app: AppEntry, direct: dict[str, object]) -> bool:
    if app.download_mode in {"localonly", "onlineonly"}:
        return False
    if app.download_mode == "direct":
        return app.name in direct
    if app.download_mode == "winget" and app.source and app.source != "winget":
        return False
    if app.download_mode == "office":
        return bool(app.winget_id)
    return True


def _filter_apps(apps: list[AppEntry], only: str | None) -> list[AppEntry]:
    if not only:
        return apps
    wanted = {name.strip().lower() for name in only.split(",") if name.strip()}
    return [app for app in apps if app.name.lower() in wanted]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe downloads for all registered apps, stopping after a minimum byte threshold."
    )
    parser.add_argument("--min-mb", type=float, default=DEFAULT_MIN_MB, help="Minimum MB to read before moving on.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout per package in seconds.")
    parser.add_argument("--poll", type=float, default=DEFAULT_POLL, help="Polling interval for winget size checks.")
    parser.add_argument("--only", help="Comma-separated list of app names to test.")
    parser.add_argument("--locale", help="Optional winget locale filter (ex: en-US).")
    parser.add_argument(
        "--mode",
        choices=["auto", "url", "winget"],
        default="auto",
        help="Probe mode: auto (prefer installer URL), url (force URL probe), winget (force winget download).",
    )
    parser.add_argument(
        "--probe-dir",
        default="downloads_probe",
        help="Directory for partial downloads (relative to repo root).",
    )
    parser.add_argument("--force", action="store_true", help="Ignore existing partials and re-probe.")
    args = parser.parse_args()

    min_bytes = max(1, int(args.min_mb * 1024 * 1024))
    winget = _find_winget_executable()
    if not winget:
        print("winget not found. Install winget or add it to PATH.")
        return 1

    settings = SettingsStore().load()
    registry = build_registry(settings)
    direct_downloaders = _direct_downloaders(settings)
    apps = _filter_apps(registry.entries, args.only)
    base_dir = ROOT / args.probe_dir
    base_dir.mkdir(parents=True, exist_ok=True)

    results: list[ProbeResult] = []
    for app in apps:
        if not _is_downloadable(app, direct_downloaders):
            results.append(ProbeResult(app.name, True, "skipped (not downloadable)"))
            continue
        print(f"\n== {app.name} ==")
        if app.download_mode in {"winget", "office"}:
            package_ids = _winget_packages_for(app)
            if not package_ids:
                results.append(ProbeResult(app.name, False, "missing winget id"))
                continue
            for package_id in package_ids:
                url_result: ProbeResult | None = None
                if args.mode in {"auto", "url"}:
                    urls = _winget_show_urls(winget, package_id, source=app.source, locale=args.locale)
                    if urls:
                        url = urls[0]
                        dest_path = base_dir / _safe_name(app.name) / _safe_name(package_id) / "installer.partial"
                        url_result = _probe_direct_download(
                            url,
                            dest_path,
                            label=f"winget:{package_id}",
                            min_bytes=min_bytes,
                            timeout=args.timeout,
                            force=args.force,
                        )
                        results.append(url_result)
                        print(f"{package_id}: {url_result.message}")
                    elif args.mode == "url":
                        url_result = ProbeResult(f"winget:{package_id}", False, "installer url not found")
                        results.append(url_result)
                        print(f"{package_id}: {url_result.message}")
                if url_result is None:
                    dest_dir = base_dir / _safe_name(app.name) / _safe_name(package_id)
                    result = _probe_winget_download(
                        winget,
                        package_id,
                        dest_dir,
                        min_bytes=min_bytes,
                        timeout=args.timeout,
                        poll_interval=args.poll,
                        locale=args.locale,
                        source=app.source,
                        force=args.force,
                    )
                    results.append(result)
                    print(f"{package_id}: {result.message}")
        elif app.download_mode == "direct":
            downloader = direct_downloaders.get(app.name)
            if not downloader:
                results.append(ProbeResult(app.name, False, "no direct downloader configured"))
                continue
            try:
                info = downloader.fetch()
            except Exception as exc:
                results.append(ProbeResult(app.name, False, f"fetch failed: {exc}"))
                continue
            filename = info.filename or f"{_safe_name(app.name)}_{_safe_name(info.version)}.exe"
            dest_path = base_dir / _safe_name(app.name) / f"{filename}.partial"
            result = _probe_direct_download(
                info.url,
                dest_path,
                min_bytes=min_bytes,
                timeout=args.timeout,
                force=args.force,
            )
            results.append(result)
            print(f"{info.url}: {result.message}")
        else:
            results.append(ProbeResult(app.name, True, f"skipped (mode={app.download_mode})"))

    success = sum(1 for result in results if result.success)
    failed = len(results) - success
    print("\n== Summary ==")
    print(f"Success: {success}  Failed: {failed}")
    for result in results:
        status = "OK" if result.success else "FAIL"
        print(f"{status} {result.label} -> {result.message}")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
