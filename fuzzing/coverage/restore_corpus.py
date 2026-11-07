#!/usr/bin/env python3
"""Restore verified DNS fuzz input artifacts from a successful earlier campaign.

Never treats previously discovered mutation inputs as reviewed regressions.
Only same-repository, successful workflow runs on the named branch are eligible.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

SHA_FILE = re.compile(r"([0-9a-f]{64})\.bin")
MAX_SAMPLE = 65535
MAX_ARCHIVE = 20 * 1024 * 1024


def choose_samples(archive: bytes, limit: int) -> list[tuple[str, bytes]]:
    if limit < 0:
        raise ValueError("limit must be nonnegative")
    with zipfile.ZipFile(io.BytesIO(archive)) as files:
        names = sorted(name for name in files.namelist() if SHA_FILE.fullmatch(name))
        if len(names) > limit and limit:
            names = [names[i * len(names) // limit] for i in range(limit)]
        elif not limit:
            names = []
        selected = []
        for name in names:
            info = files.getinfo(name)
            if info.file_size > MAX_SAMPLE or info.file_size == 0:
                continue
            data = files.read(info)
            if hashlib.sha256(data).hexdigest() != name[:-4]:
                raise ValueError(f"Corrupted content-addressed input: {name}")
            selected.append((name, data))
        return selected


def request_json(url: str, token: str) -> dict:
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                      "User-Agent": "technitium-fuzz-corpus"})
    with urllib.request.urlopen(request, timeout=15) as result:
        return json.load(result)


def download_archive(url: str, token: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                      "User-Agent": "technitium-fuzz-corpus"})
    with urllib.request.urlopen(request, timeout=30) as result:
        body = result.read(MAX_ARCHIVE + 1)
    if len(body) > MAX_ARCHIVE:
        raise ValueError("Previous artifact exceeded size budget")
    return body


def restore(repo: str, branch: str, workflow: str, target: str, folder: Path,
            token: str, limit: int = 150) -> dict:
    folder.mkdir(parents=True, exist_ok=True)
    if not token:
        return {"status": "unavailable", "imported": 0, "reason": "no GitHub token"}
    path = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow}/runs"
    query = urllib.parse.urlencode({"branch": branch, "status": "success", "per_page": 15})
    runs = request_json(f"{path}?{query}", token).get("workflow_runs", [])
    for run in runs:
        if run.get("head_repository", {}).get("full_name", "").lower() != repo.lower():
            continue
        rid = run["id"]
        listing = request_json(
            f"https://api.github.com/repos/{repo}/actions/runs/{rid}/artifacts", token)
        name = f"dns-{target}-corpus-{rid}"
        artifact = next((a for a in listing.get("artifacts", [])
                         if a["name"] == name and not a.get("expired")), None)
        if artifact is None:
            continue
        samples = choose_samples(download_archive(artifact["archive_download_url"], token),
                                 limit)
        count = 0
        for digest_name, data in samples:
            dest = folder / ("persist-" + digest_name[:-4])
            if not dest.exists():
                dest.write_bytes(data)
                count += 1
        return {"status": "restored", "source_run": rid, "imported": count}
    return {"status": "no_previous_corpus", "imported": 0}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=150)
    args = parser.parse_args()
    try:
        result = restore(args.repository, args.branch, args.workflow, args.target,
                         args.output, os.environ.get("GITHUB_TOKEN", ""), args.limit)
    except (urllib.error.URLError, TimeoutError) as exc:
        result = {"status": "api_unavailable", "imported": 0, "reason": str(exc)}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
