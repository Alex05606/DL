from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .features import parse_url, registered_domain


def _read_phishing_feed(path: Path) -> dict[str, str]:
    records: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            normalized, _ = parse_url(candidate)
            domain = registered_domain(normalized)
        except ValueError:
            continue
        if "." not in domain:
            continue
        records.setdefault(domain, normalized)
    if not records:
        raise ValueError(f"No valid phishing URLs found in feed: {path}")
    return records


def _read_tranco_domains(path: Path, limit: int) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"Tranco archive not found: {path}")
    with zipfile.ZipFile(path) as archive:
        csv_names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
        if not csv_names:
            raise ValueError(f"No CSV file found inside Tranco archive: {path}")
        with archive.open(csv_names[0]) as binary_file:
            reader = csv.reader(io.TextIOWrapper(binary_file, encoding="utf-8"))
            domains: list[str] = []
            seen: set[str] = set()
            for row in reader:
                if len(row) < 2:
                    continue
                candidate = row[1].strip().lower().rstrip(".")
                if not candidate:
                    continue
                try:
                    parse_url("https://" + candidate)
                    domain = registered_domain("https://" + candidate)
                except ValueError:
                    continue
                if domain != candidate or domain in seen:
                    continue
                seen.add(domain)
                domains.append(domain)
                if len(domains) >= limit:
                    break
    return domains


def prepare_dataset(
    phishing_feed: Path,
    tranco_archive: Path,
    output_path: Path,
    max_legitimate_ratio: int = 5,
    tranco_limit: int = 100_000,
) -> dict[str, int | str]:
    phishing = _read_phishing_feed(phishing_feed)
    legitimate_candidates = _read_tranco_domains(tranco_archive, tranco_limit)
    phishing_domains = set(phishing)
    legitimate_candidates = [
        domain for domain in legitimate_candidates if domain not in phishing_domains
    ]
    legitimate_count = min(
        len(legitimate_candidates),
        max(len(phishing) * max_legitimate_ratio, 500),
    )
    legitimate = legitimate_candidates[:legitimate_count]

    if not legitimate:
        raise ValueError("No non-overlapping Tranco domains were available.")

    captured_at = datetime.now(timezone.utc).isoformat()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file, fieldnames=["url", "label", "domain", "source", "observed_at"]
        )
        writer.writeheader()
        phishing_samples = 0
        legitimate_samples = 0
        for domain, url in sorted(phishing.items()):
            writer.writerow(
                {
                    "url": url,
                    "label": "phishing",
                    "domain": domain,
                    "source": "OpenPhish public feed",
                    "observed_at": captured_at,
                }
            )
            phishing_samples += 1
        for domain in legitimate:
            for url in (f"https://{domain}/", f"https://www.{domain}/"):
                writer.writerow(
                    {
                        "url": url,
                        "label": "legitimate",
                        "domain": domain,
                        "source": "Tranco top-sites ranking (weak label)",
                        "observed_at": captured_at,
                    }
                )
                legitimate_samples += 1

    result: dict[str, int | str] = {
        "output": str(output_path),
        "phishing_domains": len(phishing),
        "legitimate_domains": len(legitimate),
        "phishing_samples": phishing_samples,
        "legitimate_samples": legitimate_samples,
        "total_samples": phishing_samples + legitimate_samples,
        "captured_at": captured_at,
    }
    manifest = {
        "captured_at": captured_at,
        "sources": [
            {
                "name": "OpenPhish public feed",
                "url": "https://openphish.com/feed.txt",
                "path": str(phishing_feed),
                "sha256": hashlib.sha256(phishing_feed.read_bytes()).hexdigest(),
            },
            {
                "name": "Tranco top-sites list",
                "url": "https://tranco-list.eu/download/daily/top-1m.csv.zip",
                "path": str(tranco_archive),
                "sha256": hashlib.sha256(tranco_archive.read_bytes()).hexdigest(),
            },
        ],
        "dataset": result,
        "labeling_note": (
            "OpenPhish entries are phishing feed labels. Tranco entries are weak "
            "legitimate candidates, not verified benign URLs. Each Tranco domain is "
            "represented by both its apex and www HTTPS origin; neither is fetched."
        ),
    }
    manifest_path = output_path.parent / "source_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    result["manifest"] = str(manifest_path)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a labeled dataset from OpenPhish and Tranco files."
    )
    parser.add_argument("--phishing-feed", default="data/raw/openphish_feed.txt")
    parser.add_argument("--tranco-archive", default="data/raw/tranco_top1m.csv.zip")
    parser.add_argument("--output", default="data/real_urls.csv")
    parser.add_argument("--max-legitimate-ratio", type=int, default=5)
    parser.add_argument("--tranco-limit", type=int, default=100_000)
    args = parser.parse_args()
    if args.max_legitimate_ratio < 1:
        parser.error("--max-legitimate-ratio must be at least 1")
    result = prepare_dataset(
        Path(args.phishing_feed),
        Path(args.tranco_archive),
        Path(args.output),
        args.max_legitimate_ratio,
        args.tranco_limit,
    )
    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
