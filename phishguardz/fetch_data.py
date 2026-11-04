from __future__ import annotations

import argparse
import urllib.request
from pathlib import Path

SOURCES = {
    "openphish": "https://openphish.com/feed.txt",
    "tranco": "https://tranco-list.eu/download/daily/top-1m.csv.zip",
}


def download(source: str, output: Path) -> None:
    request = urllib.request.Request(
        SOURCES[source],
        headers={"User-Agent": "PhishGuard-Z research dataset fetcher"},
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(request, timeout=90) as response:
        content = response.read()
    if not content:
        raise RuntimeError(f"The {source} data source returned an empty response.")
    output.write_bytes(content)
    print(f"{source}: saved {len(content)} bytes to {output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download public real-world URL/domain datasets."
    )
    parser.add_argument("--output-dir", default="data/raw")
    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    download("openphish", output_dir / "openphish_feed.txt")
    download("tranco", output_dir / "tranco_top1m.csv.zip")


if __name__ == "__main__":
    main()
