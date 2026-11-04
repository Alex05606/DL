from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .model import PhishGuardModel


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train and evaluate PhishGuard-Z on real, labeled URL data."
    )
    parser.add_argument("--dataset", default="data/real_urls.csv")
    parser.add_argument("--output", default="models/phishguardz.joblib")
    parser.add_argument("--metrics-output", default="models/evaluation.json")
    args = parser.parse_args()

    model = PhishGuardModel(model_path=args.output)
    metrics = model.train(args.dataset)
    report: dict[str, Any] = {
        "model_path": str(Path(args.output)),
        "dataset_path": str(Path(args.dataset)),
        "dataset_sha256": hashlib.sha256(Path(args.dataset).read_bytes()).hexdigest(),
        "source_manifest_path": str(Path(args.dataset).parent / "source_manifest.json"),
        "model_metadata": model.metadata,
        "held_out_domain_metrics": metrics,
        "caveats": [
            "The test split is domain-disjoint but is not a temporal test.",
            "Tranco top-ranked domains are weak legitimate labels, not verified safety labels.",
            "OpenPhish coverage is a live-feed snapshot and does not represent every phishing family.",
        ],
    }
    report_path = Path(args.metrics_output)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
