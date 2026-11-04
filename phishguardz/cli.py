from __future__ import annotations

import argparse
import json
import os

from .model import PhishGuardModel


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a live URL with PhishGuard-Z")
    parser.add_argument("--url", required=True, help="The URL to evaluate")
    parser.add_argument("--model", default="models/phishguardz.joblib", help="Path to the trained model")
    parser.add_argument("--train-dataset", help="Optional dataset path if the model file does not exist yet")
    args = parser.parse_args()

    if not os.path.exists(args.model):
        if not args.train_dataset:
            raise FileNotFoundError(
                "Model file does not exist and no --train-dataset was supplied. "
                "Train the model first with: python -m phishguardz.train --dataset data/real_urls.csv"
            )
        from .model import train_and_save
        train_and_save(args.train_dataset, args.model)

    model = PhishGuardModel.load(args.model)
    result = model.score_url(args.url)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
