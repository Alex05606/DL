# Training data

The project uses downloaded real-world source snapshots, not synthetic samples:

- `raw/openphish_feed.txt` — public OpenPhish phishing URL feed.
- `raw/tranco_top1m.csv.zip` — Tranco ranked domains, used as weak legitimate candidates.
- `real_urls.csv` — generated labeled dataset with source and collection-time columns.

Download and build the dataset from the project root:

```powershell
python -m phishguardz.fetch_data
python -m phishguardz.prepare_data
```

Tranco ranking is not a verified benign label: top-ranked domains can host harmful content or be compromised. Overlap with the phishing feed is excluded, but other labeling errors remain possible. Keep the downloaded source files and generated CSV with each model release so the model can be traced to its data snapshot.

For defensible future-threat evaluation, archive multiple dated phishing-feed snapshots and ensure later domains appear only in the test set. A current-feed snapshot alone cannot establish temporal or zero-day performance.
