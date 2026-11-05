# Training data

The project uses downloaded real-world source snapshots, not synthetic samples:

- `raw/openphish_feed.txt` — public OpenPhish phishing URL feed.
- `raw/tranco_top1m.csv.zip` — Tranco ranked domains, used as weak legitimate candidates.
- `real_urls.csv` — generated labeled dataset with source and collection-time columns.

The source snapshots and generated CSV are included in the repository, so
teammates do not need to download or rebuild the dataset to run the included
model. To refresh the data from the project root:

```powershell
python -m phishguardz.fetch_data
python -m phishguardz.prepare_data
```

Each Tranco domain produces two weakly labeled examples (the apex and `www` HTTPS origins) because the source contains domains, not URLs. Neither URL is fetched, and both are kept together when splitting data by registered domain.

Tranco ranking is not a verified benign label: top-ranked domains can host harmful content or be compromised. Overlap with the phishing feed is excluded, but other labeling errors remain possible. Keep the downloaded source files and generated CSV with each model release so the model can be traced to its data snapshot.

For defensible future-threat evaluation, archive multiple dated phishing-feed snapshots and ensure later domains appear only in the test set. A current-feed snapshot alone cannot establish temporal or zero-day performance.
