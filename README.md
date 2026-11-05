# PhishGuard-Z

PhishGuard-Z scores a URL before visiting it. It combines character n-gram patterns and lexical URL features with a calibrated classifier and an out-of-distribution (OOD) indicator. Inference does not open the URL, perform DNS lookups, or make TLS connections.

## What this model is trained on

The training pipeline fetches:

- **OpenPhish public feed** for currently reported phishing URLs.
- **Tranco top-sites list** for legitimate-domain candidates. These are weak labels: a highly ranked domain is not guaranteed harmless, and this source is not equivalent to a verified benign URL feed.

The dataset builder removes domains present in both sources and records the source and collection time. Tranco supplies domains rather than full URLs, so each candidate is represented by its apex and `www` HTTPS origins; the builder does not fetch or verify either page. These are real ranked domains but weakly labeled URLs, not a verified benign browsing corpus. Source checksums are saved in `data/source_manifest.json`; source files are saved under `data/raw/`; the generated dataset is `data/real_urls.csv`. Both URL variants stay in the same registered-domain split during training and evaluation.

## Quick start

The repository includes the training dataset, its source snapshots, the trained
model, and a built frontend. To run the app locally, install the Python
requirements and start it:

```powershell
python -m pip install -r requirements.txt
python main.py
```

## Train the model

Retraining is optional. The following steps rebuild the model from the included
data:

From this directory:

```powershell
python -m pip install -r requirements.txt
python -m phishguardz.fetch_data
python -m phishguardz.prepare_data
python -m phishguardz.train
```

Outputs:

- `models/phishguardz.joblib` — trained classifier, calibration model, and OOD reference.
- `models/evaluation.json` — metrics from a domain-disjoint held-out test split and data caveats.

To select a smaller legitimate-domain pool:

```powershell
python -m phishguardz.prepare_data --tranco-limit 20000 --max-legitimate-ratio 3
```

To train from a separately collected real dataset, provide a CSV with `url` and `label` columns. Labels may be `phishing`/`legitimate` or `1`/`0`:

```powershell
python -m phishguardz.train --dataset data/your_real_dataset.csv
```

Training fails explicitly if there are too few unique domains or either class is absent from a split.

## Score a URL

```powershell
python -m phishguardz.cli --url https://example.org --model models/phishguardz.joblib
```

The output includes phishing probability, model confidence, a risk level, an OOD score, and lexical indicators. Treat high OOD scores as a warning that model scores may be unreliable. Model confidence is not a guarantee or a substitute for threat intelligence.

## Start the full app

From the project directory, run:

```powershell
python main.py
```

`main.py` checks for the trained model, uses the included React frontend bundle, starts FastAPI, and opens the site in your browser. If you have frontend dependencies installed and its source is newer than the bundle, it rebuilds the frontend. Press `Ctrl+C` in the terminal to stop it. If port 8000 is occupied, it tries ports 8001 through 8010. You can choose a port explicitly with `$env:PHISHGUARD_PORT=8012`.

The React source is in `web/src/`; its built production bundle is included in `phishguardz/static/`. To rebuild or develop the frontend, install dependencies with `npm ci` and run `npm run build`.

The website shows risk probability, model confidence, novelty, URL-structure checks, and recent checks stored only in that browser. The analysis reports visible signals such as URL length, scheme, suspicious words, and domain formatting. It uses URL text only: it does not resolve DNS or visit the submitted destination, and the listed checks are not a feature-by-feature explanation of the model's prediction.

The web app is served by the same API process, so `/score` and the website share one origin. Set `PHISHGUARD_MODEL` to use a model file at a different path.

For frontend development with hot reload, run the backend and Vite dev server in separate terminals. Vite proxies `/health` and `/score` to the backend:

```powershell
python main.py
```

In another terminal:

```powershell
npm ci
npm run dev
```

Then open [http://127.0.0.1:5173](http://127.0.0.1:5173).

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/score `
  -ContentType 'application/json' -Body '{"url":"https://example.org"}'
```

Keep the server bound to localhost unless it is protected by authentication, rate limiting, and appropriate network controls. A public deployment should add those controls and HTTPS before exposing this service.

## Evaluation limitations

The pipeline uses stratified registered-domain-disjoint training, calibration, and test partitions, so domains do not leak across partitions. The reported test metrics estimate generalization to held-out domains from these source snapshots; they do not establish future/zero-day performance. Proper temporal evaluation requires archived threat feeds collected over time. Tranco is a weak benign label source; the generated origin URLs are not confirmed live or benign. OpenPhish is not exhaustive. Do not use this model as the sole security control.
