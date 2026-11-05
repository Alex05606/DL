import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const HISTORY_KEY = "phishguardz-recent-checks";
const EXAMPLES = [
  { label: "google.com", url: "https://www.google.com/" },
  { label: "microsoft.com", url: "https://www.microsoft.com/" },
  { label: "feed-listed threat", url: "http://explorer.beta.bip300.xyz/" },
];
const PHASES = [
  "Parsing address structure…",
  "Checking learned URL patterns…",
  "Estimating novelty and risk…",
];

function readHistory() {
  try {
    const saved = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(saved)
      ? saved.filter((item) => item && typeof item.url === "string")
      : [];
  } catch {
    return [];
  }
}

function normalizeInput(value) {
  const trimmed = value.trim();
  if (!trimmed) throw new Error("Paste a URL to check.");

  const normalized = /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("That doesn't look like a valid web address. Check it and try again.");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    !parsed.hostname ||
    /\s/.test(parsed.hostname)
  ) {
    throw new Error("Enter a valid HTTP or HTTPS web address.");
  }
  return normalized;
}

function clampPercentage(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(1, number)) : 0;
}

function riskDescription(level, probability, isOod, novelty) {
  if (isOod || novelty >= 0.85) {
    return "This URL differs from many training patterns, so the model's probability may be less reliable.";
  }
  if (level === "CRITICAL" || level === "HIGH") {
    return "The model found URL patterns commonly associated with phishing. Avoid opening this link.";
  }
  if (level === "MEDIUM") {
    return "Some URL patterns look unusual. Verify the sender and destination before proceeding.";
  }
  if (probability > 0.15) {
    return "The model found limited risk signals, but this result cannot guarantee the link is safe.";
  }
  return "No strong phishing pattern was detected in the URL. This does not guarantee that the destination is safe.";
}

function ShieldMark() {
  return (
    <svg viewBox="0 0 40 44" fill="none" aria-hidden="true">
      <path
        d="M20 2.5 35 8v11.2c0 10.1-6.1 17.1-15 22.3C11.1 36.3 5 29.3 5 19.2V8L20 2.5Z"
        stroke="currentColor"
        strokeWidth="2.2"
      />
      <path
        d="m13.5 21.3 4.2 4.1 9.2-9.2"
        stroke="currentColor"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function SearchMark() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="10.8" cy="10.8" r="6.8" stroke="currentColor" strokeWidth="1.7" />
      <path
        d="m16 16 4.5 4.5M10.8 7.5v6.6M7.5 10.8h6.6"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
    </svg>
  );
}

function Header({ modelState }) {
  return (
    <header className="topbar">
      <a className="brand" href="/" aria-label="PhishGuard-Z home">
        <span className="brand-mark">
          <ShieldMark />
        </span>
        <span className="brand-copy">
          <span className="brand-name">
            PhishGuard<span>-Z</span>
          </span>
          <small>URL INTELLIGENCE</small>
        </span>
      </a>
      <div className="topbar-right">
        <span className={`live-status ${modelState}`}>
          <i />
          <span>
            {modelState === "ready"
              ? "Model ready"
              : modelState === "error"
                ? "Model unavailable"
                : "Checking model"}
          </span>
        </span>
        <a className="nav-link" href="#how-it-works">
          How it works
        </a>
      </div>
    </header>
  );
}

function Scanner({ onScan, busy }) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const inputRef = useRef(null);

  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      await onScan(normalizeInput(url));
    } catch (scanError) {
      setError(scanError.message);
      inputRef.current?.focus();
    }
  }

  function chooseExample(exampleUrl) {
    setUrl(exampleUrl);
    setError("");
    onScan(exampleUrl);
  }

  return (
    <div className="scanner-card">
      <div className="card-topline">
        <div>
          <span className="section-kicker">LINK CHECKER</span>
          <h2>Analyze a URL</h2>
        </div>
        <span className="scan-icon">
          <SearchMark />
        </span>
      </div>
      <form
        noValidate
        onSubmit={submit}
      >
        <label htmlFor="url-input">Paste a link to check</label>
        <div className="input-shell">
          <input
            ref={inputRef}
            id="url-input"
            name="url"
            type="text"
            inputMode="url"
            autoComplete="url"
            placeholder="https://example.com/login"
            maxLength={2048}
            aria-describedby="input-help scan-error"
            aria-invalid={Boolean(error)}
            value={url}
            onChange={(event) => {
              setUrl(event.target.value);
              if (error) setError("");
            }}
            onKeyDown={(event) => {
              if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                event.currentTarget.form?.requestSubmit();
              }
            }}
          />
          {url.length > 0 && (
            <button
              className="clear-button"
              type="button"
              aria-label="Clear URL"
              onClick={() => {
                setUrl("");
                setError("");
                inputRef.current?.focus();
              }}
            >
              ×
            </button>
          )}
        </div>
        <div className="input-meta">
          <span id="input-help">The page will not be opened.</span>
          <span>{url.length} / 2048</span>
        </div>
        <button className="primary-button" type="submit" disabled={busy}>
          <span className="button-label">{busy ? "Checking link…" : "Check link"}</span>
        </button>
        {error && <p id="scan-error" className="error-message" role="alert">{error}</p>}
      </form>
      <div className="examples">
        <span>TRY AN EXAMPLE</span>
        {EXAMPLES.map((example) => (
          <button
            key={example.label}
            type="button"
            className="example-chip"
            onClick={() => chooseExample(example.url)}
            disabled={busy}
          >
            {example.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function Hero({ onScan, busy }) {
  return (
    <section className="hero">
      <div className="hero-copy">
        <div className="eyebrow">
          <span className="eyebrow-line" />
          PRE-VISIT URL PROTECTION
        </div>
        <h1>
          Know before
          <br />
          you <span>click.</span>
        </h1>
        <p className="hero-description">
          A suspicious link can look convincing. Check its risk before the page loads —
          PhishGuard-Z reads the URL, not the website.
        </p>
        <div className="trust-row">
          <span><b className="trust-icon">✓</b> No page visit</span>
          <span><b className="trust-icon">◈</b> Domain-aware model</span>
          <span><b className="trust-icon">◎</b> Novelty signal</span>
        </div>
      </div>
      <Scanner onScan={onScan} busy={busy} />
    </section>
  );
}

function ProgressCard({ phase }) {
  return (
    <section className="progress-card" aria-live="polite">
      <div className="scan-orbit" aria-hidden="true"><span /></div>
      <div className="progress-copy">
        <strong>Inspecting URL patterns</strong>
        <span>{PHASES[phase]}</span>
      </div>
      <div className="progress-track"><span /></div>
    </section>
  );
}

function ResultSection({ data, onNewCheck, onToast }) {
  const probability = clampPercentage(data.phishing_probability);
  const confidence = clampPercentage(data.model_confidence);
  const novelty = clampPercentage(data.ood_score);
  const level = String(data.risk_level || "UNKNOWN").toUpperCase();
  const isOod = Boolean(data.is_ood);
  const indicators = Array.isArray(data.indicators) && data.indicators.length
    ? data.indicators
    : ["No lexical indicators returned"];
  const analysis = Array.isArray(data.analysis) ? data.analysis : [];
  const gaugeColor = ["CRITICAL", "HIGH"].includes(level)
    ? "var(--danger)"
    : level === "MEDIUM"
      ? "var(--warning)"
      : "var(--cyan)";
  const noveltyLabel = isOod ? "Unfamiliar" : novelty >= 0.85 ? "Elevated" : "In range";

  async function copyUrl() {
    try {
      await navigator.clipboard.writeText(data.url || "");
      onToast("URL copied to clipboard.");
    } catch {
      onToast("Clipboard access is unavailable in this browser.");
    }
  }

  return (
    <section className="result-section" aria-live="polite">
      <div className="result-heading">
        <div>
          <span className="section-kicker">ANALYSIS COMPLETE</span>
          <h2>Your link report</h2>
        </div>
        <button className="secondary-button" type="button" onClick={onNewCheck}>
          Check another
        </button>
      </div>
      <div className={`result-card risk-${level.toLowerCase()}`}>
        <div className="result-main">
          <div className="risk-indicator">
            <div
              className="risk-gauge"
              style={{
                "--score": `${(probability * 100).toFixed(1)}%`,
                "--gauge-color": gaugeColor,
              }}
            >
              <div className="gauge-inner">
                <span>{Math.round(probability * 100)}%</span>
                <small>RISK SCORE</small>
              </div>
            </div>
          </div>
          <div className="result-summary">
            <span className={`risk-pill ${level.toLowerCase()}`}>{level} RISK</span>
            <h3>
              {level === "LOW"
                ? "No strong risk detected"
                : level === "MEDIUM"
                  ? "Use extra caution"
                  : "Potential phishing risk"}
            </h3>
            <p className="result-domain">{data.url}</p>
            <p className="result-message">
              {riskDescription(level, probability, isOod, novelty)}
            </p>
          </div>
        </div>
        <div className="result-metrics">
          <article className="metric-card">
            <span>Model confidence</span>
            <strong>{Math.round(confidence * 100)}%</strong>
            <small>Model certainty, not a safety guarantee</small>
          </article>
          <article className="metric-card">
            <span>Novelty signal</span>
            <strong className={isOod || novelty >= 0.85 ? "ood-flag" : ""}>{noveltyLabel}</strong>
            <small>Novelty score: {Math.round(novelty * 100)} / 100</small>
          </article>
          <article className="metric-card">
            <span>Risk category</span>
            <strong>{level}</strong>
            <small>Based on predicted phishing probability</small>
          </article>
        </div>
        <div className="signals-block">
          <div className="signals-heading">
            <div>
              <span className="section-kicker">DETAILS BEHIND THE CHECK</span>
              <h3>URL analysis</h3>
            </div>
            <span className="signals-note">URL text only · no DNS lookup</span>
          </div>
          {analysis.length > 0 ? (
            <ul className="analysis-list">
              {analysis.map((signal, index) => (
                <li className={`analysis-item analysis-${signal.status}`} key={`${signal.title}-${index}`}>
                  <span className="analysis-status" aria-hidden="true" />
                  <span className="analysis-copy">
                    <strong>{signal.title}</strong>
                    <span>{signal.detail}</span>
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <ul className="indicator-list">
              {indicators.map((indicator, index) => <li key={`${indicator}-${index}`}>{indicator}</li>)}
            </ul>
          )}
          <p className="analysis-note">
            These checks describe URL features that may be relevant; they are not a breakdown of the model's individual decision.
          </p>
        </div>
        <div className="checked-url">
          <span>CHECKED URL</span>
          <code>{data.url}</code>
          <button type="button" onClick={copyUrl}>Copy</button>
        </div>
      </div>
      <p className="result-disclaimer">
        A low score does not guarantee a link is safe. This model uses a limited snapshot
        of threat data; verify unexpected links through trusted channels.
      </p>
    </section>
  );
}

function HistorySection({ history, onClear, onSelect }) {
  if (history.length === 0) return null;
  return (
    <section className="history-section">
      <div className="history-heading">
        <div>
          <span className="section-kicker">THIS BROWSER</span>
          <h2>Recent checks</h2>
        </div>
        <button className="text-button" type="button" onClick={onClear}>Clear history</button>
      </div>
      <div className="history-list">
        {history.map((item) => (
          <button
            key={item.url}
            className="history-item"
            type="button"
            title="Check this URL again"
            onClick={() => onSelect(item.url)}
          >
            <span className={`history-dot ${String(item.risk || "").toLowerCase()}`} />
            <span className="history-url">{item.url}</span>
            <span className="history-risk">
              {String(item.risk || "UNKNOWN")} · {Math.round((Number(item.probability) || 0) * 100)}%
            </span>
          </button>
        ))}
      </div>
      <p className="history-note">Recent URLs are stored only in this browser.</p>
    </section>
  );
}

function HowItWorks() {
  return (
    <section id="how-it-works" className="how-section">
      <div className="how-heading">
        <span className="section-kicker">BUILT FOR THE UNKNOWN</span>
        <h2>Look at the link.<br /><span>Not the landing page.</span></h2>
      </div>
      <div className="how-grid">
        <article className="how-card">
          <span className="how-number">01</span>
          <div className="how-icon" aria-hidden="true">⌁</div>
          <h3>Read the URL</h3>
          <p>Character patterns and URL structure are analyzed without loading the destination or contacting its host.</p>
        </article>
        <article className="how-card">
          <span className="how-number">02</span>
          <div className="how-icon" aria-hidden="true">◉</div>
          <h3>Look beyond familiar domains</h3>
          <p>The model learns URL patterns and is evaluated with domains kept separate between training and testing.</p>
        </article>
        <article className="how-card">
          <span className="how-number">03</span>
          <div className="how-icon" aria-hidden="true">⌖</div>
          <h3>Flag unfamiliar patterns</h3>
          <p>A novelty signal can warn when a URL differs from the training feature distribution.</p>
        </article>
      </div>
    </section>
  );
}

function App() {
  const [modelState, setModelState] = useState("checking");
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState(0);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState(readHistory);
  const [toast, setToast] = useState("");
  const timerRef = useRef(null);
  const resultRef = useRef(null);

  useEffect(() => {
    fetch("/health")
      .then((response) => {
        if (!response.ok) throw new Error("Model unavailable");
        return response.json();
      })
      .then((health) => setModelState(health.model_loaded ? "ready" : "error"))
      .catch(() => setModelState("error"));
  }, []);

  useEffect(() => () => window.clearTimeout(timerRef.current), []);

  useEffect(() => {
    if (result) resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [result]);

  function showToast(message) {
    setToast(message);
    window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(() => setToast(""), 2200);
  }

  function remember(data) {
    if (!data.url) return;
    const updated = [
      { url: data.url, risk: data.risk_level, probability: data.phishing_probability },
      ...history.filter((item) => item.url !== data.url),
    ].slice(0, 5);
    setHistory(updated);
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
    } catch {
      showToast("Browser storage is unavailable; this check was not saved.");
    }
  }

  async function checkUrl(url) {
    setResult(null);
    setBusy(true);
    setPhase(0);
    const phaseTimer = window.setInterval(
      () => setPhase((current) => Math.min(current + 1, PHASES.length - 1)),
      420,
    );
    try {
      const response = await fetch("/score", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(typeof data.detail === "string" ? data.detail : "The model could not analyze that URL.");
      }
      setResult(data);
      remember(data);
    } catch (error) {
      showToast(error instanceof TypeError
        ? "Could not connect to PhishGuard-Z. Start the website server and try again."
        : error.message || "The URL could not be checked. Please try again.");
    } finally {
      window.clearInterval(phaseTimer);
      setBusy(false);
    }
  }

  function selectHistory(url) {
    checkUrl(url);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function clearHistory() {
    setHistory([]);
    try {
      localStorage.removeItem(HISTORY_KEY);
    } catch {
      showToast("Could not clear browser history storage.");
    }
  }

  function focusScanner() {
    document.querySelector("#url-input")?.focus();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  return (
    <>
      <div className="ambient ambient-one" aria-hidden="true" />
      <div className="ambient ambient-two" aria-hidden="true" />
      <Header modelState={modelState} />
      <main>
        <Hero onScan={checkUrl} busy={busy} />
        {busy && <ProgressCard phase={phase} />}
        {result && (
          <div ref={resultRef}>
            <ResultSection data={result} onNewCheck={focusScanner} onToast={showToast} />
          </div>
        )}
        <HistorySection history={history} onClear={clearHistory} onSelect={selectHistory} />
        <HowItWorks />
        <section className="bottom-note">
          <span className="note-shield" aria-hidden="true">✓</span>
          <p>
            <strong>A second opinion, not a silver bullet.</strong>
            <br />
            PhishGuard-Z is a research model. Avoid entering sensitive information on unfamiliar
            sites, even when a link scores low risk.
          </p>
        </section>
      </main>
      <footer className="footer">
        <a className="footer-brand" href="/">PhishGuard-Z</a>
        <span>Pre-visit URL risk analysis</span>
        <span>Model decisions can be wrong. Stay cautious.</span>
      </footer>
      <div className={`toast ${toast ? "show" : ""}`} role="status" aria-live="polite">
        {toast}
      </div>
    </>
  );
}

createRoot(document.getElementById("root")).render(<App />);
