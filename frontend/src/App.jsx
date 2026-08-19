import { useEffect, useState } from "react";
import {
  LayoutDashboard,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  FileText,
  BarChart3,
  Settings,
  HelpCircle,
  History,
  Plus,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock3,
  Download,
  Sun,
  Moon,
  HelpCircle as UnknownIcon,
} from "lucide-react";

import "./App.css";
import { useScanData } from "./hooks/useScanData";
import {
  getScans,
  getScanReport,
  getApiBaseUrl,
  setApiBaseUrl,
  getDefaultApiBaseUrl,
} from "./api/client";
import {
  getVerifiableFamily,
  toBackendScannerValue,
  formatVerificationStatus,
  priorityClassName,
  statusClassName,
} from "./utils/verification";
import { applyTheme, getInitialTheme, storeTheme } from "./theme";

function App() {
  const [activePage, setActivePage] = useState("Dashboard");
  // Applied synchronously (not in an effect) so the very first paint
  // already has the right theme -- an effect would run after paint
  // and cause a visible light->dark flash on load.
  const [theme, setTheme] = useState(() => {
    const initial = getInitialTheme();
    applyTheme(initial);
    return initial;
  });
  const scan = useScanData();

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // Only an explicit toggle is persisted -- until the user actually
  // chooses, the app keeps following the OS-level
  // prefers-color-scheme on every reload rather than freezing
  // whatever it happened to resolve to on first load.
  const toggleTheme = () => {
    setTheme((current) => {
      const next = current === "dark" ? "light" : "dark";
      storeTheme(next);
      return next;
    });
  };

  const menuItems = [
    { name: "Dashboard", icon: LayoutDashboard },
    { name: "New Scan", icon: ScanLine },
    { name: "Scan History", icon: History },
    { name: "Findings", icon: ShieldAlert },
    { name: "Prioritized Risks", icon: ShieldCheck },
    { name: "Reports", icon: FileText },
  ];

  const bottomItems = [
    { name: "Metrics", icon: BarChart3 },
    { name: "Settings", icon: Settings },
    { name: "Help", icon: HelpCircle },
  ];

  return (
    <div className="app">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={21} />
          </div>
          <span>VeriTriage</span>
        </div>

        <nav className="main-nav">
          {menuItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.name}
                className={`nav-item ${
                  activePage === item.name ? "active" : ""
                }`}
                onClick={() => setActivePage(item.name)}
              >
                <Icon size={18} />
                <span>{item.name}</span>
              </button>
            );
          })}
        </nav>

        <div className="evaluation-title">EVALUATION</div>

        <nav>
          {bottomItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.name}
                className={`nav-item ${
                  activePage === item.name ? "active" : ""
                }`}
                onClick={() => setActivePage(item.name)}
              >
                <Icon size={18} />
                <span>{item.name}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="user-avatar">JD</div>
          <div>
            <strong>Jordan Diaz</strong>
            <small>Security Engineer</small>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="main">
        {/* TOP BAR */}
        <header className="topbar">
          <div>
            <span className="breadcrumb">Dashboard</span>
            <h1>{activePage}</h1>
          </div>

          <div className="top-actions">
            <ThemeToggle theme={theme} onToggle={toggleTheme} />

            <button
              className="new-scan-button"
              onClick={() => setActivePage("New Scan")}
            >
              <Plus size={17} />
              New Scan
            </button>

            <button
              type="button"
              className="scan-info-button"
              onClick={() => setActivePage("Scan History")}
              title="View scan history"
            >
              <div className="scan-info">
                <strong>
                  {scan.scanMeta ? scan.scanMeta.filename : "No scan yet"}
                </strong>
                <span>
                  {scan.scanMeta
                    ? `${scannerDisplayName(scan.scanMeta.scanner)} · ${
                        scan.findings.length
                      } finding${scan.findings.length === 1 ? "" : "s"}`
                    : "Upload a report to begin"}
                </span>
              </div>
              <ChevronRight size={14} />
            </button>

            <div className="small-avatar">JD</div>
          </div>
        </header>

        {activePage === "Dashboard" ? (
          <Dashboard scan={scan} onNavigate={setActivePage} />
        ) : activePage === "New Scan" ? (
          <NewScan scan={scan} onUploaded={() => setActivePage("Findings")} />
        ) : activePage === "Scan History" ? (
          <ScanHistoryPage scan={scan} onNavigate={setActivePage} />
        ) : activePage === "Findings" ? (
          <FindingsPage scan={scan} />
        ) : activePage === "Prioritized Risks" ? (
          <PrioritizedRisks scan={scan} />
        ) : activePage === "Reports" ? (
          <ReportsPage key={scan.scanId} scan={scan} />
        ) : activePage === "Metrics" ? (
          <MetricsPage scan={scan} />
        ) : activePage === "Settings" ? (
          <SettingsPage />
        ) : activePage === "Help" ? (
          <HelpPage />
        ) : null}
      </main>
    </div>
  );
}

/* =========================
   SHARED HELPERS
========================= */

function verificationCounts(findings, verifiedById) {
  let truePositive = 0;
  let falsePositive = 0;
  let inconclusive = 0;
  let unverified = 0;

  for (const finding of findings) {
    const verified = verifiedById[finding.finding_id];
    if (!verified) {
      unverified += 1;
      continue;
    }
    if (verified.classification.status === "TRUE_POSITIVE") truePositive += 1;
    else if (verified.classification.status === "FALSE_POSITIVE")
      falsePositive += 1;
    else inconclusive += 1;
  }

  return { truePositive, falsePositive, inconclusive, unverified };
}

/* =========================
   DASHBOARD
========================= */

function Dashboard({ scan, onNavigate }) {
  const hasScan = Boolean(scan.scanId);
  const counts = verificationCounts(scan.findings, scan.verifiedById);
  const rawCount = scan.findings.length;
  const verifiedCount =
    counts.truePositive + counts.falsePositive + counts.inconclusive;
  const noiseReduction =
    verifiedCount > 0
      ? ((counts.falsePositive / verifiedCount) * 100).toFixed(1) + "%"
      : "N/A";

  const topPriorities = Object.values(scan.priorityById)
    .filter((p) => p.priority === "CRITICAL" || p.priority === "HIGH")
    .slice(0, 5);

  return (
    <div className="dashboard">
      <div className="page-description">
        <div>
          <h2>Security Scan Overview</h2>
          <p>
            {hasScan
              ? `Automated verification results for `
              : "No scan loaded yet — "}
            <strong>
              {hasScan
                ? scan.scanMeta.filename
                : "upload a scan to see live results"}
            </strong>
          </p>
        </div>
      </div>

      {scan.loadError && (
        <ErrorBanner
          message={`Could not load scan data: ${scan.loadError.message}`}
        />
      )}

      <section className="stats-grid">
        <StatCard
          title="RAW FINDINGS"
          value={hasScan ? String(rawCount) : "—"}
          subtitle="From scanner"
          type="blue"
        />
        <StatCard
          title="TRUE POSITIVES"
          value={hasScan ? String(counts.truePositive) : "—"}
          subtitle="Confirmed"
          type="green"
        />
        <StatCard
          title="FALSE POSITIVES"
          value={hasScan ? String(counts.falsePositive) : "—"}
          subtitle="Removed"
          type="red"
        />
        <StatCard
          title="INCONCLUSIVE"
          value={hasScan ? String(counts.inconclusive) : "—"}
          subtitle="Needs review"
          type="orange"
        />
        <StatCard
          title="UNIQUE VULNERABILITIES"
          value={hasScan ? String(scan.duplicateGroups.length) : "—"}
          subtitle="After deduplication"
          type="purple"
        />
        <StatCard
          title="NOISE REDUCTION"
          value={hasScan ? noiseReduction : "—"}
          subtitle="False positives removed"
          type="blue"
        />
      </section>

      <section className="analysis-grid">
        <FindingVerificationPanel
          hasScan={hasScan}
          counts={counts}
          rawCount={rawCount}
        />
        <ScanSummaryPanel
          hasScan={hasScan}
          scan={scan}
          rawCount={rawCount}
          verifiedCount={verifiedCount}
          pending={counts.unverified}
        />
      </section>

      <section className="panel risks-panel">
        <div className="panel-header">
          <div>
            <h3>Top Risks</h3>
            <p>Highest-priority confirmed vulnerabilities</p>
          </div>
          <button
            className="view-button"
            onClick={() => onNavigate("Prioritized Risks")}
          >
            View all findings
            <ChevronRight size={16} />
          </button>
        </div>

        {!hasScan ? (
          <EmptyState text="Upload a scan to see prioritized risks." />
        ) : topPriorities.length === 0 ? (
          <EmptyState text="No CRITICAL or HIGH priority findings yet. Verify findings to populate this list." />
        ) : (
          <div className="risk-table">
            <div className="risk-header">
              <span>RANK</span>
              <span>VULNERABILITY</span>
              <span>STATUS</span>
              <span>SEVERITY</span>
              <span>PRIORITY</span>
              <span></span>
            </div>

            {topPriorities.map((p, index) => {
              const finding = scan.findings.find(
                (f) => f.finding_id === p.finding_id
              );
              return (
                <div className="risk-row" key={p.finding_id}>
                  <span className="rank">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <div className="vulnerability">
                    <strong>
                      {finding?.source?.original_name ||
                        finding?.vulnerability?.category ||
                        "Unknown"}
                    </strong>
                    <small>{finding?.target?.normalized_url}</small>
                  </div>
                  <StatusBadge status={p.verification_status} />
                  <span>{p.scanner_severity}</span>
                  <span className={`priority ${priorityClassName(p.priority)}`}>
                    {p.priority}
                  </span>
                  <span></span>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

function StatCard({ title, value, subtitle, type }) {
  return (
    <div className={`stat-card ${type}`}>
      <div className="stat-title">{title}</div>
      <div className="stat-value">{value}</div>
      <div className="stat-subtitle">{subtitle}</div>
    </div>
  );
}

// Presentational only -- reverses the New Scan dropdown's display
// mapping (utils/verification.js toBackendScannerValue) so the raw
// backend value ("ZAP"/"BURP") already stored on scan.scanMeta reads
// naturally on the Dashboard. Falls back to the raw value for
// anything unrecognized rather than inventing a label.
function scannerDisplayName(rawValue) {
  if (rawValue === "ZAP") return "OWASP ZAP";
  if (rawValue === "BURP") return "Burp Suite";
  return rawValue;
}

/**
 * Left panel of the Dashboard's overview row: how this scan's
 * findings were classified. Reuses the same counts the KPI row
 * above already computed -- nothing here is calculated separately.
 */
function FindingVerificationPanel({ hasScan, counts, rawCount }) {
  const rows = [
    { label: "Confirmed", value: counts.truePositive, barClass: "bar-green" },
    {
      label: "False Positive",
      value: counts.falsePositive,
      barClass: "bar-red",
    },
    {
      label: "Inconclusive",
      value: counts.inconclusive,
      barClass: "bar-orange",
    },
    { label: "Unverified", value: counts.unverified, barClass: "bar-gray" },
  ];

  return (
    <div className="panel verification-breakdown-panel">
      <div className="panel-header">
        <div>
          <h3>Finding Verification</h3>
          <p>How scanner findings were classified</p>
        </div>
      </div>

      {!hasScan ? (
        <EmptyState text="Upload a scan to see this breakdown." />
      ) : (
        rows.map((row) => (
          <div className="bar-row" key={row.label}>
            <div className="bar-label">
              <span>{row.label}</span>
              <strong>{row.value}</strong>
            </div>
            <div className="bar">
              <div
                className={row.barClass}
                style={{
                  width:
                    rawCount > 0
                      ? `${Math.max(
                          (row.value / rawCount) * 100,
                          row.value > 0 ? 4 : 0
                        )}%`
                      : "0%",
                }}
              >
                {row.value > 0 ? row.value : ""}
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

/**
 * Right panel of the Dashboard's overview row: a compact scan-health
 * summary. Every field is read directly from scan.scanMeta or the
 * already-computed counts -- no timestamp is shown because the
 * backend's scan record does not carry one.
 */
function ScanSummaryPanel({ hasScan, scan, rawCount, verifiedCount, pending }) {
  return (
    <div className="panel scan-summary-panel">
      <div className="panel-header">
        <div>
          <h3>Scan Summary</h3>
          <p>Current state of this scan</p>
        </div>
      </div>

      {!hasScan ? (
        <EmptyState text="Upload a scan to see its summary." />
      ) : (
        <>
          <div className="metric-line">
            <span>Scanner</span>
            <strong>{scannerDisplayName(scan.scanMeta.scanner)}</strong>
          </div>
          <div className="metric-line">
            <span>File</span>
            <strong>{scan.scanMeta.filename}</strong>
          </div>
          <div className="metric-line">
            <span>Raw findings</span>
            <strong>{rawCount}</strong>
          </div>
          <div className="metric-line">
            <span>Verified</span>
            <strong>{verifiedCount}</strong>
          </div>
          <div className="metric-line">
            <span>Pending</span>
            <strong>{pending}</strong>
          </div>

          <div
            className={`scan-status-indicator ${
              pending === 0 ? "complete" : "pending"
            }`}
          >
            {pending === 0 ? (
              <>
                <CheckCircle2 size={14} />
                Verification complete
              </>
            ) : (
              <>
                <Clock3 size={14} />
                Verification pending — {pending} remaining
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/* =========================
   NEW SCAN
========================= */

function NewScan({ scan, onUploaded }) {
  const [target, setTarget] = useState("https://test-app.local");
  const [scannerType, setScannerType] = useState("OWASP ZAP");
  const [scanDate, setScanDate] = useState("10 / 05 / 2024");
  const [notes, setNotes] = useState("");
  const [fileName, setFileName] = useState("");
  const [fileObject, setFileObject] = useState(null);
  const [formError, setFormError] = useState(null);

  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setFileName(file.name);
      setFileObject(file);
      setFormError(null);
    }
  };

  const useDemoDataset = () => {
    setTarget("https://test-app.local");
    setScannerType("OWASP ZAP");
    setScanDate("10 / 05 / 2024");
    setNotes("Demo security scan dataset");
    // No bundled demo report exists in this frontend, so this only
    // pre-fills the descriptive fields -- it does not attach a real
    // file. A real .json/.xml report must still be browsed for
    // before starting verification.
    setFileName("");
    setFileObject(null);
    setFormError(
      "Demo fields filled in. Please also browse a real ZAP/Burp report file -- no sample file is bundled with this frontend."
    );
  };

  const startVerification = async () => {
    if (!fileObject) {
      setFormError("Please choose a scanner report file first.");
      return;
    }

    setFormError(null);

    try {
      await scan.startScan({
        scanner: toBackendScannerValue(scannerType),
        file: fileObject,
      });
      onUploaded();
    } catch (err) {
      setFormError(err.message);
    }
  };

  const uploading = scan.uploadState === "uploading";

  return (
    <div className="new-scan-prototype">
      <div className="new-scan-heading">
        <div>
          <div className="breadcrumb">
            Dashboard <span>/</span> New Scan
          </div>
          <h1>Start New Security Scan</h1>
        </div>
      </div>

      <p className="new-scan-intro">
        Upload a scanner report to automatically verify findings and generate
        an evidence-backed report.
      </p>

      {/* UPLOAD AREA */}
      <section className="upload-card">
        <div className="upload-icon">↑</div>
        <h3>Drop your scanner report here</h3>
        <p>or browse files</p>

        <label className="browse-files">
          Browse Files
          <input
            type="file"
            accept=".json,.xml"
            onChange={handleFile}
            hidden
          />
        </label>

        <div className="supported-files">
          OWASP ZAP JSON · Burp Suite XML
        </div>

        {fileName && (
          <div className="selected-file">
            Selected: <strong>{fileName}</strong>
          </div>
        )}

        {formError && <ErrorBanner message={formError} />}

        {scan.uploadState === "success" && scan.scanMeta && (
          <div className="selected-file">
            ✓ Uploaded — {scan.scanMeta.finding_count} findings normalized
            (scan_id: {scan.scanMeta.scan_id})
          </div>
        )}
      </section>

      {/* SCAN CONFIGURATION */}
      <section className="scan-configuration">
        <div className="section-label">SCAN CONFIGURATION</div>

        <div className="configuration-grid">
          <div className="form-field">
            <label>Target Application (reference only)</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://test-app.local"
            />
          </div>

          <div className="form-field">
            <label>Scanner Type</label>
            <select
              value={scannerType}
              onChange={(e) => setScannerType(e.target.value)}
            >
              <option>OWASP ZAP</option>
              <option>Burp Suite</option>
            </select>
          </div>

          <div className="form-field">
            <label>Scan Date (reference only)</label>
            <input
              type="text"
              value={scanDate}
              onChange={(e) => setScanDate(e.target.value)}
              placeholder="10 / 05 / 2024"
            />
          </div>

          <div className="form-field notes-field">
            <label>Notes (optional, reference only)</label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Add any context for this scan run..."
            />
          </div>
        </div>
      </section>

      {/* AUTOMATED PIPELINE */}
      <section className="pipeline-card">
        <div className="section-label">AUTOMATED PIPELINE</div>

        <div className="pipeline">
          <div className="pipeline-step">
            <span>1</span>
            <strong>Ingest</strong>
          </div>
          <div className="pipeline-line">→</div>
          <div className="pipeline-step">
            <span>2</span>
            <strong>Normalize</strong>
          </div>
          <div className="pipeline-line">→</div>
          <div className="pipeline-step">
            <span>3</span>
            <strong>Replay</strong>
          </div>
          <div className="pipeline-line">→</div>
          <div className="pipeline-step">
            <span>4</span>
            <strong>Verify</strong>
          </div>
          <div className="pipeline-line">→</div>
          <div className="pipeline-step">
            <span>5</span>
            <strong>Deduplicate</strong>
          </div>
          <div className="pipeline-line">→</div>
          <div className="pipeline-step">
            <span>6</span>
            <strong>Enrich</strong>
          </div>
          <div className="pipeline-line">→</div>
          <div className="pipeline-step">
            <span>7</span>
            <strong>Prioritize</strong>
          </div>
        </div>

        <p className="pipeline-description">
          Upload runs Ingest + Normalize immediately. Replay/Verify runs
          per finding from the Findings page. Deduplicate/Enrich/Prioritize
          are computed live from whatever has been verified so far.
        </p>
      </section>

      {/* ACTIONS */}
      <div className="new-scan-actions">
        <button
          className="start-verification-button"
          onClick={startVerification}
          disabled={uploading}
        >
          {uploading ? "Uploading..." : "Upload Scan"}
        </button>

        <button className="demo-dataset-button" onClick={useDemoDataset}>
          Use Demo Dataset
        </button>
      </div>
    </div>
  );
}

/* =========================
   SCAN HISTORY
========================= */

/**
 * "What scans have I previously uploaded?" -- backed entirely by
 * GET /scans (backend/api/scans.py list_scans -> get_all_scans()).
 * Fetched fresh every time this page mounts (i.e. every time the
 * user navigates here) rather than cached in state, since the
 * backend -- not the frontend -- is the source of truth for scan
 * history and scans can appear between visits.
 */
function ScanHistoryPage({ scan, onNavigate }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectingId, setSelectingId] = useState(null);

  useEffect(() => {
    let cancelled = false;

    getScans()
      .then((result) => {
        if (!cancelled) setScans(result);
      })
      .catch((err) => {
        if (!cancelled) setError(err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const handleSelect = async (scanId) => {
    setSelectingId(scanId);

    try {
      await scan.loadScan(scanId);
      onNavigate("Findings");
    } catch {
      // Surfaced via scan.loadError, which the destination pages
      // (Dashboard/Findings) already render as an ErrorBanner.
    } finally {
      setSelectingId(null);
    }
  };

  // Most-recently-uploaded first. The backend keeps scans in
  // insertion order and carries no timestamp, so this is real
  // ordering information (not an invented one) -- it just isn't a
  // date.
  const ordered = [...scans].reverse();

  return (
    <div className="scan-history-page">
      <div className="page-description">
        <div>
          <h2>Scan History</h2>
          <p>Previously uploaded security scans</p>
        </div>
      </div>

      {loading ? (
        <EmptyState text="Loading scan history..." />
      ) : error ? (
        <ErrorBanner
          message={`Could not load scan history: ${error.message}`}
        />
      ) : ordered.length === 0 ? (
        <div className="scan-history-empty">
          <EmptyState text="No previous scans. Upload a scan to begin building your scan history." />
          <button
            className="new-scan-button"
            onClick={() => onNavigate("New Scan")}
          >
            <Plus size={15} />
            New Scan
          </button>
        </div>
      ) : (
        <div className="scan-history-list">
          <div className="scan-history-header">
            <span>Filename</span>
            <span>Scanner</span>
            <span>Status</span>
            <span></span>
          </div>

          {ordered.map((item) => (
            <button
              key={item.scan_id}
              type="button"
              className={`scan-history-row ${
                item.scan_id === scan.scanId ? "active" : ""
              }`}
              onClick={() => handleSelect(item.scan_id)}
              disabled={selectingId === item.scan_id}
            >
              <div className="scan-history-filename">
                <strong>{item.filename}</strong>
                <small>{item.scan_id.slice(0, 8)}</small>
              </div>
              <span>{scannerDisplayName(item.scanner)}</span>
              <ScanStatusBadge status={item.status} />
              {selectingId === item.scan_id ? (
                <span className="scan-history-loading">Loading…</span>
              ) : (
                <ChevronRight size={16} />
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ScanStatusBadge({ status }) {
  const cls = status ? status.toLowerCase() : "unknown";
  return (
    <span className={`status scan-status-${cls}`}>{status || "UNKNOWN"}</span>
  );
}

/* =========================
   FINDINGS PAGE
========================= */

function FindingsPage({ scan }) {
  const hasScan = Boolean(scan.scanId);
  const counts = verificationCounts(scan.findings, scan.verifiedById);

  return (
    <div className="findings-page">
      <div className="page-description">
        <h2>Security Findings</h2>
        <p>
          Detailed vulnerability findings identified during the security
          scan.
        </p>
      </div>

      {!hasScan ? (
        <EmptyState text="No scan uploaded yet. Go to New Scan to get started." />
      ) : scan.loadingScanData && scan.findings.length === 0 ? (
        <EmptyState text="Loading findings..." />
      ) : scan.findings.length === 0 ? (
        <EmptyState text="This scan produced no findings." />
      ) : (
        <>
          <div className="findings-summary">
            <div className="summary-card">
              <span>Total Findings</span>
              <strong>{scan.findings.length}</strong>
            </div>
            <div className="summary-card">
              <span>Verified</span>
              <strong>
                {counts.truePositive + counts.falsePositive + counts.inconclusive}
              </strong>
            </div>
            <div className="summary-card">
              <span>Not Verified Yet</span>
              <strong>{counts.unverified}</strong>
            </div>
          </div>

          <div className="findings-list">
            {scan.findings.map((finding, index) => (
              <FindingCard
                key={finding.finding_id}
                index={index}
                finding={finding}
                verified={scan.verifiedById[finding.finding_id]}
                priority={scan.priorityById[finding.finding_id]}
                enrichment={scan.enrichmentById[finding.finding_id]}
                verifying={scan.verifyingId === finding.finding_id}
                verifyError={scan.verifyErrorsById[finding.finding_id]}
                onVerify={(trigger) => scan.verify(finding.finding_id, trigger)}
              />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function FindingCard({
  index,
  finding,
  verified,
  priority,
  enrichment,
  verifying,
  verifyError,
  onVerify,
}) {
  const [panelOpen, setPanelOpen] = useState(false);
  const family = getVerifiableFamily(finding.vulnerability.category);

  return (
    <div className="finding-card">
      <div className="finding-top">
        <div>
          <span className="finding-rank">#{String(index + 1).padStart(2, "0")}</span>
          <h3>
            {finding.source.original_name || finding.vulnerability.category}
          </h3>
          <p>
            {finding.vulnerability.category}
            {finding.target.parameter
              ? ` · param: ${finding.target.parameter}`
              : ""}{" "}
            · {finding.target.normalized_url}
          </p>
        </div>

        {priority ? (
          <span className={`priority ${priorityClassName(priority.priority)}`}>
            {priority.priority}
          </span>
        ) : (
          <span className="priority unverified">NOT VERIFIED</span>
        )}
      </div>

      <div className="finding-details">
        <div>
          <span>Severity (scanner)</span>
          <strong>{finding.vulnerability.normalized_severity}</strong>
        </div>
        <div>
          <span>Status</span>
          <StatusBadge status={verified?.classification?.status} />
        </div>
        <div>
          <span>CWE</span>
          <strong>
            {enrichment?.cwe ? (
              enrichment.cwe_url ? (
                <a href={enrichment.cwe_url} target="_blank" rel="noreferrer">
                  {enrichment.cwe}
                </a>
              ) : (
                enrichment.cwe
              )
            ) : (
              "—"
            )}
          </strong>
        </div>
      </div>

      {verified && (
        <VerificationResult verified={verified} priority={priority} />
      )}

      {enrichment && <EnrichmentDetails enrichment={enrichment} />}

      <div className="finding-actions">
        {family ? (
          <button
            className="view-button"
            onClick={() => setPanelOpen((v) => !v)}
          >
            {panelOpen ? "Hide verification" : verified ? "Re-verify" : "Verify"}
            <ChevronRight size={14} />
          </button>
        ) : (
          <span className="not-verifiable-note">
            Category "{finding.vulnerability.category}" is not currently
            verifiable by this backend (only SQLI, CSRF, and reflected XSS
            are supported).
          </span>
        )}
      </div>

      {panelOpen && family && (
        <VerifyForm
          family={family}
          finding={finding}
          verifying={verifying}
          error={verifyError}
          onSubmit={onVerify}
        />
      )}
    </div>
  );
}

function StatusBadge({ status }) {
  const cls = statusClassName(status);
  const label = formatVerificationStatus(status);

  let Icon = UnknownIcon;
  if (status === "TRUE_POSITIVE") Icon = CheckCircle2;
  else if (status === "FALSE_POSITIVE") Icon = XCircle;
  else if (status === "INCONCLUSIVE") Icon = Clock3;

  return (
    <span className={`status status-${cls}`}>
      <Icon size={14} />
      {label}
    </span>
  );
}

function VerificationResult({ verified, priority }) {
  return (
    <div className="verification-result">
      <div className="verification-result-row">
        <span>Reason</span>
        <p>{verified.classification.reason}</p>
      </div>

      {verified.evidence.indicators.length > 0 && (
        <div className="verification-result-row">
          <span>Evidence</span>
          <div className="evidence-chips">
            {verified.evidence.indicators.map((indicator) => (
              <span className="chip" key={indicator}>
                {indicator}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="verification-result-row">
        <span>Verification confidence</span>
        <p>
          {(verified.classification.confidence * 100).toFixed(0)}%
          <em className="confidence-note">
            {" "}
            (evidence strength — not the same as priority)
          </em>
        </p>
      </div>

      {priority && (
        <div className="verification-result-row">
          <span>Priority reason</span>
          <p>{priority.reason}</p>
        </div>
      )}
    </div>
  );
}

function EnrichmentDetails({ enrichment }) {
  const hasAnything =
    enrichment.description ||
    enrichment.remediation ||
    enrichment.owasp_category ||
    enrichment.references.length > 0;

  if (!hasAnything) return null;

  return (
    <div className="enrichment-block">
      {enrichment.owasp_category && (
        <div className="verification-result-row">
          <span>OWASP</span>
          <p>
            {enrichment.owasp_url ? (
              <a href={enrichment.owasp_url} target="_blank" rel="noreferrer">
                {enrichment.owasp_category}
              </a>
            ) : (
              enrichment.owasp_category
            )}
          </p>
        </div>
      )}

      {enrichment.description && (
        <div className="verification-result-row">
          <span>Description</span>
          <p>{enrichment.description}</p>
        </div>
      )}

      {enrichment.remediation && (
        <div className="verification-result-row">
          <span>Remediation</span>
          <p>{enrichment.remediation}</p>
        </div>
      )}

      {enrichment.references.length > 0 && (
        <div className="verification-result-row">
          <span>References</span>
          <ul className="reference-list">
            {enrichment.references.map((ref) => (
              <li key={ref}>
                <a href={ref} target="_blank" rel="noreferrer">
                  {ref}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/* =========================
   VERIFY FORM
   Minimum required fields per family, matching
   backend/models/verification_trigger.py exactly. Optional fields
   (browser_context_required, defense_test, origin_test,
   expected_parameter) are intentionally omitted rather than
   fabricated -- only what's required to produce a valid request is
   collected.
========================= */

function VerifyForm({ family, finding, verifying, error, onSubmit }) {
  const [sqliSubtype, setSqliSubtype] = useState("time_based");
  const [baselineValue, setBaselineValue] = useState("");
  const [stateIndicator, setStateIndicator] = useState("");
  const [payload1, setPayload1] = useState("");
  const [payload2, setPayload2] = useState("");
  const [localError, setLocalError] = useState(null);

  const handleSqliSubtypeChange = (e) => {
    // Reset baseline value + any stale error when switching subtypes
    // so a value/error left over from one subtype can never be
    // retained into (or block submission of) the other.
    setSqliSubtype(e.target.value);
    setBaselineValue("");
    setLocalError(null);
  };

  const submit = (e) => {
    e.preventDefault();
    setLocalError(null);

    if (family === "sqli") {
      if (sqliSubtype === "error_based") {
        onSubmit({
          sqli: { error_based: {} },
        });
        return;
      }

      if (!baselineValue.trim()) {
        setLocalError("Baseline parameter value is required.");
        return;
      }
      onSubmit({
        sqli: { time_based: { baseline_parameter_value: baselineValue } },
      });
      return;
    }

    if (family === "csrf") {
      if (!stateIndicator.trim()) {
        setLocalError(
          "A deterministic acceptance indicator is required for this minimal CSRF check."
        );
        return;
      }
      onSubmit({
        csrf: {
          state_check: {
            deterministic_acceptance_indicator: stateIndicator,
          },
        },
      });
      return;
    }

    if (family === "xss") {
      if (!payload1.trim() || !payload2.trim()) {
        setLocalError(
          "Reflected XSS verification requires at least two distinct payload variants."
        );
        return;
      }
      onSubmit({
        xss: {
          reflected: {
            payload_variants: [
              { variant_id: "v1", payload: payload1 },
              { variant_id: "v2", payload: payload2 },
            ],
          },
        },
      });
    }
  };

  return (
    <form className="verify-form" onSubmit={submit}>
      {family === "sqli" && (
        <>
          <div className="form-field">
            <label>SQLi verification technique</label>
            <select
              value={sqliSubtype}
              onChange={handleSqliSubtypeChange}
            >
              <option value="time_based">TIME_BASED</option>
              <option value="error_based">ERROR_BASED</option>
            </select>
          </div>

          {sqliSubtype === "time_based" && (
            <div className="form-field">
              <label>Baseline parameter value (pre-injection value)</label>
              <input
                type="text"
                value={baselineValue}
                onChange={(e) => setBaselineValue(e.target.value)}
                placeholder={`e.g. the original value of "${finding.target.parameter || "id"}"`}
              />
            </div>
          )}
        </>
      )}

      {family === "csrf" && (
        <div className="form-field">
          <label>Deterministic acceptance indicator</label>
          <p className="form-field-help">
            Enter the <strong>exact text</strong> the target application
            itself returns in its response body when this specific
            request succeeds — not a general word like "accepted" or
            "success". The backend checks for this text appearing
            literally in the live replay response; it does not
            recognize any fixed set of values, because that text is
            different for every target application. Only enter text
            you have independently confirmed appears on success —
            guessing produces an unreliable result, not evidence.
          </p>
          <input
            type="text"
            value={stateIndicator}
            onChange={(e) => setStateIndicator(e.target.value)}
            placeholder='Exact success text, e.g. "Password Changed."'
          />
        </div>
      )}

      {family === "xss" && (
        <>
          <div className="form-field">
            <label>Payload variant 1</label>
            <input
              type="text"
              value={payload1}
              onChange={(e) => setPayload1(e.target.value)}
              placeholder="<script>alert(1)</script>"
            />
          </div>
          <div className="form-field">
            <label>Payload variant 2</label>
            <input
              type="text"
              value={payload2}
              onChange={(e) => setPayload2(e.target.value)}
              placeholder="<script>alert(2)</script>"
            />
          </div>
        </>
      )}

      {(localError || error) && (
        <ErrorBanner message={localError || error?.message} />
      )}

      <button
        type="submit"
        className="start-verification-button"
        disabled={verifying}
      >
        {verifying
          ? "Verifying... this can take up to a minute"
          : "Run Verification"}
      </button>
    </form>
  );
}

/* =========================
   PRIORITIZED RISKS
========================= */

function PrioritizedRisks({ scan }) {
  const hasScan = Boolean(scan.scanId);
  const priorities = Object.values(scan.priorityById);

  const priorityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
  const sorted = [...priorities].sort(
    (a, b) =>
      priorityOrder.indexOf(a.priority) - priorityOrder.indexOf(b.priority)
  );

  const criticalCount = priorities.filter((p) => p.priority === "CRITICAL").length;
  const highCount = priorities.filter((p) => p.priority === "HIGH").length;

  return (
    <div className="findings-page">
      <div className="page-description">
        <div>
          <h2>Prioritized Risks</h2>
          <p>
            Deterministic priority derived from verification status and
            scanner severity (see backend Risk/Priority V1 rules).
          </p>
        </div>
      </div>

      {!hasScan ? (
        <EmptyState text="No scan uploaded yet." />
      ) : sorted.length === 0 ? (
        <EmptyState text="No findings have been verified yet. Verify findings from the Findings page to see them prioritized here." />
      ) : (
        <>
          <div className="findings-summary">
            <div className="summary-card">
              <span>CRITICAL RISKS</span>
              <strong>{criticalCount}</strong>
            </div>
            <div className="summary-card">
              <span>HIGH RISKS</span>
              <strong>{highCount}</strong>
            </div>
            <div className="summary-card">
              <span>TOTAL VERIFIED</span>
              <strong>{sorted.length}</strong>
            </div>
          </div>

          <div className="findings-list">
            {sorted.map((p, index) => {
              const finding = scan.findings.find(
                (f) => f.finding_id === p.finding_id
              );
              return (
                <div className="finding-card" key={p.finding_id}>
                  <div className="finding-top">
                    <div>
                      <span className="finding-rank">
                        #{String(index + 1).padStart(2, "0")}
                      </span>
                      <h3>
                        {finding?.source?.original_name ||
                          finding?.vulnerability?.category ||
                          "Unknown finding"}
                      </h3>
                      <p>Target: {finding?.target?.normalized_url}</p>
                    </div>
                    <span className={`priority ${priorityClassName(p.priority)}`}>
                      {p.priority}
                    </span>
                  </div>

                  <div className="finding-details">
                    <div>
                      <span>VERIFICATION STATUS</span>
                      <StatusBadge status={p.verification_status} />
                    </div>
                    <div>
                      <span>SCANNER SEVERITY</span>
                      <strong>{p.scanner_severity}</strong>
                    </div>
                    <div>
                      <span>PRIORITY REASON</span>
                      <strong>{p.reason}</strong>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

/* =========================
   REPORTS
========================= */

/**
 * "Give me a structured report of this scan" -- entirely driven by
 * the backend's GET /scans/{scan_id}/report (ScanReport), fetched on
 * demand into local state and rendered as-is. Nothing here reads
 * live scan.findings/scan.priorityById: the point of a report is a
 * point-in-time snapshot from the backend's own report_service, not
 * a re-derivation from whatever the client happens to have cached.
 *
 * critical/high counts are the one exception -- they are not fields
 * on ScanReport, but they are computed only from that same fetched
 * report's own findings[], never from separate live state.
 */
function ReportsPage({ scan }) {
  const hasScan = Boolean(scan.scanId);

  const [report, setReport] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [generateError, setGenerateError] = useState(null);

  const handleGenerateReport = async () => {
    if (!scan.scanId) return;

    setGenerating(true);
    setGenerateError(null);

    try {
      const result = await getScanReport(scan.scanId);
      setReport(result);
    } catch (err) {
      setGenerateError(err.message);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = () => {
    if (!report) return;

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `vulnverify-report-${report.scan_id}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const criticalCount = report
    ? report.findings.filter((f) => f.priority === "CRITICAL").length
    : 0;
  const highCount = report
    ? report.findings.filter((f) => f.priority === "HIGH").length
    : 0;

  return (
    <div className="reports-page">
      <div className="page-description reports-header">
        <div>
          <h2>Security Reports</h2>
          <p>Generate and review verified security scan reports.</p>
        </div>

        {hasScan && (
          <div className="report-actions">
            <button
              className="new-scan-button"
              onClick={handleGenerateReport}
              disabled={generating}
            >
              <FileText size={15} />
              {generating
                ? "Generating..."
                : report
                ? "Regenerate Report"
                : "Generate Report"}
            </button>
            {report && (
              <button className="view-button" onClick={handleDownload}>
                <Download size={14} />
                Download JSON
              </button>
            )}
          </div>
        )}
      </div>

      {generateError && (
        <ErrorBanner
          message={`Could not generate report: ${generateError}`}
        />
      )}

      {!hasScan ? (
        <EmptyState text="No scan loaded. Upload a scan to generate a security report." />
      ) : !report ? (
        <EmptyState
          text={
            generating
              ? "Generating report..."
              : 'Click "Generate Report" to build a structured report for this scan.'
          }
        />
      ) : (
        <>
          <section className="panel report-summary-panel">
            <div className="panel-header">
              <div>
                <h3>Scan Summary</h3>
                <p>Generated {new Date(report.generated_at).toLocaleString()}</p>
              </div>
            </div>

            <div className="evaluation-details-grid">
              <div>
                <span>Scan</span>
                <strong>{report.filename}</strong>
              </div>
              <div>
                <span>Scanner</span>
                <strong>{scannerDisplayName(report.scanner)}</strong>
              </div>
              <div>
                <span>Total findings</span>
                <strong>{report.raw_finding_count}</strong>
              </div>
              <div>
                <span>Verified findings</span>
                <strong>{report.verified_count}</strong>
              </div>
              <div>
                <span>Unique vulnerabilities</span>
                <strong>{report.unique_vulnerability_count}</strong>
              </div>
              <div>
                <span>Critical findings</span>
                <strong>{criticalCount}</strong>
              </div>
              <div>
                <span>High findings</span>
                <strong>{highCount}</strong>
              </div>
            </div>
          </section>

          <section className="panel risks-panel">
            <div className="panel-header">
              <div>
                <h3>Verified Security Report</h3>
                <p>Every finding in this report, with its verification result</p>
              </div>
            </div>

            {report.findings.length === 0 ? (
              <EmptyState text="This scan produced no findings." />
            ) : (
              <div className="risk-table">
                <div className="risk-header">
                  <span>RANK</span>
                  <span>VULNERABILITY</span>
                  <span>STATUS</span>
                  <span>SEVERITY</span>
                  <span>PRIORITY</span>
                  <span></span>
                </div>

                {report.findings.map((finding, index) => (
                  <div className="risk-row" key={finding.finding_id}>
                    <span className="rank">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <div className="vulnerability">
                      <strong>{finding.original_name || finding.category}</strong>
                      <small>{finding.normalized_url}</small>
                    </div>
                    <StatusBadge status={finding.verification_status} />
                    <span>{finding.scanner_severity}</span>
                    {finding.priority ? (
                      <span
                        className={`priority ${priorityClassName(finding.priority)}`}
                      >
                        {finding.priority}
                      </span>
                    ) : (
                      <span className="priority unverified">NOT VERIFIED</span>
                    )}
                    <span></span>
                  </div>
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

/* =========================
   METRICS
========================= */

function formatMetricPercent(value) {
  return value === null || value === undefined
    ? "N/A"
    : `${(value * 100).toFixed(1)}%`;
}

/**
 * Evaluation analytics page: "how well did verification perform,"
 * as opposed to the Dashboard's "what happened in this scan."
 *
 * Precision/recall/F1/confusion-matrix values only ever come from
 * scan.metrics (GET /scans/{scan_id}/metrics) -- nothing here is
 * derived from verification results directly, since a verifier's own
 * output can never serve as ground truth for evaluating itself. The
 * four states below (no scan / loading / no ground truth / ground
 * truth but nothing evaluated) mirror the backend's own evaluation
 * semantics rather than inventing new ones.
 */
function MetricsPage({ scan }) {
  const hasScan = Boolean(scan.scanId);
  const metrics = scan.metrics;

  const handleLoadDemoGroundTruth = async () => {
    try {
      await scan.loadDemoGroundTruth();
    } catch {
      // surfaced via scan.groundTruthError below
    }
  };

  return (
    <div className="metrics-page">
      <div className="page-description">
        <div>
          <h2>Verification Metrics</h2>
          <p>
            Measure verification accuracy against labeled ground-truth
            data.
          </p>
          {hasScan && (
            <span className="metrics-scan-chip">
              {scan.scanMeta.filename}
            </span>
          )}
        </div>
      </div>

      {!hasScan ? (
        <EmptyState text="No scan loaded — upload a scan to view verification metrics." />
      ) : !metrics ? (
        <EmptyState text="Loading metrics..." />
      ) : metrics.ground_truth_count === 0 ? (
        <div className="panel metrics-empty-panel">
          <div className="ground-truth-empty">
            <EmptyState text="No ground-truth labels available for this scan. Precision, recall, and F1 cannot be calculated without labeled ground-truth data." />
            {/* Dev/test-only affordance for exercising the demo
                ground-truth dataset (backend/data/demo_ground_truth_labels.json).
                Never rendered in a production build -- ground truth
                in the real product is supplied by
                POST /scans/{scan_id}/ground-truth, not invented here. */}
            {import.meta.env.DEV && (
              <>
                <button
                  className="view-button"
                  onClick={handleLoadDemoGroundTruth}
                  disabled={scan.loadingGroundTruth}
                >
                  {scan.loadingGroundTruth
                    ? "Loading..."
                    : "(dev) Load demo ground truth"}
                </button>
                {scan.groundTruthError && (
                  <ErrorBanner
                    message={`Could not load ground truth: ${scan.groundTruthError.message}`}
                  />
                )}
              </>
            )}
          </div>
        </div>
      ) : metrics.evaluated_count === 0 ? (
        <div className="panel metrics-empty-panel">
          <EmptyState
            text={`${metrics.ground_truth_count} finding(s) have ground-truth labels, but none have a usable verification result yet (unverified: ${metrics.unverified_ground_truth_count}, inconclusive: ${metrics.excluded_inconclusive_count}). Verify those findings to compute metrics.`}
          />
        </div>
      ) : (
        <>
          <section className="metrics-kpi-grid">
            <MetricKpiCard
              accent="blue"
              label="Precision"
              value={formatMetricPercent(metrics.precision)}
              description="Of predicted positives, how many were correct"
            />
            <MetricKpiCard
              accent="green"
              label="Recall"
              value={formatMetricPercent(metrics.recall)}
              description="Of actual positives, how many were detected"
            />
            <MetricKpiCard
              accent="purple"
              label="F1 Score"
              value={formatMetricPercent(metrics.f1)}
              description="Balance between precision and recall"
            />
            <MetricKpiCard
              accent="orange"
              label="Evaluated Findings"
              value={String(metrics.evaluated_count)}
              description="Scored against ground truth"
            />
          </section>

          <section className="metrics-analysis-grid">
            <ConfusionMatrixPanel metrics={metrics} />
            <EvaluationCoveragePanel metrics={metrics} />
          </section>

          <section className="panel metrics-panel evaluation-details">
            <div className="panel-header">
              <div>
                <h3>Evaluation Details</h3>
                <p>Context for the numbers above</p>
              </div>
            </div>

            <div className="evaluation-details-grid">
              <div>
                <span>Scan</span>
                <strong>{scan.scanMeta.filename}</strong>
              </div>
              <div>
                <span>Ground truth labels</span>
                <strong>{metrics.ground_truth_count}</strong>
              </div>
              <div>
                <span>Evaluated findings</span>
                <strong>{metrics.evaluated_count}</strong>
              </div>
              <div>
                <span>Unverified labels</span>
                <strong>{metrics.unverified_ground_truth_count}</strong>
              </div>
              <div>
                <span>Inconclusive</span>
                <strong>{metrics.excluded_inconclusive_count}</strong>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

function MetricKpiCard({ accent, label, value, description }) {
  return (
    <div className={`metrics-kpi-card ${accent}`}>
      <div className="metrics-kpi-label">{label}</div>
      <div className="metrics-kpi-value">{value}</div>
      <div className="metrics-kpi-description">{description}</div>
    </div>
  );
}

function ConfusionMatrixPanel({ metrics }) {
  return (
    <div className="panel metrics-panel">
      <div className="panel-header">
        <div>
          <h3>Confusion Matrix</h3>
          <p>Verified status vs. labeled ground truth</p>
        </div>
      </div>

      <div className="confusion-matrix">
        <div className="confusion-matrix-corner" />
        <div className="confusion-matrix-col-header">
          Predicted
          <br />
          Positive
        </div>
        <div className="confusion-matrix-col-header">
          Predicted
          <br />
          Negative
        </div>

        <div className="confusion-matrix-row-header">
          Actual
          <br />
          Positive
        </div>
        <div className="confusion-matrix-cell good">
          <span className="confusion-matrix-value">
            {metrics.true_positive}
          </span>
          <span className="confusion-matrix-label">True Positive</span>
        </div>
        <div className="confusion-matrix-cell bad">
          <span className="confusion-matrix-value">
            {metrics.false_negative}
          </span>
          <span className="confusion-matrix-label">False Negative</span>
        </div>

        <div className="confusion-matrix-row-header">
          Actual
          <br />
          Negative
        </div>
        <div className="confusion-matrix-cell bad">
          <span className="confusion-matrix-value">
            {metrics.false_positive}
          </span>
          <span className="confusion-matrix-label">False Positive</span>
        </div>
        <div className="confusion-matrix-cell good">
          <span className="confusion-matrix-value">
            {metrics.true_negative}
          </span>
          <span className="confusion-matrix-label">True Negative</span>
        </div>
      </div>
    </div>
  );
}

function EvaluationCoveragePanel({ metrics }) {
  const coverage =
    metrics.ground_truth_count > 0
      ? `${Math.round(
          (metrics.evaluated_count / metrics.ground_truth_count) * 100
        )}%`
      : "N/A";

  return (
    <div className="panel metrics-panel">
      <div className="panel-header">
        <div>
          <h3>Evaluation Coverage</h3>
          <p>How much of the labeled data was scored</p>
        </div>
      </div>

      <div className="metric-line">
        <span>Ground truth labels</span>
        <strong>{metrics.ground_truth_count}</strong>
      </div>
      <div className="metric-line">
        <span>Evaluated</span>
        <strong>{metrics.evaluated_count}</strong>
      </div>
      <div className="metric-line">
        <span>Unverified</span>
        <strong>{metrics.unverified_ground_truth_count}</strong>
      </div>
      <div className="metric-line">
        <span>Inconclusive</span>
        <strong>{metrics.excluded_inconclusive_count}</strong>
      </div>

      <div className="evaluation-coverage-total">
        <span>Evaluation coverage</span>
        <strong>{coverage}</strong>
      </div>
    </div>
  );
}

/* =========================
   SETTINGS
========================= */

/**
 * Only exposes controls that actually do something.
 *
 * The backend API URL is a real, working setting: it's persisted to
 * localStorage and every subsequent api/client.js request reads it
 * (see getApiBaseUrl in api/client.js), so changing it here takes
 * effect immediately -- no rebuild required. Everything else on this
 * page is read-only information sourced from the actual parser/
 * verification code, not invented capabilities.
 */
function SettingsPage() {
  const [apiUrl, setApiUrlValue] = useState(getApiBaseUrl());
  const [saved, setSaved] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    const applied = setApiBaseUrl(apiUrl);
    setApiUrlValue(applied);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = () => {
    const defaultUrl = getDefaultApiBaseUrl();
    setApiBaseUrl("");
    setApiUrlValue(defaultUrl);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="settings-page">
      <div className="page-description">
        <div>
          <h2>Settings</h2>
          <p>Configuration that actually affects this application.</p>
        </div>
      </div>

      <div className="panel settings-panel">
        <div className="panel-header">
          <div>
            <h3>Backend API URL</h3>
            <p>
              Where the frontend sends every request. Persisted in this
              browser only.
            </p>
          </div>
        </div>

        <form className="settings-form" onSubmit={handleSave}>
          <div className="form-field">
            <label>API base URL</label>
            <input
              type="text"
              value={apiUrl}
              onChange={(e) => setApiUrlValue(e.target.value)}
              placeholder={getDefaultApiBaseUrl()}
            />
          </div>

          <div className="settings-actions">
            <button type="submit" className="new-scan-button">
              Save
            </button>
            <button
              type="button"
              className="view-button"
              onClick={handleReset}
            >
              Reset to default
            </button>
            {saved && <span className="settings-saved">Saved.</span>}
          </div>
        </form>
      </div>

      <div className="panel settings-panel">
        <div className="panel-header">
          <div>
            <h3>Application Information</h3>
            <p>What this build of VulnVerify actually supports.</p>
          </div>
        </div>

        <div className="metric-line">
          <span>Supported scanner inputs</span>
          <strong>OWASP ZAP (JSON), Burp Suite (XML)</strong>
        </div>
        <div className="metric-line">
          <span>Verification families</span>
          <strong>CSRF, SQLi (TIME_BASED / ERROR_BASED), Reflected XSS</strong>
        </div>
        <div className="metric-line">
          <span>Verification classifications</span>
          <strong>TRUE_POSITIVE, FALSE_POSITIVE, INCONCLUSIVE</strong>
        </div>
        <div className="metric-line">
          <span>Persistence</span>
          <strong>In-memory (backend restarts clear all scans)</strong>
        </div>
      </div>
    </div>
  );
}

/* =========================
   HELP
========================= */

function HelpPage() {
  return (
    <div className="help-page">
      <div className="page-description">
        <div>
          <h2>Help</h2>
          <p>How VulnVerify's verification workflow actually works.</p>
        </div>
      </div>

      <div className="panel help-panel">
        <h3>Workflow</h3>
        <ol className="help-steps">
          <li>
            <strong>Upload</strong> a ZAP JSON report or a Burp Suite XML
            report on the New Scan page.
          </li>
          <li>
            <strong>Normalize</strong> — the backend parses the report
            into a common finding format.
          </li>
          <li>
            <strong>Review findings</strong> on the Findings page.
          </li>
          <li>
            <strong>Enrichment</strong> — CWE/OWASP reference context is
            attached to each finding automatically.
          </li>
          <li>
            <strong>Verify</strong> each finding by replaying real
            requests against the target — nothing is confirmed from
            scanner output alone.
          </li>
          <li>
            <strong>Review verification results</strong> — each finding
            is classified TRUE_POSITIVE, FALSE_POSITIVE, or
            INCONCLUSIVE, with a stated reason.
          </li>
          <li>
            <strong>Risk/priority</strong> is calculated from the
            verification result and the scanner's own severity on the
            Prioritized Risks page.
          </li>
          <li>
            <strong>Evaluate against ground truth</strong> on the
            Metrics page — precision/recall/F1 are only ever computed
            when explicit ground-truth labels exist for the scan.
          </li>
        </ol>
      </div>

      <div className="panel help-panel">
        <h3>Verification types</h3>

        <div className="help-verification-type">
          <h4>CSRF</h4>
          <p>
            Replays the request and checks for state change, CSRF
            defenses (token rejection), and Origin/Referer enforcement.
          </p>
        </div>

        <div className="help-verification-type">
          <h4>SQLi — TIME_BASED</h4>
          <p>
            Requires a <strong>baseline parameter value</strong> (the
            original, pre-injection value of the tested parameter).
            The verifier replays baseline and time-delay payloads and
            compares response timing.
          </p>
        </div>

        <div className="help-verification-type">
          <h4>SQLi — ERROR_BASED</h4>
          <p>
            Does <strong>not</strong> require a baseline value. The
            verifier strips the scanner's payload to get a clean
            baseline request automatically, then replays the original
            scanner request and checks for database error signatures.
          </p>
        </div>

        <div className="help-verification-type">
          <h4>Reflected XSS</h4>
          <p>
            Replays one or more payload variants against the finding's
            query parameter and checks whether the payload is reflected
            unescaped in the response.
          </p>
        </div>
      </div>
    </div>
  );
}

/* =========================
   SHARED UI PRIMITIVES
========================= */

function ThemeToggle({ theme, onToggle }) {
  const isDark = theme === "dark";

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={onToggle}
      aria-pressed={isDark}
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      title={isDark ? "Switch to light mode" : "Switch to dark mode"}
    >
      {isDark ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
}

function ErrorBanner({ message }) {
  return (
    <div className="error-banner">
      <AlertTriangle size={14} />
      <span>{message}</span>
    </div>
  );
}

function EmptyState({ text }) {
  return <div className="empty-state">{text}</div>;
}

export default App;
