import { useState } from "react";
import {
  LayoutDashboard,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  FileText,
  BarChart3,
  Settings,
  HelpCircle,
  Plus,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock3,
  HelpCircle as UnknownIcon,
} from "lucide-react";

import "./App.css";
import { useScanData } from "./hooks/useScanData";
import {
  getVerifiableFamily,
  toBackendScannerValue,
  formatVerificationStatus,
  priorityClassName,
  statusClassName,
} from "./utils/verification";

function App() {
  const [activePage, setActivePage] = useState("Dashboard");
  const scan = useScanData();

  const menuItems = [
    { name: "Dashboard", icon: LayoutDashboard },
    { name: "New Scan", icon: ScanLine },
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
            <button
              className="new-scan-button"
              onClick={() => setActivePage("New Scan")}
            >
              <Plus size={17} />
              New Scan
            </button>

            <div className="scan-info">
              <strong>
                {scan.scanMeta ? scan.scanMeta.filename : "No scan yet"}
              </strong>
              <span>
                {scan.scanMeta
                  ? `${scan.scanMeta.scanner} · ${scan.scanMeta.finding_count} findings`
                  : "Upload a report to begin"}
              </span>
            </div>

            <div className="small-avatar">JD</div>
          </div>
        </header>

        {activePage === "Dashboard" ? (
          <Dashboard scan={scan} onNavigate={setActivePage} />
        ) : activePage === "New Scan" ? (
          <NewScan scan={scan} onUploaded={() => setActivePage("Findings")} />
        ) : activePage === "Findings" ? (
          <FindingsPage scan={scan} />
        ) : activePage === "Prioritized Risks" ? (
          <PrioritizedRisks scan={scan} />
        ) : activePage === "Reports" ? (
          <ReportsPage scan={scan} />
        ) : (
          <PlaceholderPage page={activePage} />
        )}
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
        <div className="panel scanner-panel">
          <div className="panel-header">
            <div>
              <h3>Scanner Output vs Verified Findings</h3>
              <p>
                {hasScan
                  ? `${rawCount} raw scanner findings, ${verifiedCount} verified so far`
                  : "Upload a scan to see this breakdown"}
              </p>
            </div>
          </div>

          <div className="bar-row">
            <div className="bar-label">
              <span>Raw scanner findings</span>
              <strong>{rawCount}</strong>
            </div>
            <div className="bar">
              <div className="bar-blue" style={{ width: "100%" }}>
                {rawCount}
              </div>
            </div>
          </div>

          <div className="bar-row">
            <div className="bar-label">
              <span>Confirmed true positives</span>
              <strong>{counts.truePositive}</strong>
            </div>
            <div className="bar">
              <div
                className="bar-green"
                style={{
                  width:
                    rawCount > 0
                      ? `${Math.max(
                          (counts.truePositive / rawCount) * 100,
                          counts.truePositive > 0 ? 4 : 0
                        )}%`
                      : "0%",
                }}
              >
                {counts.truePositive}
              </div>
            </div>
          </div>

          <div className="legend">
            <span>
              <i className="dot green"></i>
              Confirmed true positives — {counts.truePositive}
            </span>
            <span>
              <i className="dot red"></i>
              False positives removed — {counts.falsePositive}
            </span>
            <span>
              <i className="dot orange"></i>
              Inconclusive — {counts.inconclusive}
            </span>
          </div>
        </div>

        {/* PERFORMANCE -- backend has no ground-truth comparison
            endpoint, so these numbers cannot be computed from real
            data. Left as clearly-labeled demo data rather than
            fabricated. */}
        <div className="panel performance-panel">
          <div className="panel-header">
            <div>
              <h3>Verification Performance</h3>
              <p>Measured against labeled ground-truth data</p>
            </div>
            <span className="demo-badge">DEMO DATA</span>
          </div>

          <div className="metric-line">
            <span>Precision</span>
            <strong>96.0%</strong>
          </div>
          <div className="metric-line">
            <span>Recall</span>
            <strong>92.3%</strong>
          </div>
          <div className="metric-line">
            <span>F1 Score</span>
            <strong>94.1%</strong>
          </div>

          <div className="mini-matrix">
            <div></div>
            <strong>PRED. TRUE</strong>
            <strong>PRED. FALSE</strong>
            <strong>ACTUAL TRUE</strong>
            <span className="matrix-good">24</span>
            <span className="matrix-bad">2</span>
            <strong>ACTUAL FALSE</strong>
            <span className="matrix-bad">1</span>
            <span className="matrix-good">41</span>
          </div>
        </div>
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
          <input
            type="text"
            value={stateIndicator}
            onChange={(e) => setStateIndicator(e.target.value)}
            placeholder='Text expected in the response body on success, e.g. "Profile updated"'
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

function ReportsPage({ scan }) {
  const hasScan = Boolean(scan.scanId);
  const priorities = Object.values(scan.priorityById);
  const criticalCount = priorities.filter((p) => p.priority === "CRITICAL").length;
  const highCount = priorities.filter((p) => p.priority === "HIGH").length;

  const topFindings = [...priorities]
    .sort((a, b) => {
      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
      return order.indexOf(a.priority) - order.indexOf(b.priority);
    })
    .slice(0, 8);

  return (
    <div className="reports-page">
      <div className="page-description">
        <div>
          <h2>Security Reports</h2>
          <p>Generate and review verified security scan reports.</p>
        </div>
        <button
          className="new-scan-button"
          onClick={() => {
            // No report-generation endpoint exists on the backend yet;
            // this remains a placeholder action.
            alert(
              "Report generation is not yet implemented on the backend."
            );
          }}
        >
          Generate Report
        </button>
      </div>

      {!hasScan ? (
        <EmptyState text="No scan uploaded yet." />
      ) : (
        <>
          <div className="report-summary">
            <div className="summary-card">
              <span>Scan</span>
              <strong>{scan.scanMeta.filename}</strong>
            </div>
            <div className="summary-card">
              <span>Total Findings</span>
              <strong>{scan.findings.length}</strong>
            </div>
            <div className="summary-card">
              <span>Critical</span>
              <strong>{criticalCount}</strong>
            </div>
            <div className="summary-card">
              <span>High</span>
              <strong>{highCount}</strong>
            </div>
          </div>

          <div className="report-panel">
            <h3>Verified Security Report</h3>
            <p>
              Top prioritized findings from this scan, based on real
              verification results.
            </p>

            {topFindings.length === 0 ? (
              <EmptyState text="No findings verified yet." />
            ) : (
              topFindings.map((p) => {
                const finding = scan.findings.find(
                  (f) => f.finding_id === p.finding_id
                );
                return (
                  <div className="report-row" key={p.finding_id}>
                    <span>
                      {finding?.source?.original_name ||
                        finding?.vulnerability?.category}
                    </span>
                    <strong>{p.priority}</strong>
                  </div>
                );
              })
            )}
          </div>
        </>
      )}
    </div>
  );
}

/* =========================
   SHARED UI PRIMITIVES
========================= */

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

function PlaceholderPage({ page }) {
  return (
    <div className="placeholder">
      <div className="placeholder-icon">
        <HelpCircle size={38} />
      </div>
      <h2>{page}</h2>
      <p>This section is ready to be connected to the VeriTriage workflow.</p>
      <button className="new-scan-button">Coming in the next module</button>
    </div>
  );
}

export default App;
