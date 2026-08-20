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
  ChevronsLeft,
  ChevronsRight,
  Menu,
  X,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock3,
  Download,
  Sun,
  Moon,
  FileSearch,
  Database,
  RefreshCw,
  Code2,
  Bug,
  Loader2,
  ChevronDown,
  Search,
  Target,
  Activity,
  ListChecks,
  UploadCloud,
  Rocket,
  LifeBuoy,
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

// Sidebar navigation, split into groups purely for visual hierarchy --
// every item still just calls onNavigate(name), the same
// setActivePage mechanism the flat list used before. Grouping/labels
// here must stay in sync with the activePage switch in App() below.
const PRIMARY_NAV_ITEMS = [
  { name: "Dashboard", icon: LayoutDashboard },
  { name: "New Scan", icon: ScanLine },
  { name: "Scan History", icon: History },
  { name: "Findings", icon: ShieldAlert },
  { name: "Prioritized Risks", icon: ShieldCheck },
  { name: "Reports", icon: FileText },
];

const EVALUATION_NAV_ITEMS = [
  { name: "Metrics", icon: BarChart3 },
  { name: "Settings", icon: Settings },
  { name: "Help", icon: HelpCircle },
];

const SIDEBAR_COLLAPSED_STORAGE_KEY = "vulnverify.sidebarCollapsed";

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

  // Desktop collapse (persisted, purely a display preference -- same
  // localStorage pattern theme.js already uses) and the mobile
  // drawer's open/closed state (never persisted -- a drawer should
  // always start closed on a fresh load, on any viewport).
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return localStorage.getItem(SIDEBAR_COLLAPSED_STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

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

  const toggleSidebarCollapsed = () => {
    setSidebarCollapsed((current) => {
      const next = !current;
      try {
        localStorage.setItem(
          SIDEBAR_COLLAPSED_STORAGE_KEY,
          next ? "1" : "0"
        );
      } catch {
        // Storage unavailable -- the preference still applies for
        // this session, it just won't survive a reload.
      }
      return next;
    });
  };

  const navigate = (page) => {
    setActivePage(page);
    // A drawer that stays open after the user picked a destination
    // would just be in the way on the next screen.
    setMobileNavOpen(false);
  };

  return (
    <div className={`app ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
      <Sidebar
        activePage={activePage}
        onNavigate={navigate}
        collapsed={sidebarCollapsed}
        onToggleCollapsed={toggleSidebarCollapsed}
        mobileOpen={mobileNavOpen}
        onCloseMobile={() => setMobileNavOpen(false)}
      />

      {/* MAIN CONTENT */}
      <main className="main">
        <TopBar
          activePage={activePage}
          theme={theme}
          onToggleTheme={toggleTheme}
          scan={scan}
          onNavigate={navigate}
          onOpenMobileNav={() => setMobileNavOpen(true)}
        />

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
   SIDEBAR
========================= */

function NavGroup({ items, activePage, onNavigate, collapsed }) {
  return (
    <nav className="nav-group">
      {items.map((item) => {
        const Icon = item.icon;
        const active = activePage === item.name;
        return (
          <button
            key={item.name}
            type="button"
            className={`nav-item ${active ? "active" : ""}`}
            onClick={() => onNavigate(item.name)}
            aria-current={active ? "page" : undefined}
            title={collapsed ? item.name : undefined}
          >
            <Icon size={18} />
            <span>{item.name}</span>
          </button>
        );
      })}
    </nav>
  );
}

function Sidebar({
  activePage,
  onNavigate,
  collapsed,
  onToggleCollapsed,
  mobileOpen,
  onCloseMobile,
}) {
  return (
    <>
      {/* Only rendered (and therefore only intercepts clicks) while
          the mobile drawer is actually open. */}
      {mobileOpen && (
        <div
          className="sidebar-overlay"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside
        className={`sidebar ${collapsed ? "collapsed" : ""} ${
          mobileOpen ? "mobile-open" : ""
        }`}
      >
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={21} />
          </div>
          {!collapsed && <span>VeriTriage</span>}

          <button
            type="button"
            className="sidebar-close-button"
            onClick={onCloseMobile}
            aria-label="Close navigation"
          >
            <X size={18} />
          </button>
        </div>

        <div className="sidebar-scroll">
          <NavGroup
            items={PRIMARY_NAV_ITEMS}
            activePage={activePage}
            onNavigate={onNavigate}
            collapsed={collapsed}
          />

          {!collapsed && (
            <div className="nav-section-label">EVALUATION</div>
          )}

          <NavGroup
            items={EVALUATION_NAV_ITEMS}
            activePage={activePage}
            onNavigate={onNavigate}
            collapsed={collapsed}
          />
        </div>

        <div className="sidebar-bottom">
          <div className="user-avatar">JD</div>
          {!collapsed && (
            <div>
              <strong>Jordan Diaz</strong>
              <small>Security Engineer</small>
            </div>
          )}
        </div>

        <button
          type="button"
          className="sidebar-collapse-toggle"
          onClick={onToggleCollapsed}
          aria-pressed={collapsed}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <ChevronsRight size={15} />
          ) : (
            <ChevronsLeft size={15} />
          )}
        </button>
      </aside>
    </>
  );
}

/* =========================
   TOP BAR
========================= */

function TopBar({
  activePage,
  theme,
  onToggleTheme,
  scan,
  onNavigate,
  onOpenMobileNav,
}) {
  return (
    <header className="topbar">
      <div className="topbar-heading">
        <button
          type="button"
          className="mobile-nav-toggle"
          onClick={onOpenMobileNav}
          aria-label="Open navigation"
        >
          <Menu size={20} />
        </button>

        <div>
          <span className="breadcrumb">VulnVerify / {activePage}</span>
          <h1>{activePage}</h1>
        </div>
      </div>

      <div className="top-actions">
        <ThemeToggle theme={theme} onToggle={onToggleTheme} />

        <button
          className="new-scan-button"
          onClick={() => onNavigate("New Scan")}
        >
          <Plus size={17} />
          <span className="new-scan-button-label">New Scan</span>
        </button>

        <button
          type="button"
          className="scan-info-button"
          onClick={() => onNavigate("Scan History")}
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

// Maps a finding's category to a representative icon -- purely
// decorative, never a substitute for the actual category text shown
// next to it. Anything not in this small, explicit list (CORS,
// INFORMATION_DISCLOSURE, SECURITY_MISCONFIGURATION, ...) falls back
// to a generic icon rather than guessing.
function categoryIcon(category) {
  if (category === "SQLI") return Database;
  if (category === "CSRF") return RefreshCw;
  if (category === "XSS") return Code2;
  return Bug;
}

// Same mapping as categoryIcon() above, as a real component rather
// than a component reference stashed in a variable -- avoids
// react-hooks/static-components flagging call sites that render it
// directly (as opposed to categoryIcon()'s existing callers, which
// only ever run inside a .map() callback).
function CategoryIcon({ category, size = 18 }) {
  if (category === "SQLI") return <Database size={size} />;
  if (category === "CSRF") return <RefreshCw size={size} />;
  if (category === "XSS") return <Code2 size={size} />;
  return <Bug size={size} />;
}

function Dashboard({ scan, onNavigate }) {
  const hasScan = Boolean(scan.scanId);
  // useScanData sets scanId/scanMeta synchronously on upload/select,
  // then loads findings/verified/etc. asynchronously -- this window
  // (a real scan is active, but its data hasn't arrived yet) is a
  // genuine loading state, not "0 of everything". FindingsPage
  // already distinguishes it the same way.
  const isLoading =
    hasScan && scan.loadingScanData && scan.findings.length === 0;

  const counts = verificationCounts(scan.findings, scan.verifiedById);
  const rawCount = scan.findings.length;
  const verifiedCount =
    counts.truePositive + counts.falsePositive + counts.inconclusive;
  const verifiedRate =
    rawCount > 0 ? Math.round((verifiedCount / rawCount) * 100) : null;
  const noiseReduction =
    verifiedCount > 0
      ? ((counts.falsePositive / verifiedCount) * 100).toFixed(1) + "%"
      : "N/A";

  const priorities = Object.values(scan.priorityById);
  const criticalHighCount = priorities.filter(
    (p) => p.priority === "CRITICAL" || p.priority === "HIGH"
  ).length;
  const topPriorities = priorities
    .filter((p) => p.priority === "CRITICAL" || p.priority === "HIGH")
    .slice(0, 5);

  const kpis = [
    {
      key: "total",
      icon: FileSearch,
      tone: "primary",
      label: "TOTAL FINDINGS",
      value: rawCount,
      subtitle: hasScan
        ? `From ${scannerDisplayName(scan.scanMeta.scanner)}`
        : null,
    },
    {
      key: "verified",
      icon: ShieldCheck,
      tone: "green",
      label: "VERIFIED",
      value: verifiedCount,
      subtitle: verifiedRate !== null ? `${verifiedRate}% of findings` : null,
    },
    {
      key: "false-positive",
      icon: XCircle,
      tone: "red",
      label: "FALSE POSITIVES",
      value: counts.falsePositive,
      subtitle: "Ruled out by replay evidence",
    },
    {
      key: "pending",
      icon: Clock3,
      tone: "orange",
      label: "PENDING VERIFICATION",
      value: counts.unverified,
      subtitle: "Not yet verified",
    },
    {
      key: "critical-high",
      icon: ShieldAlert,
      tone: "purple",
      label: "CRITICAL + HIGH",
      value: criticalHighCount,
      subtitle: "Confirmed priority risks",
    },
  ];

  return (
    <div className="dashboard">
      <div className="page-description dashboard-heading">
        <div>
          <h2>Security Verification Overview</h2>
          <p>
            {hasScan
              ? "Automated verification results for "
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

      {!hasScan ? (
        <DashboardEmptyState onNavigate={onNavigate} />
      ) : isLoading ? (
        <DashboardLoadingState />
      ) : (
        <>
          <section className="dashboard-kpi-grid">
            {kpis.map(({ key, ...kpi }) => (
              <DashboardKpiCard key={key} {...kpi} />
            ))}
          </section>

          <section className="dashboard-main-grid">
            <VerificationOverviewPanel
              counts={counts}
              rawCount={rawCount}
            />
            <DashboardSecondaryMetrics
              scan={scan}
              rawCount={rawCount}
              verifiedCount={verifiedCount}
              pending={counts.unverified}
              uniqueVulnerabilities={scan.duplicateGroups.length}
              noiseReduction={noiseReduction}
            />
          </section>

          <section className="dashboard-panel dashboard-findings-panel">
            <div className="panel-header">
              <div>
                <h3>Top Risks</h3>
                <p>
                  Highest-priority findings, ranked by confirmed
                  verification status and scanner severity
                </p>
              </div>
              <button
                className="view-button"
                onClick={() => onNavigate("Prioritized Risks")}
              >
                View all findings
                <ChevronRight size={16} />
              </button>
            </div>

            {topPriorities.length === 0 ? (
              <EmptyState text="No CRITICAL or HIGH priority findings yet. Verify findings to populate this list." />
            ) : (
              <div className="dashboard-findings-list">
                {topPriorities.map((p, index) => {
                  const finding = scan.findings.find(
                    (f) => f.finding_id === p.finding_id
                  );
                  const Icon = categoryIcon(finding?.vulnerability?.category);

                  return (
                    <div className="dashboard-finding-row" key={p.finding_id}>
                      <span className="dashboard-finding-rank">
                        {String(index + 1).padStart(2, "0")}
                      </span>

                      <div className="dashboard-finding-icon">
                        <Icon size={16} />
                      </div>

                      <div className="dashboard-finding-info">
                        <strong>
                          {finding?.source?.original_name ||
                            finding?.vulnerability?.category ||
                            "Unknown"}
                        </strong>
                        <small>{finding?.target?.normalized_url}</small>
                      </div>

                      <span
                        className={`priority ${priorityClassName(
                          p.priority
                        )}`}
                      >
                        {p.priority}
                      </span>

                      <span className="dashboard-finding-severity">
                        {p.scanner_severity}
                      </span>

                      <StatusBadge status={p.verification_status} />
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

function DashboardEmptyState({ onNavigate }) {
  return (
    <div className="dashboard-empty-state">
      <div className="dashboard-empty-icon">
        <ShieldCheck size={30} />
      </div>
      <h3>No scan loaded yet</h3>
      <p>
        Upload a ZAP or Burp Suite scanner report to automatically verify
        its findings and see real verification results here.
      </p>
      <button
        type="button"
        className="new-scan-button"
        onClick={() => onNavigate("New Scan")}
      >
        <Plus size={16} />
        Start a New Scan
      </button>
    </div>
  );
}

function DashboardLoadingState() {
  return (
    <div className="dashboard-loading-state">
      <Loader2 size={22} className="dashboard-loading-spinner" />
      <span>Loading scan data…</span>
    </div>
  );
}

function DashboardKpiCard({ icon: Icon, tone, label, value, subtitle }) {
  return (
    <div className={`dashboard-kpi-card ${tone}`}>
      <div className="dashboard-kpi-icon">
        <Icon size={18} />
      </div>
      <div className="dashboard-kpi-body">
        <div className="dashboard-kpi-label">{label}</div>
        <div className="dashboard-kpi-value">{value}</div>
        {subtitle && <div className="dashboard-kpi-subtitle">{subtitle}</div>}
      </div>
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
 * The Dashboard's large analysis panel: how this scan's findings were
 * classified. Reuses the same counts the KPI row above already
 * computed -- nothing here is calculated separately. A single
 * segmented bar (plain flexbox, proportional to each category's real
 * count -- no charting library) gives an at-a-glance summary above
 * the existing per-category breakdown rows.
 */
function VerificationOverviewPanel({ counts, rawCount }) {
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

  const nonZeroRows = rows.filter((row) => row.value > 0);

  return (
    <div className="dashboard-panel dashboard-verification-panel">
      <div className="panel-header">
        <div>
          <h3>Verification Overview</h3>
          <p>
            How this scan's {rawCount} finding{rawCount === 1 ? "" : "s"}{" "}
            {rawCount === 1 ? "was" : "were"} classified
          </p>
        </div>
      </div>

      {nonZeroRows.length > 0 && (
        <div className="dashboard-segmented-bar">
          {nonZeroRows.map((row) => (
            <div
              key={row.label}
              className={row.barClass}
              style={{ flexGrow: row.value }}
              title={`${row.label}: ${row.value}`}
            />
          ))}
        </div>
      )}

      <div className="dashboard-breakdown-rows">
        {rows.map((row) => (
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
        ))}
      </div>
    </div>
  );
}

/**
 * The Dashboard's secondary-metrics panel: scan identity plus the
 * remaining real, already-computed figures (unique vulnerabilities
 * after deduplication, false-positive/noise reduction) that don't
 * need top-level KPI-card prominence. Every field is read directly
 * from scan.scanMeta or values already computed by the caller -- no
 * timestamp is shown because the backend's scan record does not
 * carry one.
 */
function DashboardSecondaryMetrics({
  scan,
  rawCount,
  verifiedCount,
  pending,
  uniqueVulnerabilities,
  noiseReduction,
}) {
  return (
    <div className="dashboard-panel dashboard-summary-panel">
      <div className="panel-header">
        <div>
          <h3>Scan Summary</h3>
          <p>Current state of this scan</p>
        </div>
      </div>

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
      <div className="metric-line">
        <span>Unique vulnerabilities</span>
        <strong>{uniqueVulnerabilities}</strong>
      </div>
      <div className="metric-line">
        <span>Noise reduction</span>
        <strong>{noiseReduction}</strong>
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
  const [dragActive, setDragActive] = useState(false);

  const acceptFile = (file) => {
    if (!file) return;

    if (!/\.(json|xml)$/i.test(file.name)) {
      setFormError(
        "Unsupported file type. Please choose an OWASP ZAP JSON report or a Burp Suite XML report."
      );
      return;
    }

    setFileName(file.name);
    setFileObject(file);
    setFormError(null);
  };

  const handleFile = (e) => {
    acceptFile(e.target.files?.[0]);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragActive(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragActive(false);
    acceptFile(e.dataTransfer.files?.[0]);
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
      <section
        className={dragActive ? "upload-card drag-active" : "upload-card"}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <div className="upload-icon">
          <UploadCloud size={22} />
        </div>
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

        <AutoVerificationProgress progress={scan.verificationProgress} />
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
   AUTOMATIC VERIFICATION PROGRESS
========================= */

/**
 * Compact progress panel for the automatic verification that starts
 * on the backend right after a fresh upload finishes normalizing
 * (see backend/services/auto_verification_service.py). Reflects
 * exactly what GET /scans/{id}/verification-progress reports --
 * no invented percentages, durations, or estimated completion times.
 *
 * Renders nothing when there is nothing to show: no automatic run has
 * been observed for the active scan (NOT_STARTED, e.g. a scan loaded
 * from Scan History), or a completed run found no automatically-
 * verifiable findings at all.
 */
function AutoVerificationProgress({ progress }) {
  if (!progress || progress.status === "NOT_STARTED") {
    return null;
  }

  if (progress.status === "RUNNING") {
    const hasKnownTotal = progress.total > 0;
    const percent = hasKnownTotal
      ? Math.round((progress.completed / progress.total) * 100)
      : null;

    return (
      <div className="auto-verify-panel">
        <div className="auto-verify-panel-header">
          <span className="auto-verify-spinner" aria-hidden="true" />
          <strong>Verifying findings…</strong>
          {hasKnownTotal && (
            <span className="auto-verify-count">
              {progress.completed} / {progress.total}
            </span>
          )}
        </div>

        <div className="auto-verify-bar-track">
          <div
            className={
              hasKnownTotal
                ? "auto-verify-bar-fill"
                : "auto-verify-bar-fill auto-verify-bar-indeterminate"
            }
            style={hasKnownTotal ? { width: `${percent}%` } : undefined}
          />
        </div>

        {progress.current && (
          <div className="auto-verify-current">
            Current: {progress.current}
          </div>
        )}
      </div>
    );
  }

  if (progress.status === "COMPLETED") {
    if (progress.total === 0) {
      return null;
    }

    const counts = progress.counts || {};

    return (
      <div className="auto-verify-panel auto-verify-panel-complete">
        <div className="auto-verify-panel-header">
          <strong>Verification complete</strong>
        </div>
        <div className="auto-verify-summary">
          {progress.total} finding{progress.total === 1 ? "" : "s"} processed
        </div>
        <div className="auto-verify-counts">
          <span className="status-true-positive">
            TRUE POSITIVE: {counts.TRUE_POSITIVE ?? 0}
          </span>
          <span className="status-false-positive">
            FALSE POSITIVE: {counts.FALSE_POSITIVE ?? 0}
          </span>
          <span className="status-inconclusive">
            INCONCLUSIVE: {counts.INCONCLUSIVE ?? 0}
          </span>
        </div>
        {progress.errors && progress.errors.length > 0 && (
          <div className="auto-verify-current">
            {progress.errors.length} finding
            {progress.errors.length === 1 ? "" : "s"} could not be
            automatically verified and remain unverified.
          </div>
        )}
      </div>
    );
  }

  if (progress.status === "FAILED") {
    return (
      <div className="auto-verify-panel auto-verify-panel-failed">
        <div className="auto-verify-panel-header">
          <strong>Automatic verification failed</strong>
        </div>
        {progress.error && (
          <div className="auto-verify-current">{progress.error}</div>
        )}
      </div>
    );
  }

  return null;
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
                <div className="scan-history-icon">
                  <FileText size={15} />
                </div>
                <div>
                  <strong>{item.filename}</strong>
                  <small>{item.scan_id.slice(0, 8)}</small>
                </div>
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
  const [query, setQuery] = useState("");

  // Client-side only -- filters the already-loaded findings array by
  // whatever is already shown on each card (name, category, endpoint,
  // parameter). Never re-fetches or changes what the backend has
  // computed; purely a display-layer convenience for scans with many
  // findings.
  const trimmedQuery = query.trim().toLowerCase();
  const filtered = trimmedQuery
    ? scan.findings.filter((finding) => {
        const haystack = [
          finding.source.original_name,
          finding.vulnerability.category,
          finding.target.normalized_url,
          finding.target.parameter,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return haystack.includes(trimmedQuery);
      })
    : scan.findings;

  return (
    <div className="findings-page">
      <div className="page-description">
        <div>
          <h2>Security Findings</h2>
          <p>
            Detailed vulnerability findings identified during the security
            scan.
          </p>
        </div>
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

          <div className="findings-toolbar">
            <div className="findings-search">
              <Search size={14} />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search by name, category, endpoint, or parameter..."
                aria-label="Search findings"
              />
            </div>
            {trimmedQuery && (
              <span className="findings-toolbar-count">
                {filtered.length} of {scan.findings.length} shown
              </span>
            )}
          </div>

          {filtered.length === 0 ? (
            <EmptyState text="No findings match your search." />
          ) : (
            <div className="findings-list">
              {filtered.map((finding) => (
                <FindingCard
                  key={finding.finding_id}
                  index={scan.findings.indexOf(finding)}
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
          )}
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
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [panelOpen, setPanelOpen] = useState(false);
  const family = getVerifiableFamily(finding.vulnerability.category);
  const hasDetails = Boolean(
    verified || enrichment || finding.original_test?.evidence
  );

  return (
    <div className="finding-card">
      <div className="finding-top">
        <div className="finding-icon">
          <CategoryIcon category={finding.vulnerability.category} size={18} />
        </div>

        <div className="finding-heading">
          <h3>
            <span className="finding-rank">
              #{String(index + 1).padStart(2, "0")}
            </span>
            {finding.source.original_name || finding.vulnerability.category}
          </h3>
          <p>
            {finding.target.normalized_url}
            {finding.target.parameter
              ? ` · param: ${finding.target.parameter}`
              : ""}
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

      <div className="finding-badge-row">
        <span className="finding-badge">{finding.vulnerability.category}</span>
        <span className="finding-badge">
          {finding.vulnerability.normalized_severity}
        </span>
        <span className="finding-badge">
          {scannerDisplayName(finding.source.scanner)}
        </span>
        <StatusBadge status={verified?.classification?.status} />
      </div>

      {finding.original_test?.evidence && (
        <p className="finding-evidence">{finding.original_test.evidence}</p>
      )}

      <div className="finding-actions">
        <button
          className="view-button"
          onClick={() => setDetailsOpen((v) => !v)}
          disabled={!hasDetails}
          title={
            hasDetails
              ? undefined
              : "No CWE, verification result, or enrichment yet for this finding"
          }
        >
          <ChevronDown
            size={14}
            className={detailsOpen ? "finding-chevron open" : "finding-chevron"}
          />
          {detailsOpen ? "Hide details" : "View details"}
        </button>

        {family ? (
          <button
            className="view-button finding-verify-button"
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

      {detailsOpen && (
        <div className="finding-details">
          <div className="finding-details-grid">
            <div>
              <span>Severity (scanner)</span>
              <strong>{finding.vulnerability.normalized_severity}</strong>
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
            <div>
              <span>Scanner</span>
              <strong>{scannerDisplayName(finding.source.scanner)}</strong>
            </div>
          </div>

          {verified && (
            <VerificationResult verified={verified} priority={priority} />
          )}

          {enrichment && <EnrichmentDetails enrichment={enrichment} />}
        </div>
      )}

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

  const [defenseTestEnabled, setDefenseTestEnabled] = useState(false);
  const [defenseName, setDefenseName] = useState("");
  const [defenseLocation, setDefenseLocation] = useState("BODY");

  const [originTestEnabled, setOriginTestEnabled] = useState(false);
  const [originMutation, setOriginMutation] = useState("BOTH");

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

      if (defenseTestEnabled && !defenseName.trim()) {
        setLocalError(
          "The CSRF token/header field name is required when the defense test is enabled."
        );
        return;
      }

      const csrf = {
        state_check: {
          deterministic_acceptance_indicator: stateIndicator.trim(),
        },
      };

      if (defenseTestEnabled) {
        csrf.defense_test = {
          name: defenseName.trim(),
          location: defenseLocation,
        };
      }

      if (originTestEnabled) {
        csrf.origin_test = { mutation: originMutation };
      }

      onSubmit({ csrf });
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

          <label className="form-field-checkbox">
            <input
              type="checkbox"
              checked={defenseTestEnabled}
              onChange={(e) => setDefenseTestEnabled(e.target.checked)}
            />
            Also test a known CSRF token / custom header defense
          </label>
          <p className="form-field-help">
            Only enable this if the target application declares a
            specific anti-CSRF token or custom header field (e.g. a
            hidden <code>csrf_token</code> form field). The backend
            replays the request twice — once unchanged, once with this
            field removed — to check whether removing it causes a
            rejection. Leave this off for a tokenless form (like DVWA's
            Low-security CSRF page), where there is no such field to
            test.
          </p>
          {defenseTestEnabled && (
            <div className="form-subfields">
              <div className="form-field">
                <label>CSRF token / header field name</label>
                <input
                  type="text"
                  value={defenseName}
                  onChange={(e) => setDefenseName(e.target.value)}
                  placeholder="e.g. csrf_token"
                />
              </div>
              <div className="form-field">
                <label>Field location</label>
                <select
                  value={defenseLocation}
                  onChange={(e) => setDefenseLocation(e.target.value)}
                >
                  <option value="BODY">BODY</option>
                  <option value="QUERY">QUERY</option>
                  <option value="HEADER">HEADER</option>
                </select>
              </div>
            </div>
          )}

          <label className="form-field-checkbox">
            <input
              type="checkbox"
              checked={originTestEnabled}
              onChange={(e) => setOriginTestEnabled(e.target.checked)}
            />
            Also test cross-site Origin/Referer enforcement
          </label>
          <p className="form-field-help">
            Replays the request once unchanged and once with a
            controlled, attacker-style Origin and/or Referer header, to
            check whether the application relies on Origin/Referer
            checks to reject cross-site requests. Session/authentication
            data is preserved in both replays.
          </p>
          {originTestEnabled && (
            <div className="form-subfields">
              <div className="form-field">
                <label>Mutate</label>
                <select
                  value={originMutation}
                  onChange={(e) => setOriginMutation(e.target.value)}
                >
                  <option value="BOTH">Origin and Referer</option>
                  <option value="ORIGIN">Origin only</option>
                  <option value="REFERER">Referer only</option>
                </select>
              </div>
            </div>
          )}
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
    <div className="risks-page">
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
          <div className="risks-summary">
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

          <div className="risk-priority-list">
            {sorted.map((p, index) => {
              const finding = scan.findings.find(
                (f) => f.finding_id === p.finding_id
              );

              return (
                <div className="risk-priority-card" key={p.finding_id}>
                  <div className="risk-priority-top">
                    <span className="risk-priority-rank">
                      #{String(index + 1).padStart(2, "0")}
                    </span>
                    <div className="risk-priority-icon">
                      <CategoryIcon
                        category={finding?.vulnerability?.category}
                        size={18}
                      />
                    </div>
                    <div className="risk-priority-heading">
                      <h3>
                        {finding?.source?.original_name ||
                          finding?.vulnerability?.category ||
                          "Unknown finding"}
                      </h3>
                      <p>{finding?.target?.normalized_url}</p>
                    </div>
                    <span className={`priority ${priorityClassName(p.priority)}`}>
                      {p.priority}
                    </span>
                  </div>

                  <div className="risk-priority-meta">
                    <div>
                      <span>Verification status</span>
                      <StatusBadge status={p.verification_status} />
                    </div>
                    <div>
                      <span>Scanner severity</span>
                      <strong>{p.scanner_severity}</strong>
                    </div>
                  </div>

                  <p className="risk-priority-reason">{p.reason}</p>
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
              icon={Target}
              accent="blue"
              label="Precision"
              value={formatMetricPercent(metrics.precision)}
              description="Of predicted positives, how many were correct"
            />
            <MetricKpiCard
              icon={CheckCircle2}
              accent="green"
              label="Recall"
              value={formatMetricPercent(metrics.recall)}
              description="Of actual positives, how many were detected"
            />
            <MetricKpiCard
              icon={Activity}
              accent="purple"
              label="F1 Score"
              value={formatMetricPercent(metrics.f1)}
              description="Balance between precision and recall"
            />
            <MetricKpiCard
              icon={ListChecks}
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

function MetricKpiCard({ icon: Icon, accent, label, value, description }) {
  return (
    <div className={`metrics-kpi-card ${accent}`}>
      <div className="metrics-kpi-card-top">
        <div className="metrics-kpi-label">{label}</div>
        {Icon && (
          <div className="metrics-kpi-icon">
            <Icon size={16} />
          </div>
        )}
      </div>
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
          <strong>SQLite (scans survive a backend restart)</strong>
        </div>
      </div>
    </div>
  );
}

/* =========================
   HELP
========================= */

const HELP_WORKFLOW_STEPS = [
  {
    title: "Upload",
    text: "a ZAP JSON report or a Burp Suite XML report on the New Scan page.",
  },
  {
    title: "Normalize",
    text: "the backend parses the report into a common finding format.",
  },
  {
    title: "Review findings",
    text: "on the Findings page.",
  },
  {
    title: "Enrichment",
    text: "CWE/OWASP reference context is attached to each finding automatically.",
  },
  {
    title: "Verify",
    text: "each finding by replaying real requests against the target — nothing is confirmed from scanner output alone.",
  },
  {
    title: "Review verification results",
    text: "each finding is classified TRUE_POSITIVE, FALSE_POSITIVE, or INCONCLUSIVE, with a stated reason.",
  },
  {
    title: "Risk/priority",
    text: "is calculated from the verification result and the scanner's own severity on the Prioritized Risks page.",
  },
  {
    title: "Evaluate against ground truth",
    text: "on the Metrics page — precision/recall/F1 are only ever computed when explicit ground-truth labels exist for the scan.",
  },
];

const HELP_VERIFICATION_TYPES = [
  {
    icon: RefreshCw,
    title: "CSRF",
    text: "Replays the request and checks for state change, CSRF defenses (token rejection), and Origin/Referer enforcement.",
  },
  {
    icon: Database,
    title: "SQLi — TIME_BASED",
    text: 'Requires a baseline parameter value (the original, pre-injection value of the tested parameter). The verifier replays baseline and time-delay payloads and compares response timing.',
  },
  {
    icon: Database,
    title: "SQLi — ERROR_BASED",
    text: "Does not require a baseline value. The verifier strips the scanner's payload to get a clean baseline request automatically, then replays the original scanner request and checks for database error signatures.",
  },
  {
    icon: Code2,
    title: "Reflected XSS",
    text: "Replays one or more payload variants against the finding's query parameter and checks whether the payload is reflected unescaped in the response.",
  },
];

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
        <div className="help-panel-title">
          <Rocket size={16} />
          <h3>Workflow</h3>
        </div>
        <ol className="help-steps">
          {HELP_WORKFLOW_STEPS.map((step) => (
            <li key={step.title}>
              <strong>{step.title}</strong> — {step.text}
            </li>
          ))}
        </ol>
      </div>

      <div className="panel help-panel">
        <div className="help-panel-title">
          <ShieldCheck size={16} />
          <h3>Verification types</h3>
        </div>

        <div className="help-verification-grid">
          {HELP_VERIFICATION_TYPES.map(({ icon: Icon, title, text }) => (
            <div className="help-verification-type" key={title}>
              <div className="help-verification-icon">
                <Icon size={16} />
              </div>
              <div>
                <h4>{title}</h4>
                <p>{text}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="panel help-panel">
        <div className="help-panel-title">
          <LifeBuoy size={16} />
          <h3>Troubleshooting</h3>
        </div>

        <div className="help-verification-type">
          <div className="help-verification-icon">
            <FileSearch size={16} />
          </div>
          <div>
            <h4>Backend won't connect</h4>
            <p>
              Check the API base URL on the Settings page. The Dashboard
              and other data pages show a banner with the exact
              connection error when the backend can't be reached.
            </p>
          </div>
        </div>

        <div className="help-verification-type">
          <div className="help-verification-icon">
            <Loader2 size={16} />
          </div>
          <div>
            <h4>Scan or findings stuck loading</h4>
            <p>
              A scan that produced zero findings, or a very large report,
              can take a moment. If loading never finishes, check the
              browser console and the backend logs for the underlying
              error.
            </p>
          </div>
        </div>

        <div className="help-verification-type">
          <div className="help-verification-icon">
            <Clock3 size={16} />
          </div>
          <div>
            <h4>Verification stuck on INCONCLUSIVE</h4>
            <p>
              INCONCLUSIVE means the replay could not confirm or rule
              out the vulnerability with the given input (e.g. an
              unreachable target, or a baseline value that didn't
              distinguish injected from normal behavior) — it is a
              real, honest result, not an error.
            </p>
          </div>
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
