/**
 * Small helpers translating between the backend's exact contract
 * values (backend/models/normalized_finding.py,
 * backend/models/verification_trigger.py,
 * backend/models/verified_finding.py) and display-friendly text.
 *
 * Nothing here invents new backend behavior -- it only maps the
 * fixed set of values the backend already returns/accepts.
 */

// Only these three categories have any verification path at all
// (backend/api/findings.py dispatches on trigger.csrf/sqli/xss and
// each handler 400s for any other category). CORS, INFORMATION_
// DISCLOSURE, SECURITY_MISCONFIGURATION, INFORMATIONAL, and OTHER
// are not verifiable via this endpoint today.
export function getVerifiableFamily(category) {
  if (category === "SQLI") return "sqli";
  if (category === "CSRF") return "csrf";
  if (category === "XSS") return "xss";
  return null;
}

// New Scan's scanner dropdown shows product names; the backend only
// accepts the exact strings "ZAP" or "BURP" (backend/api/scans.py
// ALLOWED_SCANNERS).
export function toBackendScannerValue(uiLabel) {
  if (uiLabel === "OWASP ZAP") return "ZAP";
  if (uiLabel === "Burp Suite") return "BURP";
  return uiLabel;
}

// backend/models/verified_finding.py VerificationStatus
export function formatVerificationStatus(status) {
  if (!status) return "NOT VERIFIED";
  return status.replace(/_/g, " ");
}

// backend/models/risk_assessment.py PriorityLevel -- used as a CSS
// class suffix (.priority.critical, .priority.medium, etc.)
export function priorityClassName(priority) {
  return priority ? priority.toLowerCase() : "unknown";
}

export function statusClassName(status) {
  if (!status) return "not-verified";
  return status.toLowerCase().replace(/_/g, "-");
}
