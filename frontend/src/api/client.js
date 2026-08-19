/**
 * Thin fetch wrapper for the VulnVerify backend API.
 *
 * Every function here maps 1:1 to a real, existing backend route --
 * no endpoints are invented. Response shapes are passed through
 * exactly as the backend returns them; nothing is renamed or
 * reshaped here.
 */

const DEFAULT_API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000/api/v1";

const API_BASE_URL_STORAGE_KEY = "vulnverify.apiBaseUrl";

/**
 * The backend base URL every request() call uses.
 *
 * Reads a runtime override from localStorage (set by the Settings
 * page) when present, falling back to the build-time
 * VITE_API_URL. This is a real, working setting -- not a display-only
 * field -- and takes effect on the next request, no rebuild required.
 */
export function getApiBaseUrl() {
  try {
    return (
      localStorage.getItem(API_BASE_URL_STORAGE_KEY) ||
      DEFAULT_API_BASE_URL
    );
  } catch {
    return DEFAULT_API_BASE_URL;
  }
}

export function setApiBaseUrl(url) {
  const trimmed = url.trim().replace(/\/+$/, "");

  if (!trimmed) {
    localStorage.removeItem(API_BASE_URL_STORAGE_KEY);
    return DEFAULT_API_BASE_URL;
  }

  localStorage.setItem(API_BASE_URL_STORAGE_KEY, trimmed);
  return trimmed;
}

export function getDefaultApiBaseUrl() {
  return DEFAULT_API_BASE_URL;
}

/**
 * Normalized error thrown for any non-2xx response or network
 * failure, so calling code can branch on `status` without knowing
 * fetch's Response/TypeError API.
 *
 * status is:
 *   - a number (400/404/422/etc.) for real HTTP error responses
 *   - null for network failures (backend unreachable, CORS block, etc.)
 */
export class ApiError extends Error {
  constructor(message, { status = null, detail = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/**
 * FastAPI's own error shapes differ by status code:
 *   - 400/404: {"detail": "<string>"}
 *   - 422:     {"detail": [{"msg": "...", "loc": [...]}, ...]}
 * This normalizes both into a single readable string.
 */
function extractDetailMessage(body) {
  if (body == null) return null;

  const detail = body.detail;

  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    return detail
      .map((item) => item?.msg || JSON.stringify(item))
      .join("; ");
  }

  return null;
}

async function request(path, options = {}) {
  let response;

  const baseUrl = getApiBaseUrl();

  try {
    response = await fetch(`${baseUrl}${path}`, options);
  } catch {
    throw new ApiError(
      `Could not reach the backend at ${baseUrl}. ` +
        "Is it running?",
      { status: null }
    );
  }

  let body = null;
  const text = await response.text();

  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }

  if (!response.ok) {
    const detailMessage = extractDetailMessage(body);

    throw new ApiError(
      detailMessage || `Request failed (${response.status})`,
      { status: response.status, detail: body?.detail ?? null }
    );
  }

  return body;
}

/** POST /scans -- multipart/form-data upload of a scanner report. */
export function uploadScan({ scanner, file }) {
  const formData = new FormData();
  formData.append("scanner", scanner);
  formData.append("file", file);

  return request("/scans", {
    method: "POST",
    body: formData,
  });
}

/** GET /scans/{scan_id}/status */
export function getScanStatus(scanId) {
  return request(`/scans/${scanId}/status`);
}

/** GET /scans/{scan_id}/findings -> {scan_id, count, findings[]} */
export function getFindings(scanId) {
  return request(`/scans/${scanId}/findings`);
}

/**
 * POST /scans/{scan_id}/findings/{finding_id}/verify
 * trigger must be exactly one of {csrf, sqli, xss} per the backend's
 * VerificationTriggerRequest contract. Returns a single
 * VerifiedFinding (not wrapped in an envelope).
 */
export function verifyFinding(scanId, findingId, trigger) {
  return request(
    `/scans/${scanId}/findings/${findingId}/verify`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(trigger),
    }
  );
}

/** GET /scans/{scan_id}/verified-findings -> {scan_id, count, findings[]} */
export function getVerifiedFindings(scanId) {
  return request(`/scans/${scanId}/verified-findings`);
}

/** GET /scans/{scan_id}/duplicate-groups -> {scan_id, count, groups[]} */
export function getDuplicateGroups(scanId) {
  return request(`/scans/${scanId}/duplicate-groups`);
}

/** GET /scans/{scan_id}/enrichment -> {scan_id, count, enrichments[]} */
export function getEnrichment(scanId) {
  return request(`/scans/${scanId}/enrichment`);
}

/** GET /scans/{scan_id}/risk-priorities -> {scan_id, count, priorities[]} */
export function getRiskPriorities(scanId) {
  return request(`/scans/${scanId}/risk-priorities`);
}

/** GET /scans/{scan_id}/metrics -> EvaluationMetrics */
export function getMetrics(scanId) {
  return request(`/scans/${scanId}/metrics`);
}

/** GET /scans/{scan_id}/ground-truth -> {scan_id, count, labels[]} */
export function getGroundTruth(scanId) {
  return request(`/scans/${scanId}/ground-truth`);
}

/**
 * POST /scans/{scan_id}/ground-truth
 * labels: [{finding_id, expected_status, note?}]
 */
export function submitGroundTruth(scanId, labels) {
  return request(`/scans/${scanId}/ground-truth`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ labels }),
  });
}

/**
 * POST /scans/{scan_id}/ground-truth/demo
 * Matches the backend's bundled demo dataset against this scan's
 * findings; returns {scan_id, count, labels[]} (count may be 0).
 */
export function loadDemoGroundTruth(scanId) {
  return request(`/scans/${scanId}/ground-truth/demo`, {
    method: "POST",
  });
}

/** GET /scans/{scan_id}/report -> ScanReport */
export function getScanReport(scanId) {
  return request(`/scans/${scanId}/report`);
}
