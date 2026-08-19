import { useCallback, useEffect, useRef, useState } from "react";
import {
  uploadScan,
  getScans,
  getFindings,
  getVerifiedFindings,
  getDuplicateGroups,
  getEnrichment,
  getRiskPriorities,
  getMetrics,
  getVerificationProgress,
  loadDemoGroundTruth,
  verifyFinding,
} from "../api/client";

const VERIFICATION_POLL_INTERVAL_MS = 800;

// The backend already persists every scan (SQLite, see
// backend/storage/db.py) -- it survives a backend restart just fine.
// What did NOT survive was the frontend's own idea of "which scan am
// I currently looking at": scanId/scanMeta below are plain useState,
// so a full page reload reset them to null and the app landed back on
// an empty Dashboard, even though GET /scans still returned every
// persisted scan underneath. This key is the fix: the active scan_id
// is stored here on every successful upload/select, and restored via
// loadScan() on mount (see the effect near the bottom of this file).
const ACTIVE_SCAN_ID_STORAGE_KEY = "vulnverify.activeScanId";

function storeActiveScanId(scanId) {
  try {
    if (scanId) {
      localStorage.setItem(ACTIVE_SCAN_ID_STORAGE_KEY, scanId);
    } else {
      localStorage.removeItem(ACTIVE_SCAN_ID_STORAGE_KEY);
    }
  } catch {
    // Storage can be unavailable (private browsing, quota, etc.) --
    // the app still works for the current session, it just won't
    // survive a reload. Never let this crash the actual scan action.
  }
}

function readStoredActiveScanId() {
  try {
    return localStorage.getItem(ACTIVE_SCAN_ID_STORAGE_KEY);
  } catch {
    return null;
  }
}

/**
 * Central client-side state for the currently loaded scan.
 *
 * Holds exactly what the backend actually returns for one scan_id --
 * normalized findings, verified findings (keyed by finding_id),
 * enrichment (keyed by finding_id), risk priorities (keyed by
 * finding_id), and duplicate groups -- and nothing invented on top.
 *
 * findings/enrichment always cover every finding in the scan.
 * verifiedById/priorityById only ever contain entries for findings
 * that have actually been POSTed to /verify, matching the backend's
 * own coverage (see backend/api/risks.py and duplicate-groups'
 * shared pairing helper, which both silently skip unverified
 * findings).
 */
export function useScanData() {
  const [scanId, setScanId] = useState(null);
  const [scanMeta, setScanMeta] = useState(null);

  const [findings, setFindings] = useState([]);
  const [verifiedById, setVerifiedById] = useState({});
  const [enrichmentById, setEnrichmentById] = useState({});
  const [priorityById, setPriorityById] = useState({});
  const [duplicateGroups, setDuplicateGroups] = useState([]);
  const [metrics, setMetrics] = useState(null);

  const [loadingGroundTruth, setLoadingGroundTruth] = useState(false);
  const [groundTruthError, setGroundTruthError] = useState(null);

  const [uploadState, setUploadState] = useState("idle"); // idle | uploading | error
  const [uploadError, setUploadError] = useState(null);

  const [loadingScanData, setLoadingScanData] = useState(false);
  const [loadError, setLoadError] = useState(null);

  const [verifyingId, setVerifyingId] = useState(null);
  const [verifyErrorsById, setVerifyErrorsById] = useState({});

  // Automatic (post-upload) verification progress -- distinct from
  // manual per-finding verification above. null means "nothing to
  // show" (no automatic run has been started or observed for the
  // active scan yet, e.g. a scan loaded from Scan History with no
  // stored progress). See backend/services/auto_verification_service.py.
  const [verificationProgress, setVerificationProgress] = useState(null);

  // Tracks which scan_id the active poll loop belongs to, so a poll
  // started for one scan stops updating state the moment the user
  // switches to a different scan (upload or Scan History selection)
  // instead of racing it.
  const pollingScanIdRef = useRef(null);

  const refreshScanData = useCallback(async (id) => {
    setLoadingScanData(true);
    setLoadError(null);

    try {
      const [
        findingsRes,
        enrichmentRes,
        dedupRes,
        riskRes,
        verifiedRes,
        metricsRes,
      ] = await Promise.all([
        getFindings(id),
        getEnrichment(id),
        getDuplicateGroups(id),
        getRiskPriorities(id),
        getVerifiedFindings(id),
        getMetrics(id),
      ]);

      setFindings(findingsRes.findings);

      const enrichMap = {};
      for (const item of enrichmentRes.enrichments) {
        enrichMap[item.finding_id] = item;
      }
      setEnrichmentById(enrichMap);

      setDuplicateGroups(dedupRes.groups);

      const priorityMap = {};
      for (const item of riskRes.priorities) {
        priorityMap[item.finding_id] = item;
      }
      setPriorityById(priorityMap);

      const verifiedMap = {};
      for (const item of verifiedRes.findings) {
        verifiedMap[item.finding_id] = item;
      }
      setVerifiedById(verifiedMap);
      setMetrics(metricsRes);
    } catch (err) {
      setLoadError(err);
    } finally {
      setLoadingScanData(false);
    }
  }, []);

  /**
   * Polls GET /scans/{id}/verification-progress until automatic
   * verification reaches a terminal state (COMPLETED or FAILED), then
   * refreshes the rest of the scan's data via the existing
   * refreshScanData -- Dashboard/Findings/Prioritized Risks/Metrics/
   * Reports all update through that single, already-existing path,
   * nothing is duplicated here.
   *
   * Only ever started from startScan (a fresh upload) below -- never
   * from loadScan, so re-selecting a scan from Scan History cannot
   * trigger polling or the appearance of verification "running again".
   */
  const pollVerificationProgress = useCallback(
    async (id) => {
      pollingScanIdRef.current = id;

      while (true) {
        let progress;

        try {
          progress = await getVerificationProgress(id);
        } catch {
          // A transient poll failure should not abort the loop or
          // fabricate a terminal state -- just try again next tick.
          if (pollingScanIdRef.current !== id) return;
          await new Promise((resolve) =>
            setTimeout(resolve, VERIFICATION_POLL_INTERVAL_MS)
          );
          continue;
        }

        // The user switched to a different scan while this loop was
        // in flight -- stop silently rather than overwriting their
        // newly-selected scan's state.
        if (pollingScanIdRef.current !== id) return;

        setVerificationProgress(progress);

        if (
          progress.status === "COMPLETED" ||
          progress.status === "FAILED"
        ) {
          await refreshScanData(id);
          return;
        }

        await new Promise((resolve) =>
          setTimeout(resolve, VERIFICATION_POLL_INTERVAL_MS)
        );
      }
    },
    [refreshScanData]
  );

  const loadDemoGroundTruthData = useCallback(async () => {
    if (!scanId) return undefined;

    setLoadingGroundTruth(true);
    setGroundTruthError(null);

    try {
      const result = await loadDemoGroundTruth(scanId);
      await refreshScanData(scanId);
      return result;
    } catch (err) {
      setGroundTruthError(err);
      throw err;
    } finally {
      setLoadingGroundTruth(false);
    }
  }, [scanId, refreshScanData]);

  /**
   * Loads a scan the user already uploaded in a previous session,
   * identified only by scan_id (e.g. picked from Scan History).
   *
   * There is no dedicated "GET /scans/{scan_id}" metadata endpoint --
   * only the list endpoint (GET /scans) returns filename/scanner, so
   * this fetches that list and picks the matching entry out of it,
   * rather than inventing a new backend route. Everything else
   * (findings, verified findings, priorities, metrics, ...) is then
   * loaded the exact same way a fresh upload loads it, via
   * refreshScanData -- nothing is duplicated.
   */
  const loadScan = useCallback(
    async (id) => {
      setLoadingScanData(true);
      setLoadError(null);

      // Stale UI state from whatever scan was previously active
      // (verify errors keyed by that scan's finding_ids, an in-flight
      // verifying indicator, a leftover ground-truth error) should
      // not carry over to the newly selected scan.
      setVerifyingId(null);
      setVerifyErrorsById({});
      setGroundTruthError(null);
      setUploadError(null);

      // Stop any poll loop still running for a previously-active
      // scan, and clear its progress display -- selecting a scan from
      // Scan History must never re-trigger or appear to re-trigger
      // automatic verification.
      pollingScanIdRef.current = null;
      setVerificationProgress(null);

      try {
        const allScans = await getScans();
        const meta = allScans.find((item) => item.scan_id === id);

        if (!meta) {
          throw new Error(`Scan ${id} was not found on the backend.`);
        }

        setScanId(id);
        setScanMeta(meta);
        setUploadState("success");
        storeActiveScanId(id);
        await refreshScanData(id);

        // A single, non-polling check: shows this scan's already-
        // completed (or never-started) automatic verification result,
        // without starting a poll loop for it.
        try {
          const progress = await getVerificationProgress(id);
          setVerificationProgress(progress);
        } catch {
          setVerificationProgress(null);
        }

        return meta;
      } catch (err) {
        // The stored scan_id turned out to be invalid (e.g. it no
        // longer exists on the backend) -- forget it rather than
        // re-attempting and re-failing on every future reload.
        storeActiveScanId(null);
        setLoadError(err);
        throw err;
      } finally {
        setLoadingScanData(false);
      }
    },
    [refreshScanData]
  );

  const startScan = useCallback(
    async ({ scanner, file }) => {
      setUploadState("uploading");
      setUploadError(null);
      setVerificationProgress(null);

      try {
        const result = await uploadScan({ scanner, file });
        setScanId(result.scan_id);
        setScanMeta(result);
        setUploadState("success");
        storeActiveScanId(result.scan_id);
        await refreshScanData(result.scan_id);

        // Fire-and-forget: the backend already started automatic
        // verification for this freshly-uploaded scan in the
        // background (see backend/api/scans.py::upload_scan). This
        // only polls for and displays that progress -- it does not
        // start a second verification run.
        pollVerificationProgress(result.scan_id);

        return result;
      } catch (err) {
        setUploadState("error");
        setUploadError(err);
        throw err;
      }
    },
    [refreshScanData, pollVerificationProgress]
  );

  const verify = useCallback(
    async (findingId, trigger) => {
      if (!scanId) return undefined;

      setVerifyingId(findingId);
      setVerifyErrorsById((prev) => ({ ...prev, [findingId]: null }));

      try {
        const verified = await verifyFinding(scanId, findingId, trigger);

        setVerifiedById((prev) => ({
          ...prev,
          [findingId]: verified,
        }));

        // Deduplication and risk priority both depend on verification
        // state, so refresh them after a successful verify.
        await refreshScanData(scanId);

        return verified;
      } catch (err) {
        setVerifyErrorsById((prev) => ({
          ...prev,
          [findingId]: err,
        }));
        throw err;
      } finally {
        setVerifyingId(null);
      }
    },
    [scanId, refreshScanData]
  );

  // Restore the previously-active scan, once, on mount -- e.g. after
  // a full page reload. Silent on failure (a stale/deleted scan_id
  // is already cleaned up inside loadScan's own catch block above);
  // this is a best-effort convenience restoring what the user was
  // last looking at, not a required step, so it must never surface
  // its own error banner on top of whatever page first renders.
  useEffect(() => {
    const storedScanId = readStoredActiveScanId();

    if (storedScanId) {
      loadScan(storedScanId).catch(() => {});
    }
    // Intentionally empty deps: this must run exactly once, on
    // mount, regardless of loadScan's identity (which is itself
    // stable across renders since refreshScanData never changes).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    scanId,
    scanMeta,
    findings,
    verifiedById,
    enrichmentById,
    priorityById,
    duplicateGroups,
    metrics,
    uploadState,
    uploadError,
    loadingScanData,
    loadError,
    verifyingId,
    verifyErrorsById,
    verificationProgress,
    loadingGroundTruth,
    groundTruthError,
    startScan,
    loadScan,
    verify,
    refreshScanData,
    loadDemoGroundTruth: loadDemoGroundTruthData,
  };
}
