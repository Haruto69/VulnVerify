import { useCallback, useState } from "react";
import {
  uploadScan,
  getScans,
  getFindings,
  getVerifiedFindings,
  getDuplicateGroups,
  getEnrichment,
  getRiskPriorities,
  getMetrics,
  loadDemoGroundTruth,
  verifyFinding,
} from "../api/client";

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

      try {
        const allScans = await getScans();
        const meta = allScans.find((item) => item.scan_id === id);

        if (!meta) {
          throw new Error(`Scan ${id} was not found on the backend.`);
        }

        setScanId(id);
        setScanMeta(meta);
        setUploadState("success");
        await refreshScanData(id);

        return meta;
      } catch (err) {
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

      try {
        const result = await uploadScan({ scanner, file });
        setScanId(result.scan_id);
        setScanMeta(result);
        setUploadState("success");
        await refreshScanData(result.scan_id);
        return result;
      } catch (err) {
        setUploadState("error");
        setUploadError(err);
        throw err;
      }
    },
    [refreshScanData]
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
    loadingGroundTruth,
    groundTruthError,
    startScan,
    loadScan,
    verify,
    refreshScanData,
    loadDemoGroundTruth: loadDemoGroundTruthData,
  };
}
