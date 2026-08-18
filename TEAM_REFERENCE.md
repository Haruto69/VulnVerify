# VeriTriage — Team Reference Document
**Internal Use Only | Not a Presentation Deck**

---

## 1. PROJECT AT A GLANCE

**What are we building?**
An automated verification system that catches false positives in ZAP and Burp security scanner reports. We normalize scanner findings, replay them against the target application, and verify whether each finding is a genuine vulnerability or a false alarm.

**What problem are we solving?**
Security scanners like ZAP and Burp produce many false positives—findings that look vulnerable but aren't actually exploitable. Teams waste time investigating and testing these findings. VeriTriage filters the noise automatically.

**What makes the approach useful?**
Rather than guessing based on scanner patterns, we actually *replay the attack* against your app and collect evidence (timing delays, error messages, state changes). If the evidence proves the vulnerability exists, it's a TRUE_POSITIVE. If not, it's FALSE_POSITIVE or INCONCLUSIVE. This is deterministic and reproducible.

**What is the main output?**
An API that accepts scanner reports (ZAP or Burp XML/JSON), returns a list of verified findings with classification (TRUE_POSITIVE / FALSE_POSITIVE / INCONCLUSIVE), confidence scores, and evidence collected during replay.

---

## 2. THE PIPELINE

```
ZAP / Burp Report
        ↓
    Normalization
        ↓
     Replay
        ↓
    Verification
        ↓
    Deduplication
        ↓
    Enrichment
        ↓
   Risk/Priority
        ↓
      API
        ↓
    Frontend
```

### **Scanner**
- **Status**: ✅ **Implemented**
- Accepts ZAP JSON and Burp XML reports via API file upload
- `/api/v1/scans` endpoint

### **Normalization**
- **Status**: ✅ **Implemented**
- Converts ZAP/Burp findings → unified `NormalizedFinding` structure
- Preserves scanner-specific metadata + standardizes common fields (severity, confidence, URL, parameter, etc.)
- Assigned unique `finding_id` per finding

### **Replay**
- **Status**: ✅ **Implemented**
- Reconstructs HTTP requests from normalized findings
- Executes replay against target using httpx (with timeouts, retries)
- Collects raw response (status, headers, body, timing)
- Separate replay engines for CSRF, SQLi TIME_BASED, XSS

### **Verification**
- **Status**: ✅ **Implemented (CSRF, SQLi TIME_BASED, XSS)**
- Analyzes replay results to classify findings
- CSRF: Checks defense bypass, origin policies, state acceptance
- SQLi TIME_BASED: Compares baseline vs. injected timing with statistical confidence
- XSS: Checks payload reflection and execution context
- Returns `VerifiedFinding` with status + confidence + evidence

### **Deduplication**
- **Status**: ❌ **Not Implemented**
- **Planned purpose**: Group identical or near-duplicate findings from different scanners
- Currently disabled; flagged in tests but no logic exists

### **Enrichment**
- **Status**: ❌ **Not Implemented**
- **Planned purpose**: Add CWE details, remediation guidance, threat intelligence
- No code present

### **Risk / Prioritization**
- **Status**: ❌ **Not Implemented**
- **Planned purpose**: Score risk based on CVSS, exploitability, asset criticality
- `/api/v1/risks` endpoint exists but is empty

### **API**
- **Status**: ✅ **Implemented**
- RESTful endpoints for scan management, finding retrieval, verification trigger

### **Frontend**
- **Status**: ❌ **Not Started**
- No frontend code present in repository

---

## 3. TECH STACK

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Backend** | Python 3.x | Core logic |
| **Web Framework** | FastAPI 0.141.1 | REST API server |
| **Data Validation** | Pydantic 2.13.4 | Request/response schemas, NormalizedFinding models |
| **Network** | httpx 0.28.1 | HTTP replay execution |
| **Storage** | Python dicts (in-memory) | Scans, normalized findings, verified findings |
| **Testing** | pytest 9.1.1 | Unit + integration tests (53 test files) |
| **Async** | anyio 4.14.2, Starlette 1.6.0 | Concurrent request handling |
| **Scanner Formats** | XML (Burp), JSON (ZAP) | Input parsing |
| **URL Parsing** | urllib (stdlib) + urlsplit | Request reconstruction |
| **Security** | None yet | No DB encryption, no auth on API |

---

## 4. BACKEND ARCHITECTURE

```
vulnverify-backend/
├── backend/
│   ├── api/
│   │   ├── scans.py        (scan upload, finding lists)
│   │   └── findings.py      (verification trigger endpoint)
│   ├── models/
│   │   ├── normalized_finding.py
│   │   ├── verified_finding.py
│   │   ├── replay_result.py
│   │   └── verification_trigger.py
│   ├── parsers/
│   │   ├── base.py
│   │   ├── zap.py
│   │   └── burp.py
│   ├── services/
│   │   ├── normalization_service.py
│   │   ├── scan_service.py         (in-mem storage ops)
│   │   ├── pipeline_service.py     (orchestration)
│   │   ├── csrf_verification_service.py
│   │   ├── sqli_verification_service.py
│   │   └── xss_verification_service.py
│   ├── replay/
│   │   ├── engine.py               (generic HTTP replay)
│   │   ├── csrf.py                 (CSRF-specific replay)
│   │   ├── sqli_time_based.py      (TIME_BASED replay)
│   │   ├── xss.py                  (XSS replay)
│   │   ├── request_builder.py
│   │   └── csrf_state_check.py
│   ├── verification/
│   │   ├── csrf.py                 (CSRF classifier)
│   │   ├── sqli_time_based.py      (TIME_BASED classifier)
│   │   ├── sqli_*.py               (Boolean, Error, Union research)
│   │   ├── xss.py                  (XSS classifier)
│   │   └── [many context/helper files]
│   ├── storage/
│   │   ├── repository.py           (in-mem store)
│   │   └── sqli_evidence_repository.py
│   └── main.py                     (FastAPI app)
└── tests/                          (53 test files)
```

### **Data Flow**

1. **Upload** → `POST /api/v1/scans` (multipart: scanner name + file)
2. **Parser Selection** → `get_parser(scanner)` (ZAP or Burp)
3. **Normalization** → Parser converts raw findings → `NormalizedFinding[]`
4. **Storage** → `repository.py` stores in-memory: scans{}, normalized_findings{}, verified_findings{}
5. **Retrieval** → `GET /api/v1/scans/{scan_id}/findings` returns normalized list
6. **Verification Trigger** → `POST /api/v1/scans/{scan_id}/findings/{finding_id}/verify` with verification config
7. **Replay** → `replay_engine.py` executes HTTP request
8. **Classification** → Vulnerability-specific verifier (csrf.py, sqli_time_based.py, xss.py) → `VerifiedFinding`
9. **Storage** → Verified findings persisted
10. **Retrieval** → `GET /api/v1/scans/{scan_id}/verified-findings`

---

## 5. NORMALIZATION

**Why it exists:**
ZAP reports JSON. Burp reports XML. They use different field names, severity scales, confidence formats. We need one canonical structure to feed the rest of the pipeline.

**How it works:**
- Parser reads raw report format (JSON or XML)
- Maps scanner fields → `NormalizedFinding` Pydantic model
- Severity: raw value preserved + normalized to [INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL]
- Confidence: raw value preserved + normalized to [LOW, MEDIUM, HIGH, CONFIRMED]
- Creates canonical `HttpRequest` + `HttpResponse` objects
- Generates unique `finding_id` per finding
- Preserves scanner metadata in `FindingSource` + generic `metadata` dict

**What NormalizedFinding contains (high-level):**
```python
- scan_id, finding_id
- source (scanner name, original finding ID, name)
- vulnerability (category: SQLI|CSRF|XSS, severity, confidence, CWE)
- target (URL, host, path, parameter, parameter_location)
- original_test (payload, evidence from scanner)
- request (method, URL, headers, cookies, body, query params)
- response (status, headers, body, timing)
- context (auth required?, session required?)
- references, metadata
```

**Why scanner-specific metadata is preserved:**
Later stages may need raw evidence (e.g., scanner's original confidence). Deduplication logic may reference scanner fields.

---

## 6. VERIFICATION

**Core concept:**
We replay the exact scanner-reported attack and observe whether it actually works. Evidence (response codes, timing differences, observable effects) proves or disproves the vulnerability.

### **Verification Status Outcomes**
- **TRUE_POSITIVE**: Evidence confirms the vulnerability is exploitable
- **FALSE_POSITIVE**: Evidence proves the attack did not succeed
- **INCONCLUSIVE**: Insufficient or conflicting evidence; cannot determine

### **Confidence**
A float [0.0 - 1.0] scoring how confident we are in the classification. Built from deterministic rules, not guesses.

### **Evidence**
Collection of indicators (string observations) + optional request/response references for inspection.

---

### **CSRF Verification**

**What we test:**
- Is the endpoint state-changing? (POST/PUT/PATCH/DELETE → likely yes)
- Does a baseline replay work? (Forged request accepted?)
- Can we remove a CSRF token and still bypass? (Defense test)
- Does changing Origin/Referer reject the request? (Origin policy test)
- Is there a post-request state indicator? (Acceptance indicator)

**How it works:**
1. Collect baseline replay (normal forged request)
2. (Optional) Remove suspected CSRF defense + replay
3. (Optional) Mutate Origin/Referer + replay
4. (Optional) Check for success indicator in response
5. Apply deterministic CSRF confidence scoring rules
6. Classify as TRUE_POSITIVE / FALSE_POSITIVE / INCONCLUSIVE

**Evidence collected:**
- Whether baseline request was accepted
- Whether defense (if removed) was bypassed
- Whether origin/referer policy enforced
- Success indicator matched

---

### **SQLi TIME_BASED Verification**

**What we test:**
Inject a payload that introduces a time delay if SQL injection succeeds. Compare timing between:
- **Baseline samples**: Request with benign parameter value (no delay expected)
- **Verification samples**: Request with injection payload (delay expected if vulnerable)

**How it works:**
1. Build baseline request (known-clean parameter value supplied by user)
2. Execute baseline N times, collect response times → baseline distribution
3. Execute injection request N times, collect response times → verification distribution
4. Statistical analysis: does verification distribution show significant delay?
5. Account for network/server jitter; require clear signal
6. Classify as TRUE_POSITIVE (delay observed) / FALSE_POSITIVE (no delay) / INCONCLUSIVE (unclear)

**Currently implemented mechanisms in repo:**
- **TIME_BASED**: Timing analysis (fully implemented) ✅
- **Boolean-based**: Response size/content differs based on SQL condition (code present, research-stage)
- **Error-based**: SQL error messages appear in response (code present, research-stage)
- **Union-based**: UNION SELECT results appear in response (code present, research-stage)

**API Only exposes TIME_BASED** via verification endpoint.

---

### **XSS Verification**

**What we test:**
Is the injection payload reflected in the response? Can it execute in the browser context where it appears?

**How it works:**
1. Replay the request with XSS payload
2. Check if payload appears in response body
3. Analyze HTML context (is it in an attribute? inside a tag? in JS string?)
4. Determine if payload can escape the context and execute
5. Classify as TRUE_POSITIVE / FALSE_POSITIVE / INCONCLUSIVE

**Evidence collected:**
- Payload reflection confirmed
- Execution context (script, attribute, event handler, etc.)
- Encoding/escaping observed

---

## 7. DEDUPLICATION

**Why we need it:**
ZAP finds SQLi in parameter `id`. Burp finds the same SQLi in parameter `id`. Two scanner findings, one vulnerability. We should report it once with higher confidence.

**Where it sits in the pipeline:**
Logically after verification, before enrichment. (Currently disabled.)

**Intended purpose:**
- Fuzzy match findings (same URL, similar parameter, same vulnerability type)
- Group by application-level impact (same resource affected)
- Preserve evidence from both scanners
- Return deduplicated list

**Current status:**
❌ Not implemented. Only mentioned in test comments (`test_burp_parser.py`: "Multiple issues / no deduplication").

---

## 8. ENRICHMENT + RISK

### **Enrichment (Not Implemented)**
**Planned purpose:**
- Add CWE ID and description
- Link to OWASP Top 10 category
- Provide remediation guidance
- Add external references (CVE, advisory links)

### **Risk / Prioritization (Not Implemented)**
**Planned purpose:**
- Calculate CVSS score
- Factor in exploitability (network vs. local, auth required?)
- Assess business impact (affects login? payment? sensitive data?)
- Prioritize findings by risk score for remediation queue

**Current status:**
❌ `/api/v1/risks` endpoint exists in router but `risks.py` is empty.

---

## 9. API

### **Implemented Endpoints**

#### **1. Upload Scan**
```
POST /api/v1/scans
Content-Type: multipart/form-data

Parameters:
  scanner: "ZAP" | "BURP"
  file: binary (JSON for ZAP, XML for Burp)

Response:
  {
    "scan_id": "abc123...",
    "filename": "scan.json",
    "scanner": "ZAP",
    "status": "NORMALIZED",
    "finding_count": 42
  }
```

#### **2. List All Scans**
```
GET /api/v1/scans

Response:
  [
    { "scan_id": "...", "scanner": "ZAP", "status": "NORMALIZED", ... },
    ...
  ]
```

#### **3. Get Scan Status**
```
GET /api/v1/scans/{scan_id}/status

Response:
  {
    "scan_id": "abc123...",
    "status": "NORMALIZED",
    "error": null
  }
```

#### **4. List Normalized Findings**
```
GET /api/v1/scans/{scan_id}/findings

Response:
  {
    "scan_id": "abc123...",
    "count": 42,
    "findings": [
      { "finding_id": "...", "vulnerability": {...}, "target": {...}, ... },
      ...
    ]
  }
```

#### **5. Verify a Finding**
```
POST /api/v1/scans/{scan_id}/findings/{finding_id}/verify
Content-Type: application/json

Request body (CSRF example):
  {
    "csrf": {
      "state_check": {
        "deterministic_acceptance_indicator": "success message"
      },
      "defense_test": {
        "name": "csrf_token",
        "location": "HEADER"
      },
      "browser_context_required": false
    },
    "timeout_seconds": 10.0
  }

Request body (SQLi TIME_BASED example):
  {
    "sqli": {
      "time_based": {
        "baseline_parameter_value": "1"
      }
    },
    "timeout_seconds": 10.0
  }

Response:
  {
    "finding_id": "...",
    "classification": {
      "status": "TRUE_POSITIVE",
      "confidence": 0.95,
      "reason": "..."
    },
    "evidence": {
      "indicators": ["baseline_accepted", "defense_bypassed"],
      "request_reference": "...",
      "response_reference": "..."
    },
    "verification_method": "CSRF"
  }
```

#### **6. List Verified Findings**
```
GET /api/v1/scans/{scan_id}/verified-findings

Response:
  {
    "scan_id": "abc123...",
    "count": 15,
    "findings": [
      { "finding_id": "...", "classification": {...}, ... },
      ...
    ]
  }
```

#### **7. Get Single Verified Finding**
```
GET /api/v1/scans/{scan_id}/verified-findings/{finding_id}

Response:
  { "finding_id": "...", "classification": {...}, ... }
```

---

## 10. SAMPLE DATA FLOW

```
User uploads Burp XML containing SQLi finding
        ↓
BurpParser.parse() → NormalizedFinding(
  scan_id="s1",
  finding_id="f1",
  vulnerability={category: "SQLI"},
  target={url: "http://target/api/users?id=1", parameter: "id"},
  original_test={payload: "1' OR '1'='1"},
  request={method: "GET", ...}
)
        ↓
stored in repository.normalized_findings["s1"]["f1"]
        ↓
User calls /verify with:
  {
    "sqli": {
      "time_based": {
        "baseline_parameter_value": "1"
      }
    }
  }
        ↓
Replay engine:
  - Constructs baseline request (id=1)
  - Executes, measures response time ~100ms (baseline_samples: [98, 102, 99, 101])
  - Constructs injected request (id=1' AND SLEEP(5)-- -)
  - Executes, measures response time ~5100ms (verification_samples: [5098, 5102, 5100, 5103])
        ↓
Verification:
  - Statistical test: delay is significant
  - Evidence: [sleep_delay_confirmed]
  - Classification: TRUE_POSITIVE, confidence=0.92
  - VerifiedFinding created and stored
        ↓
User retrieves /verified-findings, sees TRUE_POSITIVE with evidence
```

---

## 11. COMMON JUDGE QUESTIONS

| Question | Answer |
|----------|--------|
| **Why can't we just trust ZAP/Burp?** | Scanners use pattern matching + heuristics. They flag anything that *looks* vulnerable. Only replay proves if it's actually exploitable. |
| **How do you detect false positives?** | We replay the attack. If it fails (wrong status, no timing delay, payload not reflected), it's false positive. |
| **Why replay the request?** | Direct evidence beats heuristics. Replay shows what actually happens vs. what scanner guessed. |
| **What happens when evidence is insufficient?** | We return INCONCLUSIVE. Judges the finding by what we can prove, not by guesses. |
| **Why normalize scanner output?** | ZAP and Burp use different formats/schemas. Normalization creates one structure for the pipeline. |
| **How does SQLi TIME_BASED work?** | Inject a sleep command. If query executes (vulnerable), response is slow. Compare vs. baseline. Statistical confidence. |
| **What about WAF/rate limiting?** | Currently not handled. Timeouts in place (default 10s). WAF blocking could cause INCONCLUSIVE. No smart retry logic yet. |
| **How does deduplication help?** | Avoids duplicate reports to dev team. One finding from two scanners still = one bug to fix. (Not yet implemented.) |
| **Where is AI used?** | Not yet. Planned for enrichment/prioritization but no ML in current code. |
| **How is risk prioritized?** | Not yet. Planned but empty. Would use CVSS + exploitability + impact. |
| **What if two scanners report the same issue?** | Separate VerifiedFindings stored. Deduplication would group them. (Not yet implemented.) |
| **How would this scale to other scanners?** | Write a new parser inheriting from `BaseParser`. Implement `parse()` method. Register in `get_parser()`. |
| **What are current limitations?** | In-memory storage (no persistence), only TIME_BASED SQLi exposed in API, no dedup/enrichment, no auth, no frontend. |

---

## 12. DO NOT CLAIM

During presentation, **DO NOT SAY** these things unless explicitly confirmed in repo:

- ❌ "We support all SQLi detection types" → Only TIME_BASED is exposed via API. Boolean/Error/Union are research-stage.
- ❌ "Deduplication is complete" → Not implemented.
- ❌ "Enrichment provides remediation guidance" → Not implemented.
- ❌ "Risk scoring prioritizes findings" → Not implemented.
- ❌ "We use machine learning" → No ML in codebase.
- ❌ "Data persists across restarts" → Storage is in-memory Python dicts. Restarting server loses all data.
- ❌ "Production-ready infrastructure" → No database, no auth, no redundancy.
- ❌ "Frontend dashboard available" → No frontend code exists.
- ❌ "Handles WAF/rate limiting gracefully" → Not handled; may timeout.
- ❌ "Works with all scanners" → Only ZAP (JSON) and Burp (XML) supported.
- ❌ "XSS verification is complete" → XSS implemented but not exposed via main verification endpoint (no XSS trigger config in API).
- ❌ "We deduplicate across multiple scans" → No cross-scan deduplication logic.

---

## 13. WHO KNOWS WHAT

### **You (Backend/Tech Lead)**
- Overall architecture and data flow
- API design and endpoint behavior
- Replay engines (CSRF, SQLi, XSS)
- Normalization logic
- Storage/repository pattern

**Be ready to explain:**
- How the verification endpoint works
- Why replay is better than heuristics
- Data model for NormalizedFinding
- How parsers work (ZAP vs. Burp)

---

### **Inchara (Deduplication, Risk, Presentation)**
- Why deduplication is important (what logic would it use?)
- Risk scoring philosophy (CVSS + exploitability + impact)
- How findings would be prioritized for remediation
- Presentation narrative and flow

**Be ready to explain:**
- Deduplication algorithm approach (if designed)
- How risk score would differ from CVSS alone
- Why certain findings are higher priority
- How the system helps reduce alert fatigue

---

### **Lavanya (Verification/Security Research)**
- Deep SQL injection attack patterns
- CSRF token bypass techniques
- XSS execution contexts and encodings
- Why TIME_BASED SQLi is deterministic
- Boolean/Error/Union-based SQLi research

**Be ready to explain:**
- How timing attacks prove SQLi
- Different SQLi verification methods (and which are exposed)
- CSRF defense types we can test
- XSS payload reflection and execution

---

### **Mahita (Vulnerability Research, Testing, Docs)**
- Test suite structure (53 test files)
- Ground truth test cases (CSRF, XSS, SQLi)
- Edge cases and failure scenarios
- Test coverage for verification logic
- Documentation of test approach

**Be ready to explain:**
- How ground truth tests work
- What coverage we have for each vulnerability type
- How we validate parsing (Burp, ZAP)
- Example test cases

---

### **Dhanya + Amogh + Megha + Greeshma (Frontend)**
- Frontend hasn't started yet
- Will consume the API endpoints listed in Section 9
- Should display:
  - Scan upload interface
  - Normalized findings list
  - Verification trigger UI (with CSRF/SQLi config)
  - Verified findings with risk colors + evidence

**Be ready to explain:**
- What the API provides
- What findings structure looks like
- How verification config differs between CSRF and SQLi
- How to display evidence and confidence

---

## 14. QUICK REVISION SHEET

**Q: What are we building?**
A system that verifies ZAP/Burp findings by replaying attacks and checking for real exploitability. We return TRUE_POSITIVE / FALSE_POSITIVE / INCONCLUSIVE.

**Q: What is our architecture?**
FastAPI backend parsing ZAP/Burp JSON/XML → normalize → replay against target → verify with security checks → return results.

**Q: What is normalization?**
Converting different scanner formats (ZAP JSON, Burp XML) into one canonical NormalizedFinding structure.

**Q: How do we detect false positives?**
We replay the exact attack. If it fails (wrong status, no timing delay, payload not reflected), it's a false positive.

**Q: How does verification work?**
Replay the finding, collect evidence (response codes, timing differences, state changes), apply deterministic classification rules, return verdict with confidence score.

**Q: Where does deduplication fit?**
Logically after verification (planned). Groups identical findings from multiple scanners. **Not yet implemented.**

**Q: Where does AI/risk fit?**
Planned for enrichment (remediation guidance) and prioritization (risk scoring). **Not yet implemented.**

**Q: What is our backend stack?**
Python + FastAPI + Pydantic + httpx. In-memory storage (Python dicts). Pytest for tests.

**Q: What is our current limitation?**
In-memory storage (no persistence), only TIME_BASED SQLi exposed in API, no dedup/enrichment/risk, no auth, no frontend.

---

## Appendix: File Quick Reference

| Module | Purpose | Status |
|--------|---------|--------|
| `backend/api/scans.py` | Scan upload, finding lists | ✅ |
| `backend/api/findings.py` | Verification endpoint | ✅ |
| `backend/parsers/zap.py` | ZAP JSON parsing | ✅ |
| `backend/parsers/burp.py` | Burp XML parsing | ✅ |
| `backend/models/normalized_finding.py` | Data structure | ✅ |
| `backend/services/normalization_service.py` | Parser orchestration | ✅ |
| `backend/replay/engine.py` | Generic HTTP replay | ✅ |
| `backend/replay/csrf.py` | CSRF-specific replay | ✅ |
| `backend/replay/sqli_time_based.py` | TIME_BASED replay | ✅ |
| `backend/verification/csrf.py` | CSRF classifier | ✅ |
| `backend/verification/sqli_time_based.py` | TIME_BASED classifier | ✅ |
| `backend/verification/xss.py` | XSS classifier | ✅ |
| `backend/storage/repository.py` | In-memory storage | ✅ |
| `backend/api/risks.py` | Risk scoring | ❌ Empty |
| Frontend | UI | ❌ Not started |

---

**Document Version**: 1.0 | **Last Updated**: 2026-08-18 | **Team**: Cognizant Hackathon VeriTriage
