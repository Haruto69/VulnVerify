**# VulnVerify — Project Context**

**## Goal**

VulnVerify is an automated verification system for ZAP and Burp security scanner findings.

The system:

1\. Accepts scanner reports.

2\. Normalizes findings into a common schema.

3\. Replays relevant requests against the target.

4\. Collects verification evidence.

5\. Classifies findings as TRUE\_POSITIVE, FALSE\_POSITIVE, or INCONCLUSIVE.

6\. Produces verified findings through the API.

Primary goal: reduce false positives from automated security scanners without fabricating evidence.

\---

**## Current architecture**

Scanner report

→ Parser

→ NormalizedFinding

→ Replay

→ Verification

→ VerifiedFinding

→ API

Additional pipeline components such as deduplication, enrichment, and risk prioritization may exist separately.

\---

**## Completed verification families**

**### CSRF**

Implemented and tested.

**### SQLi TIME\_BASED**

Implemented and tested.

Important precedent:

\- \`api/findings.py\` dispatches to a dedicated verification handler.

\- Replay/mutation logic is family-specific.

\- SQLi TIME\_BASED currently passes \`verification\_confidence=0.0\` as a compatibility placeholder.

\- Real SQLi confidence is handled by its own contract/reason-code system.

**### XSS**

Reflected-XSS HTTP replay integration has now been implemented, reviewed, corrected, tested, and committed.

Implemented:

\- XSS verification trigger schema.

\- QUERY parameter mutation.

\- Multi-payload replay collection.

\- HTTP response analysis.

\- XSS replay evidence population.

\- Pipeline/API dispatch.

\- End-to-end endpoint tests.

\- Conservative response-context classification.

The existing XSS classification logic was NOT modified.

\---

**## Latest XSS implementation**

**### Commit**

The reflected XSS implementation was committed as:

\`5a9a494 feat: add reflected XSS verification\`

The commit contains 11 code/test files.

The parent-directory project documentation files were intentionally left uncommitted and remain separate.

**### Modified files**

\- \`backend/api/findings.py\`

\- \`backend/models/verification\_trigger.py\`

\- \`backend/replay/xss.py\`

\- \`backend/services/pipeline\_service.py\`

\- \`tests/test\_verification\_trigger.py\`

\- \`tests/test\_xss\_replay.py\`

\- \`tests/test\_xss\_response\_analysis.py\`

**### New files**

\- \`backend/replay/xss\_query\_mutation.py\`

\- \`backend/verification/xss\_response\_analysis.py\`

\- \`tests/test\_xss\_query\_mutation.py\`

\- \`tests/test\_xss\_response\_analysis.py\`

\- \`tests/test\_xss\_verification\_endpoint.py\`

\---

**## XSS trigger**

Reflected XSS verification accepts caller-supplied payload variants.

Important constraints:

\- At least 2 payload variants are required.

\- \`variant\_id\` values must be distinct.

\- Optional \`expected\_parameter\` can defensively verify the normalized parameter name.

\- No parameter name is inferred from caller input; the normalized finding remains the source of truth.

\- Only \`ParameterLocation.QUERY\` is currently supported.

\- Non-QUERY parameters are rejected rather than guessed.

\---

**## XSS replay**

Each payload variant:

1\. Mutates the normalized finding's query parameter.

2\. Executes through the existing replay engine.

3\. Analyzes the HTTP response.

4\. Produces an \`XssReplayAttemptObservation\`.

Existing original XSS replay behavior remains unchanged.

The replay collector is implemented in:

\`backend/replay/xss.py\`

The QUERY mutation helper is:

\`backend/replay/xss\_query\_mutation.py\`

\---

**## XSS response analysis**

New analyzer:

\`backend/verification/xss\_response\_analysis.py\`

It deliberately uses a conservative closed taxonomy.

Supported evidence:

1\. Payload absent.

2\. Payload encoded/sanitized.

3\. Inert reflection:

   - HTML comment.

   - \`\<textarea>\` / \`\<title>\` RCDATA.

   - Normal attribute value where the payload did not break out.

4\. Supported executable context:

   - Payload-created \`\<script>\` element.

   - Recognized inline event-handler attribute.

5\. Ambiguous/unresolved cases remain AMBIGUOUS rather than being guessed.

Everything else is treated conservatively.

Explicitly NOT treated as executable by this HTTP-only analyzer:

\- \`javascript:\` / \`data:\` URI schemes.

\- Arbitrary JavaScript execution.

\- Payload inside an existing script block.

\- Ordinary ambiguous text-node reflection.

\- DOM-based execution.

\- Actual browser execution.

\---

**## XSS response-analysis bug that was found and fixed**

During post-implementation review, a real correctness bug was discovered.

**### Problem**

Python's \`html.parser.HTMLParser\` only treats \`script\` and \`style\` as CDATA/raw-text elements by default.

The analyzer needed \`\<textarea>\` and \`\<title>\` to behave as RCDATA containers.

Without correction, a payload such as:

\`\<script>MARK1\</script>\`

reflected inside:

\`\<textarea>\<script>MARK1\</script>\</textarea>\`

could be tokenized by the parser as an actual nested \`\<script>\` element.

The analyzer could then incorrectly classify the reflection as \`EXECUTABLE\_CONTEXT\`.

With two independent payload variants, this could propagate through the frozen XSS verification context/classifier and produce a false TRUE\_POSITIVE.

**### Fix**

\`\_MarkerLocator\` now overrides:

\`CDATA\_CONTENT\_ELEMENTS = ("script", "style", "textarea", "title")\`

This makes the parser treat \`textarea\` and \`title\` content as raw text for the purposes of the analyzer, matching the required RCDATA semantics.

No changes were made to the XSS classification logic or frozen XSS contract.

**### Regression tests added**

\- \`test\_tag\_shaped\_payload\_inside\_textarea\_is\_inert\`

\- \`test\_tag\_shaped\_payload\_inside\_title\_is\_inert\`

\- \`test\_ambiguous\_data\_uri\`

This bug fix is included in commit:

\`5a9a494 feat: add reflected XSS verification\`

\---

**## Frozen XSS evidence fields**

These remain untouched:

\- \`marker\_fired\`

\- \`marker\_fired\_in\_correct\_context\`

\- \`payload\_execution\_vector\_blocked\_by\_verified\_policy\`

\- STORED-specific fields.

\- DOM-specific fields.

Because this slice has no browser, \`marker\_fired\` and \`marker\_fired\_in\_correct\_context\` remain false.

Therefore this integration can only reach the frozen XSS TRUE\_POSITIVE static-confirmation path, not browser-execution confirmation.

Do not claim browser execution from HTTP response analysis.

\---

**## XSS confidence**

No new XSS confidence policy was created.

The API/pipeline currently pass:

\`verification\_confidence=0.0\`

This deliberately mirrors the existing SQLi TIME\_BASED precedent.

Do NOT invent or introduce an XSS confidence formula unless explicitly requested as a separate task.

This is a known limitation.

\---

**## XSS classification constraint**

The existing XSS classifier/context logic is frozen for this task.

Do NOT modify:

\- \`backend/verification/xss.py\`

\- \`backend/verification/xss\_context.py\`

\- \`backend/verification/xss\_context\_builder.py\`

\- \`backend/verification/xss\_observations.py\`

\- \`backend/verification/xss\_mapping.py\`

\- \`backend/services/xss\_verification\_service.py\`

Do not change vulnerability classification logic.

\---

**## API behavior**

The reflected XSS verification flow is wired through:

\`backend/api/findings.py\`

The flow is:

\`VerificationTriggerRequest.xss\`

→ XSS validation

→ reflected-XSS subtype validation

→ QUERY parameter validation

→ payload variant collection

→ response analysis

→ \`verify\_reflected\_xss\_finding()\`

→ \`finalize\_xss\_verification()\`

→ persistence

The XSS handler also validates \`expected\_parameter\` when supplied.

Unsupported mutation cases are rejected rather than guessed.

The XSS endpoint converts mutation \`ValueError\` failures into HTTP 400 responses.

This behavior is intentionally more defensive than the current SQLi sibling implementation. Do not "fix" SQLi as part of unrelated XSS work.

\---

**## Deduplication**

**### Status**

Deduplication V1 (pure, single-scan grouping) is implemented and tested.

This is a grouping-only slice. It is currently unwired: not called from

\`pipeline\_service.py\`, not persisted, and not exposed through any API

endpoint.

Do not claim the full deduplication pipeline is complete. Only V1 pure

grouping is complete.

**### New files**

\- \`backend/models/deduplicated\_finding.py\`

  - \`DuplicateGroup\`

  - \`DuplicateGroupMember\`

\- \`backend/services/deduplication\_service.py\`

  - \`group\_duplicate\_findings()\`

\- \`tests/test\_deduplication\_service.py\`

**### Grouping key**

Deduplication V1 groups findings using exactly this key:

\`\`\`

(

    vulnerability.category,

    target.normalized\_url,

    target.parameter

)

\`\`\`

**### Decisions**

\- Category-level grouping, not subtype-level.

\- \`parameter=None\` is a valid grouping-key component.

\- Single-scan only.

\- Mixed scan IDs are rejected rather than silently combined.

\- \`NormalizedFinding\` and \`VerifiedFinding\` are paired by \`finding\_id\`.

\- Mismatched \`NormalizedFinding\`/\`VerifiedFinding\` IDs are rejected.

\- Existing classifications and confidences are preserved per member.

\- No merged classification.

\- No confidence modification.

\- No representative finding selection.

\- No persistence.

\- No API endpoint.

\- No pipeline integration.

\- No cross-scan deduplication.

\- No parser/normalization changes.

\- No verification/classification logic changes.

**### Tests**

13 new tests in \`tests/test\_deduplication\_service.py\`.

Full suite after this slice: \`798 passed, 1 warning\`. No regressions.

\---

**## Tests**

Before the XSS implementation:

\- 720 existing tests.

After the initial implementation:

\- 782 tests passed.

\- 62 new tests.

After the response-analysis bug fix:

\- 785 tests passed.

\- 3 additional regression tests were added.

\- No regressions were observed.

After Deduplication V1:

\- 798 tests passed.

\- 13 new deduplication tests.

\- No regressions were observed.

Latest verified result:

\`798 passed, 1 warning\`

Always rerun tests after pulling, merging, or changing code rather than trusting this document blindly.

\---

**## Important architectural decisions**

\- Do not fabricate scanner evidence.

\- Do not fabricate payloads.

\- Caller supplies XSS payload variants.

\- Normalized finding supplies the vulnerable parameter.

\- QUERY-only mutation for this XSS slice.

\- Reject unsupported mutation cases rather than guessing.

\- Preserve existing replay contracts.

\- Preserve existing verification/classification contracts.

\- Keep replay I/O separate from evidence analysis.

\- Response analysis must be conservative.

\- Ambiguous response evidence must remain ambiguous.

\- Browser execution cannot be claimed from HTTP response analysis.

\- STORED and DOM\_BASED XSS are not supported by this trigger.

\- Confidence must not be invented merely to satisfy an API field.

\- Existing CSRF/SQLi behavior must remain unchanged.

\- Do not broaden the XSS taxonomy without an explicit architectural decision.

\- Parser behavior must be validated against actual HTML parsing semantics where context classification depends on it.

\---

**## Current task**

The reflected XSS integration is implemented, reviewed, corrected, tested, and committed.

Deduplication V1 (pure, single-scan grouping) is implemented and tested. It is not merely being investigated -- the grouping contract and its tests are complete. It remains unwired: no persistence, no API endpoint, no pipeline integration.

The next task is to review Deduplication V1 and decide how (and whether) to integrate it -- persistence, API exposure, and/or pipeline wiring -- not to redesign or reinvestigate the grouping contract from scratch.

Before modifying code:

1\. Inspect the relevant existing implementation.

2\. Compare against established CSRF/SQLi/XSS patterns where applicable.

3\. Check whether the work is already implemented by another team member.

4\. Identify the smallest safe next implementation slice.

5\. Run focused tests before the full suite.

6\. Do not modify frozen XSS classification logic unless explicitly assigned.

7\. Do not modify the Deduplication V1 grouping contract without an explicit decision.

\---

**## Current ownership**

\- Reflected XSS integration: complete and committed.

\- XSS response-analysis review: complete.

\- API endpoint audit: assigned to Megha.

\- Other team work should be checked against the latest team/reference documents before making assumptions.

\---

**## Known limitations**

\- XSS HTTP-only verification cannot prove browser execution.

\- XSS confidence currently returns \`0.0\` because no approved confidence policy exists.

\- XSS mutation currently supports QUERY parameters only.

\- Parameter extraction from scanner issue-location text may have pre-existing limitations.

\- STORED and DOM\_BASED XSS verification are not implemented in this integration.

\- Event-handler recognition is intentionally conservative and does not enumerate every possible HTML event handler.

\- The endpoint-level test suite does not currently exercise every mutation \`ValueError\` path through the HTTP boundary; unit tests cover the mutation helper itself.

\- Deduplication V1 is currently unwired: it is not called from \`pipeline\_service.py\`, not exposed through any API endpoint, and its results are not persisted.

\- Cross-scan and cross-scanner deduplication are not implemented; Deduplication V1 is single-scan only and rejects mixed scan IDs rather than combining them.

\- Deduplication V1 groups at category level only; subtype-level grouping is not implemented.

---

# CURRENT PROJECT STATE — 2026-08-19

This section supersedes stale "current task" statements above where they conflict with the latest repository state.

## Repository structure

The backend repository was flattened in commit:

`a9e886a refactor: flatten backend project structure`

Current top-level layout is:

```text
VulnVerify/
├── backend/
├── tests/
├── frontend/
├── requirements.txt
├── .gitignore
├── TEAM_REFERENCE.md
└── PROJECT_CONTEXT.md
```

The old `vulnverify-backend/backend/` and `vulnverify-backend/tests/` paths no longer apply.

The Python virtual environment is at the repository root:

`.venv/`

## Latest backend baseline

The latest verified backend/full test result is:

`873 passed, 1 warning`

The warning is the existing Starlette/httpx TestClient deprecation warning and is unrelated to the project logic.

When testing, prefer:

`python -m pytest`

rather than invoking `pytest` directly if the Windows launcher points at a stale virtual-environment path.

## CORS

Minimal development CORS support has been added to `backend/main.py`.

Allowed frontend origins:

- `http://localhost:5173`
- `http://127.0.0.1:5173`

The configuration allows the methods/headers required by the frontend, including `GET`, `POST`, and `OPTIONS`.

Focused CORS tests were added in:

`tests/test_cors.py`

The CORS change was tested independently and against the full suite. The disallowed-origin behavior is correctly understood: a normal request can still return `200`, but without `Access-Control-Allow-Origin`; the browser therefore blocks frontend access. Disallowed preflight requests are rejected by Starlette.

Do not unnecessarily modify CORS configuration unless frontend integration requires it.

## Frontend — current strategy

A React/Vite frontend is now part of the repository.

The important architectural decision is:

**Keep our currently integrated frontend implementation as the functional baseline.**

A later UI from Dhanya should be treated as a visual/design source, not as a replacement for the working API integration.

Dhanya's submitted frontend ZIP was inspected. It has a useful visual design, including the older:

- Confidence column
- Risk Score /100 column
- Priority badges
- Dashboard
- New Scan
- Findings
- Prioritized Risks
- Reports

However, that version still contains hardcoded/demo risk values and does not implement the full backend pipeline integration. It should therefore NOT replace the current integrated frontend wholesale.

If Dhanya supplies a newer UI later:

1. Keep the current API client/state/integration architecture.
2. Port/adapt the visual components and styling.
3. Reconnect those UI components to the existing real backend data.
4. Do not reintroduce hardcoded risk scores or unsupported vulnerability categories.

## Current integrated frontend capabilities

The current frontend integration has been tested against the live backend.

Implemented frontend API integration:

- `POST /scans`
- `GET /scans/{scan_id}/findings`
- `POST /scans/{scan_id}/findings/{finding_id}/verify`
- `GET /scans/{scan_id}/verified-findings`
- `GET /scans/{scan_id}/duplicate-groups`
- `GET /scans/{scan_id}/enrichment`
- `GET /scans/{scan_id}/risk-priorities`

Key frontend files:

- `frontend/src/api/client.js`
- `frontend/src/hooks/useScanData.js`
- `frontend/src/utils/verification.js`
- `frontend/src/App.jsx`
- `frontend/src/App.css`
- `frontend/.env.example`

The integrated frontend has been live-tested through the actual React UI using a real ZAP SQLi fixture.

Verified flow:

1. Upload real scanner report.
2. Backend creates scan and findings.
3. Frontend displays real normalized findings.
4. Frontend displays real enrichment.
5. User opens verification form.
6. SQLi verification trigger is submitted.
7. Long-running verification state is displayed.
8. Verification result is retrieved/displayed.
9. INCONCLUSIVE result is shown correctly.
10. Priority is correctly capped at MEDIUM for that result.
11. Prioritized Risks page renders real backend priority data.
12. No console errors were observed during the live integration test.

Frontend build/lint baseline:

- `npm run build` — succeeds.
- `npm run lint` — clean.

## Frontend verification UI

The current integrated UI intentionally uses only the verification fields actually supported by the backend contract.

Examples:

- SQLi: baseline parameter value.
- CSRF: state-check indicator.
- XSS: at least two payload variants.

Do not invent optional verification fields merely because they appear in an older UI.

Verification status is translated for display:

- `TRUE_POSITIVE` → `TRUE POSITIVE`
- `FALSE_POSITIVE` → `FALSE POSITIVE`
- `INCONCLUSIVE` → `INCONCLUSIVE`

Verification confidence must remain conceptually separate from risk priority.

## Important risk-score decision

The older frontend showed both:

- Confidence
- Risk Score /100

That is still the desired product direction, but the numeric risk score must be produced by the backend rather than fabricated by the frontend.

The backend currently has priority logic, but the project is now considering a dedicated, explicit `/100` risk-score model as part of the Use Case 4 extension.

### Proposed model — NOT YET IMPLEMENTED

Risk score should combine external vulnerability-risk signals and verification confidence:

- CVSS severity: 40%
- EPSS exploit likelihood: 25%
- KEV presence: 20%
- Verification confidence: 15%

Conceptually:

`Risk Score = 0.40 × CVSS_normalized + 0.25 × EPSS_normalized + 0.20 × KEV_score + 0.15 × Verification_confidence`

Normalization:

- CVSS 0–10 → 0–100
- EPSS 0–1 → 0–100
- KEV present → 100; absent → 0
- Verification confidence 0–1 → 0–100

Important distinction:

**Verification confidence answers: "How confident are we that this finding is real?"**

**Risk score answers: "How dangerous/urgent is this finding?"**

EPSS and KEV are consumed from enrichment/external vulnerability intelligence; they are not values we calculate ourselves.

Recommended priority constraints:

- `TRUE_POSITIVE`: full risk score can determine priority.
- `INCONCLUSIVE`: cap priority at MEDIUM.
- `FALSE_POSITIVE`: INFORMATIONAL or excluded from active risk ranking.
- Not verified: do not assign a final risk priority yet.

This model is a proposal for the next implementation slice, not an existing backend contract. Do not claim it is implemented until code and tests prove it.

## Enrichment / risk terminology

When discussing the system with the team, keep these concepts separate:

### Enrichment

Adds contextual/external vulnerability information such as:

- CWE
- OWASP category
- CVSS
- EPSS
- KEV
- descriptions
- remediation
- references

The exact currently implemented enrichment fields must always be checked in the actual backend models/services before claiming a specific field is live.

### Verification

Replays relevant requests and determines:

- TRUE_POSITIVE
- FALSE_POSITIVE
- INCONCLUSIVE

with verification evidence and confidence according to the approved family-specific contracts.

### Risk scoring

A future explicit numeric risk score can combine enrichment signals with verification confidence.

### Priority

Priority is the operational severity/ranking result. It must not be confused with verification confidence.

## Use Case 4 status

The core verification pipeline is substantially implemented:

- scanner ingestion
- parsing
- normalization
- replay
- CSRF verification
- SQLi TIME_BASED verification
- reflected XSS HTTP verification
- verified findings
- enrichment
- deduplication V1
- risk-priority service/API
- frontend integration

The main extension work still relevant to Use Case 4 is to make the end-to-end prioritization story more complete and defensible, especially:

1. Decide/finalize the numeric risk-score formula.
2. Confirm which enrichment sources/fields are actually available for CVSS, EPSS, and KEV.
3. Implement the risk-score model in the backend with focused tests.
4. Integrate the score into the API contract.
5. Have the frontend display the real score alongside verification confidence.
6. Ensure verification status constraints cannot be bypassed by a high raw score.
7. Improve/complete deduplication wiring if still required by the final demo.
8. Add any missing reporting/metrics endpoints only if the use case requires them.

Do not treat the old static frontend numbers as evidence that risk scoring is already implemented.

## Deduplication current state

Deduplication V1 remains:

- pure
- single-scan
- category + normalized URL + parameter grouping
- grouping-only

It is implemented and tested.

The implementation was subsequently exposed to the frontend/API work, but before making further claims about persistence or pipeline wiring, inspect the current repository rather than relying on this document.

The original V1 contract remains important:

```text
(
    vulnerability.category,
    target.normalized_url,
    target.parameter
)
```

Do not silently change this grouping contract.

## Current test baseline / historical test counts

Historical counts in the earlier sections of this document are preserved for traceability:

- 798 passed after Deduplication V1.
- 785 passed after XSS response-analysis fixes.
- 873 passed is the latest verified full-suite baseline after later repository changes and CORS/frontend integration.

Always run the current suite rather than relying on historical counts.

## Next recommended task

Before changing the risk model:

1. Inspect the actual current enrichment models/service/API.
2. Inspect the actual current risk service/API.
3. Inspect the current `NormalizedFinding`, `VerifiedFinding`, and enrichment schemas.
4. Determine exactly which of CVSS, EPSS, KEV are already present and from which source.
5. Decide the final risk-score formula with the team.
6. Implement the smallest backend slice that produces a deterministic score.
7. Add focused tests.
8. Run the full suite.
9. Update the frontend only after the backend contract is stable.

Do not modify verification-family classification logic as part of risk-score work unless explicitly required.

## Handoff rules for future chats

A new chat should:

- Read this file first.
- Inspect the actual repository before assuming any path or implementation state.
- Treat the latest git state and tests as authoritative over stale context.
- Use `python -m pytest` on Windows.
- Preserve frozen XSS classification contracts.
- Preserve the Deduplication V1 grouping contract unless explicitly asked to change it.
- Keep verification confidence separate from risk score and priority.
- Never fabricate scanner evidence, enrichment values, verification evidence, or risk scores.
- Treat Dhanya's frontend as UI/design material unless a newer version is explicitly confirmed to be integrated.
