# VulnVerify — Project Context

## Goal

VulnVerify is an automated verification system for ZAP and Burp security scanner findings.

The system:
1. Accepts scanner reports.
2. Normalizes findings into a common schema.
3. Replays relevant requests against the target.
4. Collects verification evidence.
5. Classifies findings as TRUE_POSITIVE, FALSE_POSITIVE, or INCONCLUSIVE.
6. Produces verified findings through the API.

Primary goal: reduce false positives from automated security scanners without fabricating evidence.

---

## Current architecture

Scanner report
→ Parser
→ NormalizedFinding
→ Replay
→ Verification
→ VerifiedFinding
→ API

Additional pipeline components such as deduplication, enrichment, and risk prioritization may exist separately.

---

## Completed verification families

### CSRF

Implemented and tested.

### SQLi TIME_BASED

Implemented and tested.

Important precedent:
- `api/findings.py` dispatches to a dedicated verification handler.
- Replay/mutation logic is family-specific.
- SQLi TIME_BASED currently passes `verification_confidence=0.0` as a compatibility placeholder.
- Real SQLi confidence is handled by its own contract/reason-code system.

### XSS

Reflected-XSS HTTP replay integration has now been implemented, reviewed, corrected, tested, and committed.

Implemented:
- XSS verification trigger schema.
- QUERY parameter mutation.
- Multi-payload replay collection.
- HTTP response analysis.
- XSS replay evidence population.
- Pipeline/API dispatch.
- End-to-end endpoint tests.
- Conservative response-context classification.

The existing XSS classification logic was NOT modified.

---

## Latest XSS implementation

### Commit

The reflected XSS implementation was committed as:

`5a9a494 feat: add reflected XSS verification`

The commit contains 11 code/test files.

The parent-directory project documentation files were intentionally left uncommitted and remain separate.

### Modified files

- `backend/api/findings.py`
- `backend/models/verification_trigger.py`
- `backend/replay/xss.py`
- `backend/services/pipeline_service.py`
- `tests/test_verification_trigger.py`
- `tests/test_xss_replay.py`
- `tests/test_xss_response_analysis.py`

### New files

- `backend/replay/xss_query_mutation.py`
- `backend/verification/xss_response_analysis.py`
- `tests/test_xss_query_mutation.py`
- `tests/test_xss_response_analysis.py`
- `tests/test_xss_verification_endpoint.py`

---

## XSS trigger

Reflected XSS verification accepts caller-supplied payload variants.

Important constraints:
- At least 2 payload variants are required.
- `variant_id` values must be distinct.
- Optional `expected_parameter` can defensively verify the normalized parameter name.
- No parameter name is inferred from caller input; the normalized finding remains the source of truth.
- Only `ParameterLocation.QUERY` is currently supported.
- Non-QUERY parameters are rejected rather than guessed.

---

## XSS replay

Each payload variant:
1. Mutates the normalized finding's query parameter.
2. Executes through the existing replay engine.
3. Analyzes the HTTP response.
4. Produces an `XssReplayAttemptObservation`.

Existing original XSS replay behavior remains unchanged.

The replay collector is implemented in:

`backend/replay/xss.py`

The QUERY mutation helper is:

`backend/replay/xss_query_mutation.py`

---

## XSS response analysis

New analyzer:

`backend/verification/xss_response_analysis.py`

It deliberately uses a conservative closed taxonomy.

Supported evidence:

1. Payload absent.
2. Payload encoded/sanitized.
3. Inert reflection:
   - HTML comment.
   - `<textarea>` / `<title>` RCDATA.
   - Normal attribute value where the payload did not break out.
4. Supported executable context:
   - Payload-created `<script>` element.
   - Recognized inline event-handler attribute.
5. Ambiguous/unresolved cases remain AMBIGUOUS rather than being guessed.

Everything else is treated conservatively.

Explicitly NOT treated as executable by this HTTP-only analyzer:
- `javascript:` / `data:` URI schemes.
- Arbitrary JavaScript execution.
- Payload inside an existing script block.
- Ordinary ambiguous text-node reflection.
- DOM-based execution.
- Actual browser execution.

---

## XSS response-analysis bug that was found and fixed

During post-implementation review, a real correctness bug was discovered.

### Problem

Python's `html.parser.HTMLParser` only treats `script` and `style` as CDATA/raw-text elements by default.

The analyzer needed `<textarea>` and `<title>` to behave as RCDATA containers.

Without correction, a payload such as:

`<script>MARK1</script>`

reflected inside:

`<textarea><script>MARK1</script></textarea>`

could be tokenized by the parser as an actual nested `<script>` element.

The analyzer could then incorrectly classify the reflection as `EXECUTABLE_CONTEXT`.

With two independent payload variants, this could propagate through the frozen XSS verification context/classifier and produce a false TRUE_POSITIVE.

### Fix

`_MarkerLocator` now overrides:

`CDATA_CONTENT_ELEMENTS = ("script", "style", "textarea", "title")`

This makes the parser treat `textarea` and `title` content as raw text for the purposes of the analyzer, matching the required RCDATA semantics.

No changes were made to the XSS classification logic or frozen XSS contract.

### Regression tests added

- `test_tag_shaped_payload_inside_textarea_is_inert`
- `test_tag_shaped_payload_inside_title_is_inert`
- `test_ambiguous_data_uri`

This bug fix is included in commit:

`5a9a494 feat: add reflected XSS verification`

---

## Frozen XSS evidence fields

These remain untouched:

- `marker_fired`
- `marker_fired_in_correct_context`
- `payload_execution_vector_blocked_by_verified_policy`
- STORED-specific fields.
- DOM-specific fields.

Because this slice has no browser, `marker_fired` and `marker_fired_in_correct_context` remain false.

Therefore this integration can only reach the frozen XSS TRUE_POSITIVE static-confirmation path, not browser-execution confirmation.

Do not claim browser execution from HTTP response analysis.

---

## XSS confidence

No new XSS confidence policy was created.

The API/pipeline currently pass:

`verification_confidence=0.0`

This deliberately mirrors the existing SQLi TIME_BASED precedent.

Do NOT invent or introduce an XSS confidence formula unless explicitly requested as a separate task.

This is a known limitation.

---

## XSS classification constraint

The existing XSS classifier/context logic is frozen for this task.

Do NOT modify:

- `backend/verification/xss.py`
- `backend/verification/xss_context.py`
- `backend/verification/xss_context_builder.py`
- `backend/verification/xss_observations.py`
- `backend/verification/xss_mapping.py`
- `backend/services/xss_verification_service.py`

Do not change vulnerability classification logic.

---

## API behavior

The reflected XSS verification flow is wired through:

`backend/api/findings.py`

The flow is:

`VerificationTriggerRequest.xss`
→ XSS validation
→ reflected-XSS subtype validation
→ QUERY parameter validation
→ payload variant collection
→ response analysis
→ `verify_reflected_xss_finding()`
→ `finalize_xss_verification()`
→ persistence

The XSS handler also validates `expected_parameter` when supplied.

Unsupported mutation cases are rejected rather than guessed.

The XSS endpoint converts mutation `ValueError` failures into HTTP 400 responses.

This behavior is intentionally more defensive than the current SQLi sibling implementation. Do not "fix" SQLi as part of unrelated XSS work.

---

## Tests

Before the XSS implementation:
- 720 existing tests.

After the initial implementation:
- 782 tests passed.
- 62 new tests.

After the response-analysis bug fix:
- 785 tests passed.
- 3 additional regression tests were added.
- No regressions were observed.

Latest verified result:

`785 passed, 1 warning`

Always rerun tests after pulling, merging, or changing code rather than trusting this document blindly.

---

## Important architectural decisions

- Do not fabricate scanner evidence.
- Do not fabricate payloads.
- Caller supplies XSS payload variants.
- Normalized finding supplies the vulnerable parameter.
- QUERY-only mutation for this XSS slice.
- Reject unsupported mutation cases rather than guessing.
- Preserve existing replay contracts.
- Preserve existing verification/classification contracts.
- Keep replay I/O separate from evidence analysis.
- Response analysis must be conservative.
- Ambiguous response evidence must remain ambiguous.
- Browser execution cannot be claimed from HTTP response analysis.
- STORED and DOM_BASED XSS are not supported by this trigger.
- Confidence must not be invented merely to satisfy an API field.
- Existing CSRF/SQLi behavior must remain unchanged.
- Do not broaden the XSS taxonomy without an explicit architectural decision.
- Parser behavior must be validated against actual HTML parsing semantics where context classification depends on it.

---

## Current task

The reflected XSS integration is implemented, reviewed, corrected, tested, and committed.

The next task should NOT blindly add more XSS functionality.

First inspect the latest repository state and team/reference documents.

Then determine the next highest-priority unfinished work from the project plan/team ownership.

Before modifying code:
1. Inspect the relevant existing implementation.
2. Compare against established CSRF/SQLi patterns where applicable.
3. Check whether the work is already implemented by another team member.
4. Identify the smallest safe next implementation slice.
5. Run focused tests before the full suite.
6. Do not modify frozen XSS classification logic unless explicitly assigned.

---

## Current ownership

- Reflected XSS integration: complete and committed.
- XSS response-analysis review: complete.
- API endpoint audit: assigned to Megha.
- Other team work should be checked against the latest team/reference documents before making assumptions.

---

## Known limitations

- XSS HTTP-only verification cannot prove browser execution.
- XSS confidence currently returns `0.0` because no approved confidence policy exists.
- XSS mutation currently supports QUERY parameters only.
- Parameter extraction from scanner issue-location text may have pre-existing limitations.
- STORED and DOM_BASED XSS verification are not implemented in this integration.
- Event-handler recognition is intentionally conservative and does not enumerate every possible HTML event handler.
- The endpoint-level test suite does not currently exercise every mutation `ValueError` path through the HTTP boundary; unit tests cover the mutation helper itself.