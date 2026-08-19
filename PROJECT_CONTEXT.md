## Current CSRF Investigation — August 2026

### Finding

VulnVerify's CSRF verification implementation already exists and is scanner-agnostic.

The gap is not in:
- CSRF replay
- CSRF verification
- verification-family dispatch
- NormalizedFinding schema

The gap is ZAP evidence ingestion.

### ZAP Investigation

The repository's Traditional ZAP JSON fixtures were programmatically inspected.

Files:
- tests/fixtures/zap/zap_report.json
- tests/fixtures/zap/zap_sqli_positive.json

Neither contains:
- /DVWA/vulnerabilities/csrf/
- /DVWA/vulnerabilities/csrf/?password_new=...&password_conf=...&Change=...

inside:
site[].alerts[].instances[].uri

The string `vulnerabilities/csrf` only appears inside response-body HTML because DVWA includes CSRF in its navigation menu.

Therefore this HTML occurrence must NOT be treated as CSRF evidence.

### Important architectural conclusion

Do NOT modify ZapParser to infer CSRF from:
- response-body HTML
- URL substrings
- password_new/password_conf parameter names
- arbitrary HTTP history

Do NOT convert arbitrary traffic into findings.

Traditional ZAP JSON only gives VulnVerify a finding when ZAP itself provides an alert/instance.

### Existing CSRF support

Burp already supports CSRF:
Burp issue
→ BurpParser
→ category=CSRF
→ existing CSRF verification
→ independent replay/classification

The existing CSRF verifier should be reused rather than rewritten.

### Next Task

Investigate whether VulnVerify should support a ZAP export format that actually contains HTTP request/response messages.

Potential architecture:

ZAP alert export
→ existing alert parser
→ NormalizedFinding

ZAP traffic-containing export
→ explicit evidence/candidate parser
→ NormalizedFinding
→ existing CSRF verification

Do not implement until the export format and candidate-detection design are established.

### Product principle

Scanner output is evidence, not truth.

VulnVerify must independently verify findings and must not manufacture TRUE_POSITIVE results simply because a scanner reported something.