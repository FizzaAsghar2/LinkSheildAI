# API

Interactive OpenAPI docs are served at `/docs`.

- `GET /health`
- `POST /api/v1/scans` with `{"url":"https://example.org"}` returns a scan ID and pending state; poll `GET /api/v1/scans/{id}`.
- `GET /api/v1/scans?limit=50&q=example` lists history.
- `GET /api/v1/reports/{id}` returns a completed report.
- `DELETE /api/v1/scans/{id}` deletes a record.
- `POST /api/v1/extension/check` uses the same deterministic scanner and returns the evidence score, verdict, confidence, findings, and script coverage.
- `GET /api/v1/settings`
- `POST /api/v1/explanations/{id}` returns a Cerebras explanation or clear fallback.

Completed reports distinguish the severity classification from the assessment verdict. `INCONCLUSIVE` means coverage or verification was insufficient; `REVIEW` means indicators need human review; `SUSPICIOUS` means high-severity patterns were observed. The 0–100 score is evidence-weighted, not a probability. No report certifies a site as safe.

