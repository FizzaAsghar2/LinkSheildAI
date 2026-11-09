# API

Interactive OpenAPI docs are served at `/docs`.

- `GET /health`
- `POST /api/v1/scans` with `{"url":"https://example.org"}` returns a scan ID and pending state; poll `GET /api/v1/scans/{id}`.
- `GET /api/v1/scans?limit=50&q=example` lists history.
- `GET /api/v1/reports/{id}` returns a completed report.
- `DELETE /api/v1/scans/{id}` deletes a record.
- `POST /api/v1/extension/check` uses the same deterministic scanner and required Cerebras explanation; returns the evidence score, verdict, confidence, findings, script coverage, and AI summary.
- `GET /api/v1/settings`
- `POST /api/v1/explanations/{id}` generates another Cerebras explanation for a completed report.

Every web scan calls Cerebras before it can complete. Configure `CEREBRAS_API_KEY` and `CEREBRAS_MODEL` in `backend/.env`; missing configuration or a Cerebras error fails the scan with a clear error. The prompt includes structured scanner findings and coverage, not the full URL or fetched page source. Cerebras summarizes evidence and does not assign or change the risk score or verdict.\n\nCompleted reports distinguish the severity classification from the assessment verdict. `INCONCLUSIVE` means coverage or verification was insufficient; `REVIEW` means indicators need human review; `SUSPICIOUS` means high-severity patterns were observed. The 0–100 score is evidence-weighted, not a probability. No report certifies a site as safe.

