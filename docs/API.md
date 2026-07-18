# API Reference

The Flask app runs locally from `webapp/app.py` on `http://127.0.0.1:5000`.

## `GET /health`

Returns a simple service status.

Example response:

```json
{
  "status": "running"
}
```

## `POST /analyze`

Analyzes one CTI/log sample.

Request:

```json
{
  "text": "CVE-2024-3400 active exploitation with webshell activity."
}
```

Response includes:

- `prediction`: calibrated final severity.
- `ml_prediction`: raw ML pipeline prediction.
- `confidence`: model confidence when available.
- `probabilities`: class probabilities.
- `features`: extracted forensic features.
- `indicators`: IPs, hashes, CVEs, files, and domains.
- `entities`: hosts, users, processes, event IDs, and source/destination IPs.
- `forensic`: incident type, MITRE-style mapping, triage priority, evidence value, and response actions.

## `POST /analyze-multi`

Splits bulk evidence into multiple samples and analyzes each one.

Request:

```json
{
  "text": "sample one\n\nsample two\n\nsample three"
}
```

Response:

```json
{
  "total_samples": 3,
  "high": 1,
  "ioc": 4,
  "results": []
}
```

## `POST /check-hash`

Performs optional VirusTotal hash enrichment. Requires `VT_API_KEY`.

Request:

```json
{
  "hash": "<sha256-file-hash>"
}
```

If the environment variable is missing, the endpoint returns a non-fatal configuration error.

## `GET /fetch-cves`

Fetches recent CVEs from the NVD API for dashboard awareness.

## `POST /generate-report`

Generates a forensic PDF report from one or more samples.

Request:

```json
{
  "text": "raw evidence text",
  "analyst_name": "SOC Analyst",
  "purpose": "Automated Threat Triage",
  "tlp": "AMBER"
}
```

Response:

```json
{
  "message": "Report generated",
  "filename": "forensic_report_1777784924.pdf"
}
```

## `GET /download-report/<filename>`

Downloads a generated PDF report from the local `outputs/` directory.
