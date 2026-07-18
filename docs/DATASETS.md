# Dataset Notes

Large source feeds and generated datasets are intentionally not committed to GitHub. This keeps the repository lightweight and avoids GitHub file-size limits.

## Inputs

The dataset builder expects these local files:

```text
data/raw/mitre/enterprise-attack.json
data/raw/cve/nvdcve-2.0-2022.json
data/raw/cve/nvdcve-2.0-2023.json
data/raw/cve/nvdcve-2.0-2024.json
data/raw/apt_reports/APTnotes.csv
```

## Generated Output

`scripts/build_dataset.py` writes:

```text
data/processed/final_cti_dataset.csv
```

The final training dataset described in the thesis contains 60,000 balanced records:

| Class | Records |
| --- | ---: |
| HIGH | 20,000 |
| MEDIUM | 20,000 |
| LOW | 20,000 |

The production training script then removes exact duplicate text/label pairs before evaluation. The metrics file records `43,701` rows after cleaning and an `8,741` sample held-out test set.

## Source Construction Summary

- HIGH examples: MITRE ATT&CK attack-pattern text, APT campaign descriptions, severe CVEs, ransomware/RCE/credential-dumping SIEM-style templates.
- MEDIUM examples: suspicious telemetry such as brute force, suspicious PowerShell, scanning, macro delivery, anomalous login, and unconfirmed suspicious activity.
- LOW examples: authorized scanner traffic, routine update activity, baseline telemetry, approved maintenance, false positives, and clean health checks.

## Rebuild Commands

```powershell
python scripts/build_dataset.py
python scripts/models/train_pipeline.py
```

The trained production model is stored in:

```text
models/cti_pipeline.pkl
```
