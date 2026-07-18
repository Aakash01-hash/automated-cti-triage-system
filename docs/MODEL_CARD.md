# Model Card

## Model

`models/cti_pipeline.pkl`

## Task

Classify raw CTI text, threat reports, vulnerability descriptions, and SIEM-style evidence into three triage severities:

- `HIGH`
- `MEDIUM`
- `LOW`

## Pipeline

- `TfidfVectorizer`
- `LogisticRegression`
- Unigram and bigram features
- `max_features=50000`
- Balanced class weights

## Evaluation

The production model was trained and evaluated with a stratified 80/20 split after duplicate removal.

| Metric | Value |
| --- | ---: |
| Rows after cleaning | 43,701 |
| Held-out test samples | 8,741 |
| Accuracy | 82.45% |
| Macro F1 | 0.8266 |
| Weighted F1 | 0.8263 |

## Confusion Matrix

Rows are actual labels and columns are predicted labels.

| Actual / Predicted | HIGH | MEDIUM | LOW |
| --- | ---: | ---: | ---: |
| HIGH | 1,901 | 478 | 10 |
| MEDIUM | 587 | 2,969 | 104 |
| LOW | 86 | 269 | 2,337 |

## Why Calibration Exists

The ML model ranks text severity, but SOC evidence often needs deterministic context. The inference layer therefore applies forensic calibration rules for:

- active exploitation and RCE
- ransomware and credential dumping
- command-and-control and exfiltration
- brute force and credential attacks
- benign certificate/update traffic
- authorized scanners and routine telemetry
- educational or simulated content

The calibrated output is intended to help analysts triage faster while still requiring human review.

## Limitations

- The model is not a replacement for forensic validation.
- HIGH and MEDIUM classes can overlap because both may contain suspicious security terminology.
- Live enrichment depends on API availability and configured keys.
- Synthetic examples improve coverage but may not reflect every production environment.
