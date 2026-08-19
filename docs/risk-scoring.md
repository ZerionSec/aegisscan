# Risk Scoring Methodology

AegisScan uses a **project-specific risk indicator** (0–100).  
It is **not** a CVSS score.

## Score Calculation

Each finding contributes points based on severity and impact:

| Severity   | Typical Points |
|------------|----------------|
| CRITICAL   | 20             |
| HIGH       | 10             |
| MEDIUM     | 5              |
| LOW        | 1–2            |

Total score is capped at 100.

## Risk Levels

| Score Range | Level     |
|-------------|-----------|
| 70–100      | CRITICAL  |
| 50–69       | HIGH      |
| 25–49       | MEDIUM    |
| 0–24        | LOW       |

## Confidence

Findings also carry a confidence rating (HIGH / MEDIUM / LOW) to help prioritize verification.

## Important Notes

- This scoring is designed for **authorized assessments** and educational use.
- Always validate findings manually before taking action.
- Context (environment, business impact, compensating controls) matters more than the raw number.
