# Risk Scoring

AegisScan uses a simple additive model designed for educational and defensive assessment purposes.

## Point Values

| Finding Severity | Points |
|------------------|--------|
| CRITICAL         | 20     |
| HIGH             | 10     |
| MEDIUM           | 5      |
| LOW              | 1–2    |

The total score is capped at **100**.

## Risk Levels

| Score Range | Level    |
|-------------|----------|
| ≥ 70        | CRITICAL |
| ≥ 50        | HIGH     |
| ≥ 25        | MEDIUM   |
| < 25        | LOW      |

## Important Notes

- This is a **project-specific** risk indicator.
- It is **not** a CVSS, OWASP Risk Rating, or industry-standard score.
- Scores help prioritize remediation during authorized assessments and learning exercises.
- Multiple low-severity findings can accumulate; a single critical finding has significant weight.
