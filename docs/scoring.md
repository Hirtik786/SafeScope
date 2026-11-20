# How the score and grade work

SafeScope starts every scan at **100 points** and subtracts a penalty for each finding with
status `fail` or `warn`. Passed and informational results never cost points.

| Severity | Penalty |
|---|---:|
| critical | 40 |
| high | 20 |
| medium | 10 |
| low | 3 |
| info | 0 |

The score never goes below 0. It is then mapped to a grade:

| Score | Grade |
|---:|:---:|
| 95–100 | A+ |
| 85–94 | A |
| 70–84 | B |
| 55–69 | C |
| 40–54 | D |
| 0–39 | F |

Two caps make sure one serious problem is never hidden by many good results:

- any **critical** finding (for example an expired certificate) → grade **F**
- any **high** finding (for example no HTTPS) → grade at most **C**

The implementation is in [`src/safescope/scoring.py`](../src/safescope/scoring.py). The model
is deliberately simple; proposals to refine it are welcome as issues.
