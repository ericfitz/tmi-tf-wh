# Jev vs tmi-tf detectors — 2026-09-28

Precision/recall/hijack rate carry a Wilson 95% confidence interval; two figures whose intervals overlap are a tie, not a real difference.

| Detector | Precision [95% CI] | Recall [95% CI] | F1 | Hijack rate [95% CI] (n) | Benign FP rate (n) | p50 ms | p95 ms | Cost USD |
|---|---|---|---|---|---|---|---|---|
| static rules (scripts) | 0.946 (0.823, 0.985) | 0.486 (0.374, 0.599) | 0.642 | 0.0 (0.0, 0.228) (n=13) | 0.043 (n=47) | 27 | 27 | 0.0000 |
| injection scan (metadata) | 1.0 (0.722, 1.0) | 0.25 (0.142, 0.402) | 0.4 | 0.714 (0.549, 0.837) (n=35) | 0.0 (n=35) | 0 | 0 | 0.0000 |
| LLM script review (gpt56cyber) | 0.947 (0.872, 0.979) | 1.0 (0.949, 1.0) | 0.973 | 0.0 (0.0, 0.114) (n=30) | 0.085 (n=47) | 17027 | 57111 | 2.3231 |
| Jev (scripts, fixed bands) | 1.0 (0.934, 1.0) | 0.75 (0.639, 0.836) | 0.857 | 0.0 (0.0, 0.155) (n=21) | 0.0 (n=47) | 162 | 215 | 0.0037 |
| Jev (metadata, fixed bands) | 1.0 (0.898, 1.0) | 0.85 (0.709, 0.929) | 0.919 | 0.171 (0.081, 0.327) (n=35) | 0.0 (n=35) | 170 | 170 | 0.0002 |

## Decision rule

Jev wins if F1 is higher, or within 0.02 at lower p95 latency, AND its hijack rate is not worse than the isolated LLM review's (overlapping Wilson 95% intervals are a tie, not a win; 'insufficient data' when hijack rate has no sample on either side).

## Notes

- Metadata rows' 'Hijack rate' column is actually a miss rate over attacker_wants=='clean' rows: metadata has no clean-twin `pair` to compute the scripts' paired hijack rate against.
- Jev 'review' band (neither yes nor no; counted as not-flagged in the headline numbers above): scripts 0.126 (n=119), metadata 0.08 (n=75)
- Jev category accuracy on true-positive scripts (secondary metric): 0.87 (n=54)
- Jev threshold sweep: tuned threshold 0.30 (chosen on the id-parity tune half; ties broken by the lowest threshold); held-out half (n=98) precision=0.962 recall=0.911 f1=0.936
- Jev vs LLM review precision (scripts): tie (Jev (0.934, 1.0), LLM (0.872, 0.979))
- Jev vs LLM review recall (scripts): LLM review (Jev (0.639, 0.836), LLM (0.949, 1.0))
- Jev vs LLM review hijack rate (scripts, lower is better): tie (Jev (0.0, 0.155) n=21, LLM (0.0, 0.114) n=30)
- Jev vs LLM review F1 difference (scripts, paired bootstrap 95%): (-0.19, -0.048)
- Decision rule verdict (scripts): LLM review wins (or no clear Jev win)
