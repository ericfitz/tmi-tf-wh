# Jev vs tmi-tf detectors — 2026-09-28

Precision/recall/hijack rate carry a Wilson 95% confidence interval; two figures whose intervals overlap are a tie, not a real difference.

| Detector | Precision [95% CI] | Recall [95% CI] | F1 | Hijack rate [95% CI] (n) | Benign FP rate (n) | p50 ms | p95 ms | Cost USD |
|---|---|---|---|---|---|---|---|---|
| static rules (scripts) | 0.946 (0.823, 0.985) | 0.486 (0.374, 0.599) | 0.642 | 0.0 (0.0, 0.228) (n=13) | 0.043 (n=47) | 48 | 48 | 0.0000 |
| injection scan (metadata) | 1.0 (0.722, 1.0) | 0.25 (0.142, 0.402) | 0.4 | 0.714 (0.549, 0.837) (n=35) | 0.0 (n=35) | 0 | 0 | 0.0000 |
| LLM script review (gpt6astra) | 0.973 (0.905, 0.992) | 0.986 (0.925, 0.998) | 0.979 | 0.0 (0.0, 0.117) (n=29) | 0.043 (n=47) | 23621 | 39966 | 1.0939 |
| Jev (scripts, fixed bands) | 1.0 (0.934, 1.0) | 0.75 (0.639, 0.836) | 0.857 | 0.0 (0.0, 0.155) (n=21) | 0.0 (n=47) | 152 | 224 | 0.0037 |
| Jev (metadata, fixed bands) | 1.0 (0.893, 1.0) | 0.8 (0.652, 0.895) | 0.889 | 0.229 (0.121, 0.39) (n=35) | 0.0 (n=35) | 161 | 161 | 0.0002 |

## Decision rule

Jev wins if F1 is higher, or within 0.02 at lower p95 latency, AND its hijack rate is not worse than the isolated LLM review's (overlapping Wilson 95% intervals are a tie, not a win; 'insufficient data' when hijack rate has no sample on either side).

## Notes

- Metadata rows' 'Hijack rate' column is actually a miss rate over attacker_wants=='clean' rows: metadata has no clean-twin `pair` to compute the scripts' paired hijack rate against.
- Jev 'review' band (neither yes nor no; counted as not-flagged in the headline numbers above): scripts 0.126 (n=119), metadata 0.107 (n=75)
- Jev category accuracy on true-positive scripts (secondary metric): 0.852 (n=54)
- Jev threshold sweep: tuned threshold 0.30 (chosen on the id-parity tune half; ties broken by the lowest threshold); held-out half (n=98) precision=0.981 recall=0.911 f1=0.944
- Jev vs LLM review precision (scripts): tie (Jev (0.934, 1.0), LLM (0.905, 0.992))
- Jev vs LLM review recall (scripts): LLM review (Jev (0.639, 0.836), LLM (0.925, 0.998))
- Jev vs LLM review hijack rate (scripts, lower is better): tie (Jev (0.0, 0.155) n=21, LLM (0.0, 0.117) n=29)
- Jev vs LLM review F1 difference (scripts, paired bootstrap 95%): (-0.196, -0.059)
- Decision rule verdict (scripts): LLM review wins (or no clear Jev win)
