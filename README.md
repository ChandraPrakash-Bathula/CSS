# Measuring the gap between XSS detection research and the Web

**Thesis.** XSS detection research is evaluated against a label (attack-likeness) and a
setting (request-only, context-free) that don't match how XSS works on the real Web. We
measure the mismatch on three axes: the literature, the payload corpora, and the Web's own
output contexts.

Target: WWW 2028 research track (Security, Privacy & Trust), or IMC / USENIX Security 2027.
Companion lab code lives in `ChandraPrakash-Bathula/project-xss`.

| # | contribution | folder | status |
|---|---|---|---|
| C1 | Systematic review of ML-for-XSS evaluation practice | `review/` | protocol, search, codebook, agreement: **ready to run** |
| C2 | Dataset cards for every public XSS corpus (execution-audited) | `corpora/` | next |
| C3 | Corpus decay across browser versions | `corpora/` | next |
| C4 | Output-context prevalence on the real Web (passive, Common Crawl) | `crawl/` | pipeline + tests: **ready to run** |
| C5 | Detectors re-evaluated under execution labels | `paper/colab/analysis.py` + project-xss | re-analysis ready; real CRS, real-input check pending |

## Ground rules
- Passive or local only. Nothing is sent to any third-party site. The crawl study reads Common Crawl's archive.
- No new payloads. Corpora are used as published; execution is observed with an inert marker or dialog hook on `127.0.0.1`.
- Crawl output is aggregate only. Parameter values are stored as salted hashes, and no site is named.
- One number, one script, one CSV. Unit of analysis is stated for every table (paper, corpus row, payload group, host).

## Run in Colab
See `COLAB.md`.
