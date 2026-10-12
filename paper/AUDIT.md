# Audit of the README claims against the Project-Xss code and logs

Checked against `ChandraPrakash-Bathula/project-xss` @ `afcb51c` (single commit).
Numbers marked ✔ were re-derived from the committed logs and models with
`checks/recheck.py` (run it from the Project-Xss root).

## A. Claims with NO code or logs in the repo: find them or drop them

None of these exist in the repo: `verify/real_input_check.py`, `verify/cross_browser.py`,
`logs/table11*`–`table17*`, `table12b*`, `table13*`, `table15*`, `table16*`, and
`split_sensitivity` for transformers. The README claims below therefore cannot be checked:

| README claim | status |
|---|---|
| Finding 2: synthetic dispatch overstates by 27% (118/150) | **no code, no log** |
| §3 "corrected" rates (Table 17) | **no code, no log**; the factor in the README is 0.79–0.80, not 0.787 |
| §6 response-side AUC 0.979, per-class table, DOM = 0.500 | **no code, no log** |
| §4 definition table (render / plausible / any) | script `ml/interaction_tiers.py` exists, its output `table11` does not |
| §11 calibration on novel sinks | **no code, no log** |
| cross-browser (Firefox/WebKit) | **no code, no log** |
| `requirements.txt` cited in "Reproducing" | missing |

They may live in a Colab or local copy that was never pushed. If you can't produce the
script and the CSV, the claim doesn't go in the paper.

## B. What the code shows (✔ = reproduced)

**B1. The execution oracle is reasonable.** It waits for `load`, then a 200 ms settle, and
reads the marker. Payloads with no literal `alert/prompt/confirm(...)` are **excluded**, not
labelled inert (439 of 500 attack originals convert: Kaggle 99%, PayloadBox 62%). My earlier
worry that the rewrite manufactured "inert" labels does not hold. It does introduce a
**selection bias**: heavily obfuscated payloads are missing from every execution result.
Say so.

**B2. "~2% fire without interaction" is real in the logs ✔, but it describes the dataset, not
XSS.** Raw-body render-time firing is 2.7% (app 1) and 2.0% (engines). The Kaggle attack class
is dominated by cheat-sheet enumerations of tag × event (`<nobr oncontextmenu=…>`,
`<tr onbeforecut=…>`). Many "inert" rows need preconditions the harness doesn't supply:
- a URL fragment (`:target` transitions);
- a real image (`validimage.png`);
- IE-only events (`onbeforedeactivate`, `onbeforeactivate`);
- a specific sanitiser (mXSS-style `<x '="foo"><x foo='>…`);
- or they arrive pre-escaped (`&lt;IMG LOWSRC…`).

These payloads aren't dead. They're **context- or precondition-dependent**. The paper's
wording has to be "did not execute under our harness", plus a taxonomy of why.

**B3. Synthetic dispatch can reach elements real users can't** ✔ (seen in the data:
`<script onmousemove>` and `<template onmousemove>` are labelled *executes*). That supports
Finding 2's direction. Its size (27%) is unverifiable until A is resolved, and the
one-sidedness claim is still untested (the 2×2 table had no synthetic-negative cases).

**B4. Table 3 (detector score vs execution) reproduces ✔, but its sample is 92 payloads, not
632.**
- The 632 "distinct strings" are 92 parent payloads × ~7 transforms. Execution is (almost)
  a property of the parent, so the bootstrap over 632 strings gives CIs that are far too
  narrow. Resample by `group_id` (as `ml/context_crossed.py` already does).
- On the 92 near-original payloads, the baseline exec-AUC is **0.338**.
- **Payload length alone gets 0.623** (shorter → executes). The anti-correlation is largely
  "long, exotic, legacy cheat-sheet strings score as more attack-like and run less". That's a
  publishable mechanism, but you must present it as such.
- **Source confound**: Kaggle 67.5% execute and PayloadBox 13.3%, and PayloadBox scores high.
  The PayloadBox-only AUC is 0.04, so report Kaggle-only too (0.36).

**B5. Context experiment (Table 4): the headline reverses when trivial sinks are removed ✔.**

| sinks | payload only | sink only | payload + sink |
|---|---|---|---|
| all 5 (README) | 0.814 | **0.850** | 0.971 |
| drop escaped (0 by construction) and JS-string (0.003) | **0.873** | 0.696 | 0.950 |

"Knowing where beats knowing what" exists only because two of the five sinks never fire.
Defensible claim: **context adds about +0.08 AUC over the payload among sinks where execution
is possible.** The grouped split and group bootstrap are correct (no leakage ✔).

**B6. Escaped-sink zero ✔, but the bound in the README is wrong.**
The logs have **3,430** escaped rows (not 3,859), drawn from **1,130 distinct payloads in 371
groups**. The rule of three on independent units gives **≤0.81%**, not 0.078%. Present this as
the oracle's negative control (no false positives), not as a finding. Escaping in the right
context prevents XSS by definition.

**B7. Row-level labels are dominated by two constant strings.** 878 of the 1,022 confirmed rows
in `browser_results.csv` come from `js_string_breakout` and `entity_in_attr_value`, which emit
the **same string** for every parent. `execution_auc.py` dedups correctly. Any table computed
per row (Table 1 recall on "seen transformations", per-endpoint rates) must be checked for the
same problem.

**B8. The "CRS" baseline isn't CRS** (confirmed in `ml/published_baselines.py`). It uses
extracted `@rx` patterns, applied with Python `re` to lowercased text, and drops patterns that
fail to compile. It has no libinjection (`@detectXSS`), no `t:` transformations, no anomaly
scoring and no paranoia levels. Either run real ModSecurity v3 or Coraza with CRS v4 at PL1–4,
or rename it "regex patterns extracted from CRS".

**B9. Benchmark audit ✔.** Kaggle 233/297, PayloadBox 33/134. It uses dialog observation on
verbatim rows, which is good. But "fired" includes synthetic interaction (B3). Render-only is
**9/297 Kaggle and 23/134 PayloadBox**. Report both.

**B10. Smaller items.**
- CSIC 2010 is generated traffic, so don't call it "real traffic".
- Kaggle licence unstated: ship IDs plus a fetch script.
- `published_baselines.py` calls the Miczek paper "the brief's own reference [1]". That's
  agent/brief leftover language; scrub it everywhere.

## C. What survives as a paper

1. **Label validity, with a mechanism.** On 92 grouped payloads, detector scores are
   anti-correlated with execution, and that is explained by payload length/exoticness and
   by benchmark composition. A model trained on execution does learn it. This is the core.
2. **Benchmark composition.** Public XSS sets are cheat-sheet enumerations. Only ~2–3%
   fire at render, and most "attacks" need an interaction, a precondition or a legacy browser.
   Include a taxonomy of non-executing payloads.
3. **Oracle methodology.** Synthetic dispatch reaches unreachable elements. Quantify that
   (once the real-input experiment is recovered or re-run) in both directions.
4. **Context.** +0.08 AUC among executable sinks. The template engines reproduce it (raw
   0.425, escaped 0).
5. Stored/DOM visibility and the real-CRS result **only if** A and B8 are done.

With B4 and B5 corrected, findings 1, 7 and the "sink beats payload" line from the README
become: negative control; anti-correlation with a mechanism; and a modest context gain.
That's still a coherent measurement paper, just a more modest one.

---

# Update: Project-Xss @ `7aa0f94` (new logs and scripts pushed)

## Now backed by committed evidence ✔
| claim | check |
|---|---|
| Real-input 2×2 (118/32/0/0) | `table13_real_input.csv` + `verify/real_input_check.py` reproduce it |
| Cross-browser table, 96.0% agreement | `table14_cross_browser.csv` reproduces it exactly. The Chromium re-run matches the original Chromium labels on **1000/1000** pairs, which is strong evidence the oracle is deterministic |
| Response-side AUCs (§6), corrected rates (§3) | CSVs present (`table15`–`17`) |

## Still open
1. **No generator scripts for `table11`, `table12`, `table12b`, `table15`, `table16`, `table17`.** Only the response *collectors* (`verify/collect_responses*.py`) were pushed. Push the analysis scripts that turn those logs into the tables.
2. **The real-input check covers about a third of what it corrects.** It tests only the 14 events Playwright can drive (click / hover / focus families). Those account for **33.7%** of the 1,152 interaction firings in `cross_context.csv`. The other 66% (`animationiteration` 84, `drop` 54, `contextmenu` 51, `drag*`, `copy`, `focusout`, `pointerleave/out`, `beforepaste` …) were never validated, yet Table 17 applies the 0.787 factor to them too.
   Also, per-event confirmation varies from 0.42 (`mousemove`) to 1.0, so a single factor is wrong. Apply per-event factors, and report the untested share as untested.
3. **`animationiteration` is a likely oracle artefact.** It is classed as interaction-gated, but no user action triggers it. With `@keyframes x{}` and the default iteration count of 1, the browser never fires it, so its 84 firings are synthetic-only. The same check is needed for every non-user event in the "interaction" class.
4. **One-sidedness is still unmeasured.** `real_input.out` confirms the sample was *"150 interaction-gated payloads that fired synthetically"*. Rewrite the README sentence to say so, or sample synthetic negatives.
5. **Cross-browser doesn't speak to PayloadBox.** Its 200 payloads come from `cross_context.csv` (marker-converted, transformed variants), not the unmodified public rows. The README's motivation for §11 ("public payload rows are inert … merely Chromium-dead") isn't tested by it. Also: 200 payloads = 152 groups; "executes" includes synthetic dispatch; render-only rates are 0.5–4% in every engine.
6. **The "0 of 4,459" total still counts repeats.** The 600 cross-browser escaped rows are the same 200 payloads ×3 engines, and they're already inside the 3,430. Report the bound on distinct groups (≈0.8%).
7. **Housekeeping:**
   - 14 `__pycache__/*.pyc` files are committed; add a `.gitignore`.
   - Result CSVs sit at the repo root (`table5_*`, `scores_*`) as well as in `logs/`, and `new-results/` holds `(1).csv` copies. Keep one canonical copy of each.
   - `real_input.out` contains a local path (`/Users/<name>/Downloads/...`). Scrub it before the artifact goes to anonymous review.
