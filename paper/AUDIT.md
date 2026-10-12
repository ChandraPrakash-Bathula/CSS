# Pre-submission audit of the README claims

Scope: the README only. The repository was empty when this audit was written, so no code,
logs or CSVs could be checked. Every item below is either (a) arithmetic recomputed from the
README, or (b) a validity threat a WWW Security/Privacy/Trust reviewer is likely to raise.
Severity: **BLOCKER** = could invalidate a headline claim; **MAJOR** = reviewer will demand it;
**MINOR** = wording / presentation.

## 0. Arithmetic that checks out

| claim | recomputed |
|---|---|
| 0/3,859, rule-of-three bound 0.078% | 3/3859 = 0.0777% ✔ (but see B4: rows are not independent) |
| 118/150 = 0.787, Wilson [0.714, 0.845] | ✔ exactly |
| "overstates by 27%" | 150/118 = 1.271 ✔ |
| 62% of public rows fire | (233+33)/(297+134) = 0.617 ✔ (denominator = adjudicable, not 500) |
| corrected = reported × factor | factor is **0.793–0.801**, not 0.787. Formula is undocumented → state it (M1) |

## 1. BLOCKERS: verify these yourself before believing anything

**B1. Marker substitution can manufacture "inert" payloads, and with them Finding 7.**
Public payloads are rewritten so `alert(...)` becomes `window.__xss_fired = true`. Obfuscated
payloads (`alert`, `top['al'+'ert']`, `eval(atob(..))`, `String.fromCharCode`, entity- or
URL-encoded `alert`) won't match the rewrite. They then run but never set the marker, and get
labelled **inert**. Obfuscated payloads are also the ones detectors score *highest*. That alone
would produce AUC < 0.5 on executes-vs-inert (0.38–0.47 observed), which is your Finding 7.
*Test:* re-label everything with an instrumented oracle that hooks `alert/confirm/prompt/print`,
the `dialog` event, `eval`/`Function`/`setTimeout(string)`, and navigations to `javascript:`.
Then recompute Table 3. If AUC moves toward 0.5 or above, Finding 7 was partly an artefact.

**B2. "Only ~2% execute without user action" may be a timing artefact.**
`<img src=x onerror=…>`, `<svg onload=…>`, `<video><source onerror=…>` and `<script>` in a raw
HTML body all fire at render. They are among the most common vectors in Kaggle and PayloadBox.
`onerror` is asynchronous. If the marker is read at `DOMContentLoaded` or right after `goto()`,
these get missed at render, then "caught" by the synthetic-dispatch phase and classed as
*interaction-required*. *Test:* hand-pick 30 canonical render-time payloads and run them in the
raw-body sink. Every one should fire with **zero** interaction. Read the marker after `load` plus
a fixed settle time (e.g. 500 ms) and after `networkidle`. If they don't all fire, Findings 2, 5,
the "88% need interaction" figure and the definition table in §4 all change.

**B3. The one-sidedness claim in §5 is untested and is stated backwards.**
The 2×2 table has **0 cases** in the "synthetic: no" row, so only synthetic *positives* were
sampled. Two problems follow:
1. The text says "synthetic never finds an exploit real input misses". The table shows exactly
   that 32 times. The intended claim is the converse: *real input never finds what synthetic
   missed*.
2. The converse was never measured. You need ~150 synthetic-negatives replayed with real input.
   Until then you can't say "synthetic can only over-report", and the argument that "the
   escaped-sink zero needs no correction" rests on nothing. (That zero is fine anyway, see B5.)

**B4. Non-independence: all CIs are too narrow.**
Variants share a parent, and each payload is sent to every sink. The 3,859 escaped rows and
the AUC CIs treat rows as i.i.d. Use a **cluster bootstrap over `group_id`** for every CI. For
the zero, report the rule of three on the number of *distinct groups*, not rows.

**B5. Crossed-design leakage in §4 (payload + sink = 0.974).**
If the test split is by (payload, sink) row, the same payload shows up in training with other
sinks. The model can then memorise "this payload executes when raw", which inflates the
payload+sink AUC. *Check* that the split is by payload `group_id`. Also report a
**leave-one-sink-out** variant.

**B6. Your CRS baseline isn't CRS.**
28 extracted `@rx` patterns leave out libinjection (`@detectXSS`, rule 941100, the main XSS
rule), the transformation pipeline (`t:urlDecodeUni,htmlEntityDecode,jsDecode,…`), anomaly
scoring and paranoia levels. Calling it "a production WAF ruleset" will be rejected. *Fix:* run
real **ModSecurity v3 or Coraza with CRS v4** in front of the app at **PL1–PL4**, and report
block rate on executing vs inert payloads per PL. (This is maybe a day of work, and it becomes
your strongest external result.)

## 2. MAJOR: reviewer objections to pre-empt

**M1. The correction factor.** State the formula. A real-input confirmation rate measured on
*interaction-required* payloads should only scale the interaction-required portion of each
rate, not render-time firings. Propagate the CI of the factor; don't take it as fixed.

**M2. "Escaping eliminates execution" is true by construction.** HTML-entity escaping in a text
node *should* give zero, so a reviewer will call it a tautology. Use it as a **positive control
that validates the oracle** (no false positives), not as a headline finding. The interesting
cells are where escaping is **context-mismatched**: the JS-string sink at 0.003 is non-zero,
`href="javascript:…"` survives HTML escaping, and unquoted attributes. Add those sinks; they're
the actual measurement.

**M3. Conceptual attack on the whole paper: "a WAF is *supposed* to block dead attacks."**
Blocking an inert attack attempt isn't a false positive operationally, because no benign user
sends `<svg onload>`. The paper needs one clear paragraph on *why execution is the label that
matters*:
(a) alert triage and prioritisation (SOC cost);
(b) robustness/evasion papers report "evasion" without checking that the evading payload still
executes, so their numbers are uninterpretable;
(c) benchmarks padded with dead payloads inflate reported accuracy;
(d) context-dependent blocking.
Point (b) is the sharpest. Miczek et al. (arXiv 2504.21045) generate obfuscated XSS with an LLM.
**Do those LLM-obfuscated payloads still execute?** Measuring that is a strong, novel, cheap
experiment.

**M4. "Detector doesn't rank by execution" is unsurprising if never trained to.** Answer it with
your existing positive control: the RF trained on execution reaches 0.773. The signal is
learnable, and the community's label just doesn't ask for it. Lead with that framing.

**M5. Sink-only AUC 0.858 depends on the sink mix.** Escaped sinks give zero by construction, so
including many of them inflates sink-only AUC. Report it **with escaped sinks excluded**.

**M6. DOM response AUC "exactly 0.500" is by construction.** The response doesn't vary, so the
feature is constant. Present it as an illustration, not a measurement. The stored row shows
request 0.917 ≈ response 0.915, which contradicts "stored: response only" in Finding 3. Restate:
the *write* request carries the payload, but the request-side detector at write time has no sink
context and can't link it to the victim's later response.

**M7. CSIC 2010 isn't "real traffic".** It's generated, synthetic traffic from 2010. Rename it
and acknowledge that.

**M8. Thin external validity.** Two own-written apps, a harness around template engines, and 2
Juice Shop sinks. Add **Google Firing Range** (purpose-built, dozens of reflected/DOM contexts),
plus DVWA/bWAPP/WebGoat, or a handful of reproduced real XSS CVEs in Docker.

**M9. "Inert in 5 contexts" ≠ inert.** Many payloads are written for a specific breakout (`">`,
`';`, `</textarea>`, `</title>`) or for legacy IE (`expression()`, `vbscript:`). Build a
**taxonomy of why payloads are dead** (legacy-only / needs-specific-context / malformed /
interaction-only-no-surface). That turns Finding 6 from a number into an explanation.

**M10. Cross-browser.** You ran Firefox and WebKit (n=200), but the README reports no numbers
from them. Report agreement (Cohen's κ) with Chromium.

**M11. Citations.** Agents fabricate references. Check every one by DOI. (Miczek et al. is real:
arXiv 2504.21045.)

## 3. MINOR / cut

- Finding 8 (latency) is well known for n-gram LR and off-thesis. Move it to the appendix.
- Augmentation and calibration negative results: keep them, briefly.
- "Four claims retracted": good practice, and one sentence in the paper is enough.
- Kaggle licence unstated: release IDs + a fetch script, not the data.
- Report per-architecture execution AUC as a range across splits (it's split-sensitive by up to 0.23).

## 4. What survives as the paper's core, provided B1–B6 hold

1. **Label validity:** attack-likeness ≠ executability. Detectors are near chance at ranking
   by execution, and a model trained on execution can learn it.
2. **Context dominates:** where a value lands matters more than what it is. This is shown with
   real template engines, and context-mismatched escaping is the interesting regime.
3. **Inspection-point coverage:** request vs response vs DOM for reflected/stored/DOM XSS.
4. **Benchmark decay:** a large share of public payload lists is dead in modern browsers,
   explained by a taxonomy.
5. **Verification methodology:** synthetic dispatch over-reports. Quantify it in both
   directions.
6. **Real WAF:** CRS at PL1–4 barely separates executing from inert payloads.
