# Systematic review protocol: how is ML-based XSS detection evaluated?

Written **before** screening starts. Commit this file and don't change it after screening
begins; record any deviation in `DEVIATIONS.md` with a date and a reason. Reviewers trust a
review whose protocol predates its results.

Reporting follows PRISMA 2020 (flow diagram: identified → screened → eligible → included).

## Review questions
- **SR1** What data do ML-based XSS detectors train and test on? Which corpora, and how much do papers share them?
- **SR2** What does the positive label mean? Inherited from a corpus, regex/WAF-assigned, manually assigned, or **execution-verified**?
- **SR3** How are data split? Random rows vs grouped by payload family/source vs temporal. Is near-duplicate leakage addressed?
- **SR4** Which metrics, baselines and robustness tests (obfuscation, adversarial) are reported? Is evasion success checked for preserved execution?
- **SR5** Where is the detector placed (request, response, browser, server), and is that placement discussed?
- **SR6** Are code and data released?

## Sources and search
Databases: OpenAlex, Semantic Scholar, arXiv, DBLP, plus IEEE Xplore and ACM DL by manual
export (their APIs need keys). Then one round of backward and forward **snowballing** from
the included set (Wohlin 2014).

Window: 2015-01-01 to the search date. Language: English.

Query, in each source's syntax (`search.py` holds the exact strings sent):

```
("cross-site scripting" OR "cross site scripting" OR XSS)
AND ("machine learning" OR "deep learning" OR "neural network" OR classifier OR
     "random forest" OR SVM OR LSTM OR CNN OR transformer OR BERT OR "language model" OR LLM)
AND (detect* OR classif* OR "web application firewall" OR WAF)
```

## Eligibility
Include if **all** hold:
- I1 Proposes or evaluates a **learned** detector (ML, DL, LLM) for XSS, alone or among web attacks.
- I2 Reports a quantitative evaluation on some dataset.
- I3 Peer-reviewed venue, or a preprint with ≥1 citation or from the last 18 months.

Exclude if any holds:
- E1 Purely rule/regex/taint-based, with no learned component.
- E2 XSS is mentioned but not evaluated separately, and no per-class results can be extracted.
- E3 Survey, position paper or thesis duplicate of an included paper (keep the most complete version).
- E4 Full text unobtainable.

## Procedure
1. `python search.py --out candidates.csv` collects and deduplicates records.
2. **Title/abstract screening:** two coders independently, using `screen_A`/`screen_B` columns in `candidates.csv` (include / exclude / maybe). Compute κ with `agreement.py`, then resolve disagreements by discussion. "Maybe" goes to full text.
3. **Full-text screening:** same two coders, recording the exclusion reason (E1–E4).
4. **Extraction:** each coder fills their own copy of `extraction_template.csv` following `CODEBOOK.md`. Report κ per field, then a reconciled final sheet.
5. **Pilot:** both coders extract the same 5 papers first, then refine the codebook wording only (not the categories). Pilot papers are re-extracted afterwards.

## Analysis
Descriptive counts and shares per codebook field, with Wilson 95% CIs. Also cross-tabs:
label type × year; split type × reported accuracy. Dataset reuse is shown as a bipartite
paper–dataset graph; report how many papers the top-3 corpora cover.

The headline we expect but do not assume: *the share of papers whose label is
execution-verified*. If it turns out large, that is a finding too and we report it.

## Threats
Search recall (mitigated by snowballing and multiple databases), coder bias (two coders, κ),
and grey literature (preprints included under I3).
