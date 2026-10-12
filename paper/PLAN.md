# Plan to submission

Official WWW 2027 research track dates (check the CfP, https://www2027.thewebconf.org/?p=296):
**abstract 18 Oct 2026, full paper 25 Oct 2026, AoE**, via OpenReview. Track: *Security, Privacy and Trust*.

The go/no-go depends on B1 and B2 in `AUDIT.md`. If either of them flips a headline finding,
don't submit a rushed version. A solid version for USENIX Security / IEEE S&P / CCS / ACSAC / RAID /
DIMVA beats a rejected WWW paper whose reviews then circulate.

## Days 1–2 (by 14 Oct): do the oracle checks yourself, by hand, not via agents
- [ ] Open the browser harness code and **read it**. Where is the marker read? After which event? How long does it wait?
- [ ] B2: 30 canonical render-time payloads → raw-body sink → all must fire with no interaction.
- [ ] B1: build an instrumented oracle (dialog hook + `eval`/`Function`/string-timer hooks + `javascript:` nav). Re-label all payloads with it and diff against the marker labels. Count the disagreements and inspect 20 by eye.
- [ ] B5: confirm that the train/test split is by payload `group_id` in the crossed experiment.
- **Decision point (14 Oct):** do Findings 5 and 7 survive the re-labelling? If yes, register the abstract.

## Days 3–6 (by 18 Oct, abstract)
- [ ] B6: Coraza or ModSecurity v3 + CRS v4 at PL1–4 in front of app 1 (docker `owasp/modsecurity-crs`). Block rate on executing vs inert.
- [ ] B3: replay ~150 synthetic-negatives with real input.
- [ ] B4: cluster bootstrap over `group_id` for every CI. Rule of three on distinct groups.
- [ ] M3(b): run Miczek-style / LLM-obfuscated payloads through the execution oracle. What fraction still executes?
- [ ] Submit the abstract (it's in `main.tex`; adjust the numbers).

## Days 7–11 (by 23 Oct)
- [ ] M2: add context-mismatched escaping sinks (`href` with HTML escaping, unquoted attribute, JS string with HTML escaping).
- [ ] M8: Google Firing Range (docker) as a third-party target.
- [ ] M9: taxonomy of dead payloads (manual coding of ~100 inert rows, two coders if possible, report κ).
- [ ] M10: cross-browser κ.
- [ ] Regenerate every table from scripts. Each table cell should trace to a CSV in `logs/`.

## Days 12–13 (by 25 Oct)
- [ ] Write the paper. Every number in the text gets copy-checked against its CSV (do this yourself).
- [ ] Verify every citation by DOI.
- [ ] Anonymise: no repo URL, no names. Use an anonymous artifact link (e.g. anonymous.4open.science).
- [ ] Ethics paragraph (already solid: local only, inert marker).

## Rules for working with agents from here
1. An agent may write code. **You** run it and look at raw output for at least a sample.
2. No number goes in the paper unless a script produced it and the CSV is committed.
3. For each claim, ask: "what bug in the harness would produce this exact result?" Then test for that bug.
