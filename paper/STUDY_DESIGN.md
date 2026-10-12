# Study design: "What does an XSS detector actually detect?"

Built on the course brief ("Can AI Detect XSS in Web Traffic?") and the Project-Xss repo.
The brief asks a robustness question. The repo's strongest evidence answers a more basic one:
**the label the field optimises is not the property operators care about.** That is the
contribution. It's a measurement and methodology paper, not a new detector.

## Contributions (each must be backed by a committed script + CSV)

| # | contribution | evidence that exists today | still needed |
|---|---|---|---|
| C1 | **Label validity.** Detector scores that separate attack from benign almost perfectly are uninformative or anti-correlated with execution, and a simple length baseline explains much of that | Table 3 reproduces; length AUC 0.62 | grouped bootstrap, per-source, all 10 architectures (`colab/analysis.py`) |
| C2 | **Benchmark composition.** Public XSS corpora are largely tag × event enumerations; few payloads execute on render, and non-execution has identifiable causes | benchmark audit reproduces | manual taxonomy of non-executing rows, two coders, Cohen's κ (`colab/taxonomy_sheet.py`) |
| C3 | **Context.** Among sinks where execution is possible, output context adds a measurable gain over the payload | +0.08 reproduced | report with trivial sinks excluded, per-application |
| C4 | **Oracle methodology.** Synthetic event dispatch over-reports execution | seen qualitatively in the logs | re-run your real-input validation in **both** directions and commit it |
| C5 | **Brief deliverables** (robustness by family, held-out family, latency) | Table 1, Table 2 exist | keep these short. They're replication, not novelty |

What makes this new: prior ML-XSS papers (e.g. Miczek et al. 2025, XSShield, GenXSS in your
brief) report accuracy against inherited labels. Execution-verified XSS work (Lekies et al.
CCS'13, Melicher et al. NDSS'18, Steffens et al. NDSS'19) verifies execution in order to *find
bugs*. Nobody has used execution verification to **audit detectors and their benchmarks**.
That gap is your paper. Position it against Arp et al., "Dos and Don'ts of ML in Computer
Security" (USENIX Sec'22), as a concrete instance of their label-inaccuracy pitfall.

## Research questions
- **RQ1** Does a detector's score track execution? (C1)
- **RQ2** What are public XSS benchmarks made of, and why do most entries not execute? (C2)
- **RQ3** How much of exploitability is decided by where a value lands rather than what it is? (C3)
- **RQ4** How reliable is the standard execution oracle? (C4)

## Rules for this round (doing it carefully, by hand)
1. **One number, one script, one CSV.** If you can't regenerate it in Colab from the repo, it doesn't go in the paper.
2. **Unit of analysis = payload group.** All CIs come from a cluster bootstrap over `group_id`.
3. **Report the denominator** everywhere: rows, distinct payloads, groups.
4. **Two labels, never mixed:** `attack_like` (inherited) vs `executes` (render-only, and render-or-interaction, reported separately).
5. Inert marker, `127.0.0.1` only, no third-party systems, no new payload generation. Use only the public corpora you already have.
6. Read 20 raw rows behind every headline number with your own eyes before writing it down.

## Colab order
1. Clone Project-Xss, `pip install scikit-learn pandas joblib scipy`.
2. `python colab/analysis.py --repo /content/project-xss` → `results/*.csv`. Send me the printed output.
3. `python colab/taxonomy_sheet.py --repo /content/project-xss` → `results/taxonomy_to_code.csv`. You and a second person each fill in the `cause` column independently. Send both files back and I'll compute κ and the table.
4. Find or re-run the real-input validation (C4). Sample **both** synthetic-positive and synthetic-negative cases (~150 each).
