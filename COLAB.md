# Colab runbook

```bash
!git clone https://github.com/ChandraPrakash-Bathula/CSS && cd CSS
!pip install -q -r requirements.txt
```

## C4: real-Web output contexts (Common Crawl, passive)
Start small, check the output by hand, then scale.

```bash
!cd crawl && python -m pytest -q tests                       # 13 tests must pass
!cd crawl && REFLECT_SALT=<long-secret-keep-private> python run_warc.py \
      --crawl CC-MAIN-2025-38 --n-warcs 2 --limit 2000 --out /content/cc_pilot
!cd crawl && python aggregate.py --in /content/cc_pilot --boot 200
```

**Before scaling**, open `/content/cc_pilot/occurrences/*.csv` and check 30 rows by hand
against the archived page (use the `record_id`). Are contexts right? Is `self_url_echo` right?
Send me the pilot output and the problems you find.

Then scale up: `--n-warcs 50`, no `--limit`. Each WARC is about 1 GB streamed, roughly 5–15 minutes.
Run several Colab sessions with different `--seed`, all into the same `--out` folder (finished WARCs are skipped).
With the lab rates:

```bash
!cd crawl && python aggregate.py --in /content/cc_full \
      --lab /content/project-xss/logs/cross_context.csv
```

Keep `/content/cc_*` in Drive. Don't publish per-host rows.

## C1: systematic review
```bash
!cd review && python search.py --out candidates.csv --mailto <your email>
```
Then export IEEE Xplore (CSV) and ACM DL (BibTeX) results for the same query by hand, and run:
`python search.py --out candidates.csv --sources none --import ieee.csv acm.bib`.
Screening and extraction are done by two people in a spreadsheet (see `review/PROTOCOL.md`).
Agreement: `python agreement.py screen candidates.csv` and
`python agreement.py extract coder_A.csv coder_B.csv`.
