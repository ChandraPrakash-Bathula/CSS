"""Build a manual-coding sheet for public benchmark rows that did NOT execute.

Two people code the `cause` column independently (copy the file first); then
`python taxonomy_sheet.py --score a.csv b.csv` reports Cohen's kappa and the table.

Allowed causes (pick one; use `other` + a note sparingly):
  needs_interaction_no_surface   handler on an element a user cannot reach
  needs_precondition             fragment, real resource, specific DOM/sanitiser state
  legacy_browser_only            handler/feature not supported by current browsers
  wrong_context                  written for a sink our five contexts do not include
  pre_encoded                    arrives already escaped/encoded in the source
  malformed                      syntactically broken
  other
"""
import argparse
from pathlib import Path

import pandas as pd

CAUSES = ["needs_interaction_no_surface", "needs_precondition", "legacy_browser_only",
          "wrong_context", "pre_encoded", "malformed", "other"]


def build(repo, out, n, seed=42):
    b = pd.read_csv(Path(repo) / "logs/benchmark_audit.csv", keep_default_na=False)
    b["fired"] = (b.fired_load.astype(str) == "1") | (b.fired_interact.astype(str) == "1")
    r = b.groupby(["source", "row_id"]).agg(text=("text", "first"), obs=("observable", "first"),
                                            fired=("fired", "any")).reset_index()
    r = r[r.obs.astype(str).isin(["1", "True", "true"]) & ~r.fired]
    # stratified by source so the smaller list is not swamped
    per = max(n // r.source.nunique(), 1)
    s = pd.concat([g.sample(min(per, len(g)), random_state=seed) for _, g in r.groupby("source")])
    s = s.sample(frac=1, random_state=seed)[["source", "row_id", "text"]]   # hide ordering
    s["cause"] = ""
    s["note"] = ""
    s.to_csv(out, index=False)
    print(f"{len(s)} rows -> {out}\nallowed causes: {', '.join(CAUSES)}")


def score(a, b):
    from sklearn.metrics import cohen_kappa_score
    x = pd.read_csv(a, keep_default_na=False).set_index(["source", "row_id"])
    y = pd.read_csv(b, keep_default_na=False).set_index(["source", "row_id"])
    j = x[["cause"]].join(y[["cause"]], lsuffix="_a", rsuffix="_b").query("cause_a != '' and cause_b != ''")
    bad = set(j.cause_a) | set(j.cause_b)
    assert bad <= set(CAUSES), f"unknown causes: {bad - set(CAUSES)}"
    print(f"coded by both: {len(j)}   Cohen's kappa = {cohen_kappa_score(j.cause_a, j.cause_b):.3f}")
    agree = j[j.cause_a == j.cause_b]
    print(f"agreed rows: {len(agree)}")
    print(agree.reset_index().groupby(["source", "cause_a"]).size().unstack(fill_value=0).to_string())


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo")
    ap.add_argument("--out", default="results/taxonomy_to_code.csv")
    ap.add_argument("--n", type=int, default=120)
    ap.add_argument("--score", nargs=2, metavar=("CODER_A", "CODER_B"))
    a = ap.parse_args()
    if a.score:
        score(*a.score)
    else:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        build(a.repo, a.out, a.n)
