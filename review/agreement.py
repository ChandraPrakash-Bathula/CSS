"""Inter-coder agreement for screening and extraction.

    python agreement.py screen candidates.csv            # screen_A vs screen_B, fulltext_A vs fulltext_B
    python agreement.py extract coder_A.csv coder_B.csv   # per-field kappa over extraction sheets

Kappa per field is computed on rows both coders filled. Multi-valued fields (`;`-separated)
are compared per code, as presence/absence, and the mean kappa is reported.
Disagreements are written to disagreements.csv for the reconciliation meeting.
"""
import sys

import pandas as pd
from sklearn.metrics import cohen_kappa_score

MULTI = {"datasets", "xss_types"}
SKIP = {"paper_id", "notes", "headline_value", "dataset_size_pos", "dataset_size_neg", "year"}


def kappa(a, b):
    if len(set(a) | set(b)) < 2:
        return float("nan")            # one category only: kappa undefined, report raw agreement
    return cohen_kappa_score(a, b)


def screen(path):
    d = pd.read_csv(path, keep_default_na=False)
    for a, b in [("screen_A", "screen_B"), ("fulltext_A", "fulltext_B")]:
        x = d[(d[a] != "") & (d[b] != "")]
        if x.empty:
            continue
        print(f"{a[:-2]}: n={len(x)}  agreement={(x[a] == x[b]).mean():.3f}  kappa={kappa(x[a], x[b]):.3f}")
        x[x[a] != x[b]][["paper_id", "title", a, b]].to_csv(f"disagreements_{a[:-2]}.csv", index=False)


def extract(pa, pb):
    A = pd.read_csv(pa, keep_default_na=False).set_index("paper_id")
    B = pd.read_csv(pb, keep_default_na=False).set_index("paper_id")
    common = A.index.intersection(B.index)
    rows, dis = [], []
    for f in A.columns:
        if f in SKIP or f.endswith("_evidence") or f not in B.columns:
            continue
        a, b = A.loc[common, f], B.loc[common, f]
        m = (a != "") & (b != "")
        a, b = a[m], b[m]
        if a.empty:
            continue
        if f in MULTI:
            codes = sorted({c for v in pd.concat([a, b]) for c in v.split(";") if c})
            ks = [kappa([c in v.split(";") for v in a], [c in v.split(";") for v in b]) for c in codes]
            k = pd.Series(ks).mean()
            agree = (a.map(lambda v: set(v.split(";"))) == b.map(lambda v: set(v.split(";")))).mean()
        else:
            k, agree = kappa(a, b), (a == b).mean()
        rows.append(dict(field=f, n=len(a), raw_agreement=agree, kappa=k))
        for pid in a.index[a != b]:
            dis.append(dict(paper_id=pid, field=f, coder_A=a[pid], coder_B=b[pid]))
    t = pd.DataFrame(rows)
    print(t.to_string(index=False, float_format="%.3f"))
    pd.DataFrame(dis).to_csv("disagreements_extraction.csv", index=False)
    print(f"\n{len(dis)} disagreements -> disagreements_extraction.csv")


if __name__ == "__main__":
    if sys.argv[1] == "screen":
        screen(sys.argv[2])
    else:
        extract(sys.argv[2], sys.argv[3])
