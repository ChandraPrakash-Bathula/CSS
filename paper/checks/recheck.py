"""Independent re-checks of README claims against Project-Xss logs and models.

Run from the Project-Xss root with scikit-learn installed:
    python /path/to/recheck.py
Each block prints the number that AUDIT.md cites.
"""
import sys
import warnings

import joblib
import pandas as pd
from sklearn.metrics import roc_auc_score

warnings.filterwarnings("ignore")
sys.path.insert(0, ".")


def ex_col(d, a="browser_confirmed", b="browser_confirmed_with_interaction"):
    return ((d[a].astype(str) == "1") | (d[b].astype(str) == "1")).astype(int)


# 1. Effective sample size behind Table 3
m = pd.read_csv("data/manifest.csv", keep_default_na=False)
t = m[(m.split == "test") & (m.label_kind == "attack_variant")].copy()
t["ex"] = ex_col(t)
t = t.drop_duplicates("norm_text")
print(f"[T3] distinct test strings {len(t)}, parents {t.parent_id.nunique()}, groups {t.group_id.nunique()}")
print("[T3] execution label is constant within a parent across subtypes:",
      t[~t.subtype.isin(["entity_in_html_body"])].groupby("parent_id").ex.nunique().max() == 1)

# 2. Table 3 decomposed: source, length baseline, within-subtype
s = t[t.subtype == "single_urlencode"].copy()
s["score"] = joblib.load("models/baseline.joblib")["pipeline"].predict_proba(s.norm_text.tolist())[:, 1]
print(f"[T3] baseline exec-AUC on 92 near-original payloads {roc_auc_score(s.ex, s.score):.3f}")
print(f"[T3] payload LENGTH alone (shorter = executes) AUC {roc_auc_score(s.ex, -s.text.str.len()):.3f}")
print("[T3] exec rate by source:", s.groupby("source").ex.mean().round(3).to_dict())

# 3. Fixed strings that dominate the row-level browser labels
b = pd.read_csv("data/browser_results.csv", keep_default_na=False)
b["c"] = b.browser_confirmed.astype(int)
fixed = b.subtype.isin(["js_string_breakout", "entity_in_attr_value"])
print(f"[B] confirmed rows {b.c.sum()}, of which from 2 constant strings {b[fixed].c.sum()}")

# 4. Context value with and without trivially-zero sinks
from ml.context_crossed import build, inputs, load  # noqa: E402

d = load()
for name, dd in [("all sinks", d),
                 ("drop escaped + js", d[~d.sink.isin(["html_text_escaped", "js_string_literal"])])]:
    tr, te = dd[dd.split.isin(["train", "val"])], dd[dd.split == "test"]
    r = {k: round(roc_auc_score(te.ex, build(k).fit(inputs(k, tr), tr.ex)
                                .predict_proba(inputs(k, te))[:, 1]), 3)
         for k in ["payload_only", "sink_only", "payload_sink"]}
    print(f"[T4] {name}: {r}")

# 5. Escaped-sink zero: rows vs distinct payloads vs groups
rows, payloads, groups = 0, set(), set()
for f in ["logs/cross_context.csv", "logs/cross_context_app2.csv", "logs/cross_context_engines.csv"]:
    x = pd.read_csv(f, keep_default_na=False)
    e = x[x.sink.str.contains("escap")]
    assert ((e.fired_load.astype(int) | e.fired_interact.astype(int)) == 0).all()
    rows += len(e); payloads |= set(e.norm_text); groups |= set(e.group_id)
print(f"[Z] escaped: {rows} rows, {len(payloads)} distinct payloads, {len(groups)} groups, 0 fired; "
      f"rule-of-three upper bound on groups = {3/len(groups):.2%}")
