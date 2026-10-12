"""Re-analysis of Project-Xss results with payload-group as the unit of analysis.

Uses only committed logs, manifest and trained models. Generates nothing new.

    python analysis.py --repo /content/project-xss [--out results] [--boot 2000]

Outputs (all in --out):
  rq1_exec_auc.csv          per model: attack-vs-benign AUC, exec AUC (+ group-bootstrap CI),
                            on all distinct strings and on near-original payloads only,
                            plus per-source exec AUC
  rq1_baselines.csv         trivial baselines for exec AUC (length, char-class counts)
  rq2_benchmark_audit.csv   per source: adjudicable, executes render-only, executes w/ interaction
  rq3_context.csv           payload / sink / both, for three sink sets, per application log
  rq3_escaped_control.csv   escaped-sink negative control with rows / payloads / groups
  denominators.csv          rows, distinct payloads and groups behind every table
"""
import argparse
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import Pipeline

warnings.filterwarnings("ignore")
SEED = 42
MODELS = ["baseline", "augmented", "char_svm", "word_lr", "hand_rf", "hand_gb", "hybrid_lr", "charcnn"]


def group_boot_auc(y, s, g, n, seed=SEED):
    """95% CI for AUC, resampling whole groups with replacement."""
    y, s, g = map(np.asarray, (y, s, g))
    if len(np.unique(y)) < 2:
        return np.nan, np.nan
    rng = np.random.default_rng(seed)
    uniq = np.unique(g)
    idx = {k: np.flatnonzero(g == k) for k in uniq}
    out = []
    for _ in range(n):
        take = np.concatenate([idx[k] for k in rng.choice(uniq, len(uniq), replace=True)])
        if len(np.unique(y[take])) == 2:
            out.append(roc_auc_score(y[take], s[take]))
    return float(np.percentile(out, 2.5)), float(np.percentile(out, 97.5))


def auc_or_nan(y, s):
    return roc_auc_score(y, s) if len(np.unique(y)) == 2 else np.nan


def executes(d, load_col, inter_col):
    load = d[load_col].astype(str) == "1"
    inter = d[inter_col].astype(str) == "1"
    return load.astype(int), (load | inter).astype(int)


def rq1(repo, out, nboot, denoms):
    m = pd.read_csv(repo / "data/manifest.csv", keep_default_na=False)
    test = m[m.split == "test"]
    att = test[test.label_kind == "attack_variant"].copy()
    att["ex_render"], att["ex_any"] = executes(att, "browser_confirmed", "browser_confirmed_with_interaction")
    att = att.drop_duplicates("norm_text")
    ben = test[test.label_kind == "fpr_probe"].drop_duplicates("norm_text")
    near = att[att.subtype == "single_urlencode"]          # closest to the verbatim payload
    for name, d in [("rq1_all_strings", att), ("rq1_near_original", near)]:
        denoms.append(dict(table=name, rows=len(d), distinct=d.norm_text.nunique(),
                           groups=d.group_id.nunique(), positives_any=int(d.ex_any.sum()),
                           positives_render=int(d.ex_render.sum())))

    rows = []
    sys.path.insert(0, str(repo))
    for name in MODELS:
        f = repo / "models" / f"{name}.joblib"
        if not f.exists():
            print(f"  skip {name}: no model file")
            continue
        try:
            pipe = joblib.load(f)["pipeline"]
            s_att = pipe.predict_proba(att.norm_text.tolist())[:, 1]
            s_ben = pipe.predict_proba(ben.norm_text.tolist())[:, 1]
        except Exception as e:                               # e.g. charcnn needs torch
            print(f"  skip {name}: {type(e).__name__}: {e}")
            continue
        att["s"] = s_att
        nr = att[att.subtype == "single_urlencode"]
        r = dict(model=name,
                 auc_attack_vs_benign=roc_auc_score(np.r_[np.ones(len(s_att)), np.zeros(len(s_ben))],
                                                    np.r_[s_att, s_ben]))
        for tag, d in [("all", att), ("near", nr)]:
            for lab in ["ex_any", "ex_render"]:
                lo, hi = group_boot_auc(d[lab], d.s, d.group_id, nboot)
                r[f"exec_auc_{tag}_{lab}"] = auc_or_nan(d[lab], d.s)
                r[f"ci_{tag}_{lab}"] = f"[{lo:.3f}, {hi:.3f}]"
        for src, g in nr.groupby("source"):
            r[f"exec_auc_near_ex_any_{src}"] = auc_or_nan(g.ex_any, g.s)
        rows.append(r)
        print(f"  {name:<10} attack/benign {r['auc_attack_vs_benign']:.3f}  "
              f"exec(near, any) {r['exec_auc_near_ex_any']:.3f} {r['ci_near_ex_any']}")
    pd.DataFrame(rows).to_csv(out / "rq1_exec_auc.csv", index=False)

    # trivial baselines on the near-original payloads: if these match the detectors,
    # the detectors' exec signal is no more than string shape
    nr = att[att.subtype == "single_urlencode"].copy()
    feats = {
        "neg_length": -nr.text.str.len(),
        "neg_n_angle_brackets": -nr.text.str.count("<"),
        "neg_n_nonalnum": -nr.text.str.count(r"[^A-Za-z0-9\s]"),
        "neg_n_tags": -nr.text.str.count(r"<[A-Za-z]"),
    }
    b = []
    for k, v in feats.items():
        lo, hi = group_boot_auc(nr.ex_any, v, nr.group_id, nboot)
        b.append(dict(feature=k, exec_auc_any=auc_or_nan(nr.ex_any, v), ci=f"[{lo:.3f}, {hi:.3f}]"))
    pd.DataFrame(b).to_csv(out / "rq1_baselines.csv", index=False)
    print(pd.DataFrame(b).to_string(index=False))


def rq2(repo, out, denoms):
    b = pd.read_csv(repo / "logs/benchmark_audit.csv", keep_default_na=False)
    b["render"] = b.fired_load.astype(str) == "1"
    b["any"] = b.render | (b.fired_interact.astype(str) == "1")
    r = b.groupby(["source", "row_id"]).agg(obs=("observable", "first"), render=("render", "any"),
                                            any_=("any", "any"))
    r["obs"] = r.obs.astype(str).isin(["1", "True", "true"])
    t = r.groupby("source").apply(lambda g: pd.Series(dict(
        rows=len(g), adjudicable=int(g.obs.sum()),
        exec_render=int((g.obs & g.render).sum()), exec_any=int((g.obs & g.any_).sum()))))
    t["rate_render"] = t.exec_render / t.adjudicable
    t["rate_any"] = t.exec_any / t.adjudicable
    t.to_csv(out / "rq2_benchmark_audit.csv")
    print(t.to_string())
    denoms.append(dict(table="rq2_benchmark_audit", rows=len(b), distinct=len(r), groups=np.nan))


def context_model(kind):
    v = (TfidfVectorizer(analyzer="word", token_pattern=r"\S+") if kind == "sink_only"
         else TfidfVectorizer(analyzer="char", ngram_range=(2, 5), sublinear_tf=True, min_df=2))
    return Pipeline([("v", v), ("c", LogisticRegression(max_iter=3000, random_state=SEED))])


def context_inputs(kind, d):
    if kind == "payload_only":
        return d.norm_text.tolist()
    if kind == "sink_only":
        return d.sink.tolist()
    return [f"[{s}] {t}" for s, t in zip(d.sink, d.norm_text)]


def rq3(repo, out, nboot, denoms):
    rows, ctrl = [], []
    for log in ["cross_context", "cross_context_app2", "cross_context_engines"]:
        f = repo / "logs" / f"{log}.csv"
        if not f.exists():
            continue
        d = pd.read_csv(f, keep_default_na=False)
        d = d[d.note == ""].copy()
        d["ex"] = ((d.fired_load.astype(int) == 1) | (d.fired_interact.astype(int) == 1)).astype(int)
        esc = d[d.sink.str.contains("escap")]
        ctrl.append(dict(log=log, rows=len(esc), distinct_payloads=esc.norm_text.nunique(),
                         groups=esc.group_id.nunique(), fired=int(esc.ex.sum()),
                         rule_of_three_upper_on_groups=3 / max(esc.group_id.nunique(), 1)))
        rates = d.groupby("sink").ex.mean()
        possible = rates[rates >= 0.01].index           # sinks where execution happens at all
        sets = {"all_sinks": d, "exec_possible_sinks": d[d.sink.isin(possible)]}
        for name, dd in sets.items():
            tr, te = dd[dd.split.isin(["train", "val"])], dd[dd.split == "test"]
            if te.ex.nunique() < 2 or tr.sink.nunique() < 2:
                continue
            assert not (set(tr.group_id) & set(te.group_id)), "group leak"
            r = dict(log=log, sink_set=name, sinks="|".join(sorted(dd.sink.unique())),
                     n_test=len(te), test_groups=te.group_id.nunique())
            for kind in ["payload_only", "sink_only", "payload_sink"]:
                p = context_model(kind).fit(context_inputs(kind, tr), tr.ex)
                s = p.predict_proba(context_inputs(kind, te))[:, 1]
                lo, hi = group_boot_auc(te.ex, s, te.group_id, nboot)
                r[kind] = roc_auc_score(te.ex, s)
                r[f"{kind}_ci"] = f"[{lo:.3f}, {hi:.3f}]"
            r["context_gain"] = r["payload_sink"] - r["payload_only"]
            rows.append(r)
            print(f"  {log:<22} {name:<20} payload {r['payload_only']:.3f}  sink {r['sink_only']:.3f}  "
                  f"both {r['payload_sink']:.3f}  gain {r['context_gain']:+.3f}")
        denoms.append(dict(table=f"rq3_{log}", rows=len(d), distinct=d.norm_text.nunique(),
                           groups=d.group_id.nunique()))
    pd.DataFrame(rows).to_csv(out / "rq3_context.csv", index=False)
    pd.DataFrame(ctrl).to_csv(out / "rq3_escaped_control.csv", index=False)
    print(pd.DataFrame(ctrl).to_string(index=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", default="results")
    ap.add_argument("--boot", type=int, default=2000)
    a = ap.parse_args()
    repo, out = Path(a.repo), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    denoms = []
    print("== RQ1: does the score track execution? ==");  rq1(repo, out, a.boot, denoms)
    print("\n== RQ2: public benchmark audit ==");          rq2(repo, out, denoms)
    print("\n== RQ3: output context ==");                  rq3(repo, out, a.boot, denoms)
    pd.DataFrame(denoms).to_csv(out / "denominators.csv", index=False)
    print(f"\nall tables -> {out}/")


if __name__ == "__main__":
    main()
