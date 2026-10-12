"""Aggregate run_warc.py output into the prevalence tables for the paper.

    python aggregate.py --in out/ [--lab /content/project-xss/logs/cross_context.csv] [--boot 1000]

Unit of analysis is the *reflection point*: one (page, parameter) pair that reappears in
the response. Confidence intervals resample whole hosts, because pages of one site share
a template and are not independent.

Only aggregate numbers are produced. Nothing here names a host, and the paper must not.

Outputs (in --in):
  T_overview.csv          pages, hosts, share of pages that reflect any query value
  T_context.csv           share of reflection points with >=1 occurrence per context,
                          with and without self-URL echoes (canonical/og:url links)
  T_script_split.csv      inside JavaScript: string literal vs code vs comment
  T_attr_quoting.csv      attribute contexts by quote style
  T_encoding.csv          among values containing < > " ' &: raw vs encoded, per context
  T_lab_coverage.csv      share of real reflection points whose context has a lab sink,
                          and (with --lab) the lab execution rate of that sink
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 7

# real-web context -> the closest sink measured in the Project-Xss lab (None = not measured)
LAB_SINK = {
    ("html_text", "raw"): "html_body_raw",
    ("html_text", "escaped"): "html_text_escaped",
    ("attr_other", '"'): "attribute_double_quoted",
    ("script_js", '"'): "js_string_literal",
}


def load(d):
    pages = pd.concat([pd.read_csv(f, keep_default_na=False) for f in sorted((d / "pages").glob("*.csv"))],
                      ignore_index=True)
    occ_files = sorted((d / "occurrences").glob("*.csv"))
    occ = pd.concat([pd.read_csv(f, keep_default_na=False, dtype={"quote": str, "in_js_string": str})
                     for f in occ_files], ignore_index=True)
    for c in ["value_has_special", "encoding_observable", "self_url_echo"]:
        occ[c] = occ[c].astype(str).str.lower().eq("true")
    occ["point"] = occ.record_id + "|" + occ.param_hash
    return pages, occ


def host_boot(df, stat, n, seed=SEED):
    """Percentile CI for stat(df), resampling hosts with replacement."""
    hosts = df.host.unique()
    if len(hosts) < 2:
        return np.nan, np.nan
    groups = {h: g for h, g in df.groupby("host")}
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n):
        pick = rng.choice(hosts, len(hosts), replace=True)
        vals.append(stat(pd.concat([groups[h] for h in pick], ignore_index=True)))
    return float(np.nanpercentile(vals, 2.5)), float(np.nanpercentile(vals, 97.5))


def fmt(lo, hi):
    return f"[{lo:.4f}, {hi:.4f}]"


def overview(pages, n):
    p = pages[pages.skipped == ""].copy()
    p["has_cand"] = p.n_candidate_params > 0
    p["reflects"] = p.n_reflected_params > 0
    c = p[p.has_cand]
    share = lambda d: d.reflects.mean()
    lo, hi = host_boot(c, share, n)
    return pd.DataFrame([dict(
        html_pages_with_query=len(p), hosts=p.host.nunique(),
        pages_with_candidate_value=int(p.has_cand.sum()),
        pages_reflecting_a_value=int(c.reflects.sum()),
        share_reflecting=share(c), ci=fmt(lo, hi),
        reflection_points=int(p.n_reflected_params.sum()),
        skipped=int((pages.skipped != "").sum()))])


def point_table(occ, key_cols, n):
    """Share of reflection points having >=1 occurrence in each category."""
    pts = occ.groupby("point").host.first().rename("host").reset_index()
    total = len(pts)
    cats = occ[["point"] + key_cols].drop_duplicates()
    rows = []
    for key, g in cats.groupby(key_cols):
        key = key if isinstance(key, tuple) else (key,)
        has = set(g.point)
        df = pts.assign(x=pts.point.isin(has))
        lo, hi = host_boot(df, lambda d: d.x.mean(), n)
        rows.append({**dict(zip(key_cols, key)), "points": len(has), "share": len(has) / total,
                     "ci": fmt(lo, hi), "hosts": occ[occ.point.isin(has)].host.nunique()})
    return pd.DataFrame(rows).sort_values("share", ascending=False)


def encoding_table(occ, n):
    o = occ[occ.encoding_observable].copy()
    if o.empty:
        return pd.DataFrame()
    o["raw"] = o.encoding.eq("raw")
    rows = []
    for ctx, g in o.groupby("context"):
        lo, hi = host_boot(g, lambda d: d.raw.mean(), n)
        rows.append(dict(context=ctx, occurrences=len(g), points=g.point.nunique(),
                         hosts=g.host.nunique(), share_raw=g.raw.mean(), ci=fmt(lo, hi),
                         **{f"enc_{k}": int(v) for k, v in g.encoding.value_counts().items()}))
    return pd.DataFrame(rows).sort_values("occurrences", ascending=False)


def lab_key(r):
    if r.context == "html_text":
        if not r.encoding_observable:
            return None                       # cannot tell raw from escaped
        return ("html_text", "raw" if r.encoding == "raw" else "escaped")
    if r.context == "attr_other":
        return ("attr_other", r.quote)
    if r.context == "script_js":
        return ("script_js", r.in_js_string)
    return (r.context, "")


def lab_coverage(occ, lab_csv, n):
    o = occ[~occ.self_url_echo].copy()
    o["lab_sink"] = [LAB_SINK.get(lab_key(r)) if lab_key(r) else "undetermined"
                     for r in o.itertuples()]
    o["lab_sink"] = o.lab_sink.fillna("not_measured_in_lab")
    # a point counts as covered if ANY of its occurrences maps to a lab sink
    pts = o.groupby("point").agg(host=("host", "first"),
                                 sinks=("lab_sink", lambda s: set(s)))
    lab_names = set(LAB_SINK.values())
    pts["covered"] = pts.sinks.map(lambda s: bool(s & lab_names))
    pts["only_unmeasured"] = pts.sinks.map(lambda s: s <= {"not_measured_in_lab"})
    rows = []
    for col in ["covered", "only_unmeasured"]:
        lo, hi = host_boot(pts.reset_index(), lambda d, c=col: d[c].mean(), n)
        rows.append(dict(measure=col, share=pts[col].mean(), ci=fmt(lo, hi), points=len(pts)))
    out = pd.DataFrame(rows)
    per_sink = o.groupby("lab_sink").point.nunique().rename("points").reset_index()
    if lab_csv:
        lab = pd.read_csv(lab_csv, keep_default_na=False)
        lab = lab[lab.note == ""] if "note" in lab else lab
        lab["ex"] = ((lab.fired_load.astype(int) == 1) | (lab.fired_interact.astype(int) == 1))
        lab["ex_render"] = lab.fired_load.astype(int) == 1
        rates = lab.groupby("sink").agg(lab_exec_rate=("ex", "mean"),
                                        lab_exec_rate_render=("ex_render", "mean")).reset_index()
        per_sink = per_sink.merge(rates, left_on="lab_sink", right_on="sink", how="left").drop(columns="sink")
    return out, per_sink


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="out")
    ap.add_argument("--lab", help="Project-Xss logs/cross_context.csv, for lab execution rates")
    ap.add_argument("--boot", type=int, default=1000)
    a = ap.parse_args()
    d = Path(a.inp)
    pages, occ = load(d)
    n = a.boot

    t = overview(pages, n); t.to_csv(d / "T_overview.csv", index=False); print(t.T.to_string(), "\n")
    if occ.empty:
        print("no reflections found"); return
    for echo_name, o in [("all", occ), ("no_self_url_echo", occ[~occ.self_url_echo])]:
        t = point_table(o, ["context"], n).assign(subset=echo_name)
        t.to_csv(d / f"T_context_{echo_name}.csv", index=False)
        print(f"contexts ({echo_name}):\n", t.head(15).to_string(index=False), "\n")
    js = occ[occ.context == "script_js"].assign(js=lambda x: x.in_js_string.replace("", "code"))
    if not js.empty:
        t = point_table(js, ["js"], n); t.to_csv(d / "T_script_split.csv", index=False)
        print("inside JavaScript:\n", t.to_string(index=False), "\n")
    at = occ[occ.context.str.startswith("attr_") & ~occ.self_url_echo].copy()
    if not at.empty:
        at["quote"] = at.quote.replace({"": "unquoted"})
        t = point_table(at, ["context", "quote"], n); t.to_csv(d / "T_attr_quoting.csv", index=False)
        print("attribute quoting:\n", t.head(15).to_string(index=False), "\n")
    t = encoding_table(occ, n); t.to_csv(d / "T_encoding.csv", index=False)
    print("encoding (values with special characters only):\n", t.to_string(index=False), "\n")
    cov, per_sink = lab_coverage(occ, a.lab, n)
    cov.to_csv(d / "T_lab_coverage.csv", index=False)
    per_sink.to_csv(d / "T_lab_coverage_per_sink.csv", index=False)
    print("lab coverage of real reflection points (self-URL echoes excluded):\n", cov.to_string(index=False))
    print(per_sink.to_string(index=False))


if __name__ == "__main__":
    main()
