"""Collect candidate papers for the systematic review and deduplicate them.

    python search.py --out candidates.csv [--mailto you@uni.edu] [--since 2015]
    python search.py --out candidates.csv --import ieee_export.csv acm_export.bib   # manual exports

Every raw API response is saved under raw/ with the date, so the search is auditable and
the exact query strings are in this file. Re-running never deletes screening columns
already filled in candidates.csv: new records are appended, existing ones are kept.
"""
import argparse
import csv
import datetime as dt
import json
import re
import time
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

XSS = ['"cross-site scripting"', '"cross site scripting"', "XSS"]
ML = ['"machine learning"', '"deep learning"', '"neural network"', "classifier", '"random forest"',
      "SVM", "LSTM", "CNN", "transformer", "BERT", '"language model"', "LLM"]
TASK = ["detection", "detect", "classification", "classify", '"web application firewall"', "WAF"]

# Simpler keyword sets for APIs without boolean syntax; results are filtered locally by
# matches_query() so every source ends up with the same logical query.
SIMPLE_QUERIES = [
    "cross-site scripting machine learning detection",
    "XSS detection deep learning",
    "XSS detection neural network",
    "cross site scripting classifier",
    "XSS attack detection transformer BERT",
    "XSS detection large language model",
    "web attack detection XSS machine learning",
    "malicious payload detection XSS convolutional LSTM",
    "XSS web application firewall machine learning",
]

COLS = ["paper_id", "title", "year", "venue", "doi", "arxiv_id", "url", "authors", "abstract",
        "sources", "query_match", "screen_A", "screen_B", "screen_final", "fulltext_A",
        "fulltext_B", "fulltext_final", "exclude_reason", "notes"]

RAW = Path(__file__).resolve().parent / "raw"


def norm_title(t):
    t = unicodedata.normalize("NFKD", t or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", " ", t).strip()


def matches_query(text):
    t = (text or "").lower()
    xss = any(k in t for k in ["cross-site scripting", "cross site scripting", "xss"])
    ml = any(k in t for k in ["machine learning", "deep learning", "neural", "classifier",
                              "random forest", "svm", "support vector", "lstm", "cnn", "convolutional",
                              "transformer", "bert", "language model", "llm", "learning-based",
                              "xgboost", "naive bayes", "decision tree", "gradient boosting"])
    task = any(k in t for k in ["detect", "classif", "firewall", "waf"])
    return xss and ml and task


def save_raw(source, q, payload):
    RAW.mkdir(exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "_", q.lower())[:50]
    f = RAW / f"{dt.date.today()}_{source}_{slug}.json"
    f.write_text(json.dumps(payload, indent=1)[:20_000_000])


def get(url, params=None, headers=None, tries=4):
    for k in range(tries):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=60)
            if r.status_code == 429:
                time.sleep(5 * (k + 1))
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            print(f"    {e}; retry")
            time.sleep(2 ** (k + 1))
    return None


def openalex(since, mailto):
    q = "(" + " OR ".join(XSS) + ") AND (" + " OR ".join(ML) + ") AND (" + " OR ".join(TASK) + ")"
    out, cursor = [], "*"
    pages = []
    while cursor:
        r = get("https://api.openalex.org/works", params={
            "filter": f"title_and_abstract.search:{q},from_publication_date:{since}-01-01",
            "per-page": 200, "cursor": cursor, **({"mailto": mailto} if mailto else {})})
        if r is None:
            break
        j = r.json()
        pages.append(j)
        for w in j.get("results", []):
            inv = w.get("abstract_inverted_index") or {}
            words = sorted(((p, wd) for wd, ps in inv.items() for p in ps))
            out.append(dict(
                title=w.get("title") or "", year=w.get("publication_year"),
                venue=((w.get("primary_location") or {}).get("source") or {}).get("display_name", ""),
                doi=(w.get("doi") or "").replace("https://doi.org/", ""),
                url=w.get("id", ""), abstract=" ".join(wd for _, wd in words),
                authors="; ".join(a["author"]["display_name"] for a in w.get("authorships", [])[:10])))
        cursor = j.get("meta", {}).get("next_cursor")
        time.sleep(0.2)
    save_raw("openalex", "boolean", pages)
    return out


def semantic_scholar(since):
    out = []
    for q in SIMPLE_QUERIES:
        token, pages = None, []
        while True:
            params = {"query": q, "year": f"{since}-",
                      "fields": "title,year,venue,externalIds,abstract,authors,url"}
            if token:
                params["token"] = token
            r = get("https://api.semanticscholar.org/graph/v1/paper/search/bulk", params=params)
            if r is None:
                break
            j = r.json()
            pages.append(j)
            for p in j.get("data", []) or []:
                ids = p.get("externalIds") or {}
                out.append(dict(title=p.get("title") or "", year=p.get("year"), venue=p.get("venue") or "",
                                doi=ids.get("DOI", "") or "", arxiv_id=ids.get("ArXiv", "") or "",
                                url=p.get("url") or "", abstract=p.get("abstract") or "",
                                authors="; ".join(a.get("name", "") for a in (p.get("authors") or [])[:10])))
            token = j.get("token")
            if not token or len(pages) > 20:
                break
            time.sleep(1.1)
        save_raw("s2", q, pages)
    return out


def arxiv(since):
    out = []
    ns = {"a": "http://www.w3.org/2005/Atom"}
    for q in SIMPLE_QUERIES:
        terms = " AND ".join(f"all:{w}" for w in q.split() if len(w) > 2)
        r = get("https://export.arxiv.org/api/query",
                params={"search_query": terms, "start": 0, "max_results": 300})
        if r is None:
            continue
        save_raw("arxiv", q, {"xml": r.text})
        root = ET.fromstring(r.text)
        for e in root.findall("a:entry", ns):
            year = int((e.findtext("a:published", "", ns) or "0000")[:4])
            if year < since:
                continue
            aid = (e.findtext("a:id", "", ns) or "").rsplit("/abs/", 1)[-1]
            out.append(dict(title=" ".join((e.findtext("a:title", "", ns) or "").split()), year=year,
                            venue="arXiv", arxiv_id=re.sub(r"v\d+$", "", aid),
                            url=e.findtext("a:id", "", ns), abstract=" ".join((e.findtext("a:summary", "", ns) or "").split()),
                            authors="; ".join(a.findtext("a:name", "", ns) for a in e.findall("a:author", ns)[:10])))
        time.sleep(3.1)                               # arXiv asks for >= 3 s between calls
    return out


def dblp(since):
    out = []
    for q in ["xss machine learning", "xss deep learning", "cross-site scripting detection",
              "xss detection", "xss neural", "xss classifier", "xss llm", "xss transformer"]:
        r = get("https://dblp.org/search/publ/api", params={"q": q, "format": "json", "h": 1000})
        if r is None:
            continue
        j = r.json()
        save_raw("dblp", q, j)
        for h in j.get("result", {}).get("hits", {}).get("hit", []) or []:
            i = h.get("info", {})
            year = int(i.get("year", 0) or 0)
            if year < since:
                continue
            au = i.get("authors", {}).get("author", [])
            au = au if isinstance(au, list) else [au]
            out.append(dict(title=i.get("title", ""), year=year, venue=i.get("venue", ""),
                            doi=i.get("doi", ""), url=i.get("ee", "") if isinstance(i.get("ee"), str) else "",
                            abstract="", authors="; ".join(a.get("text", "") for a in au[:10])))
        time.sleep(1)
    return out


def import_exports(files):
    """IEEE Xplore CSV and ACM DL BibTeX exports, done by hand in the browser."""
    out = []
    for f in files:
        p = Path(f)
        if p.suffix.lower() == ".csv":
            with open(p, newline="", encoding="utf-8-sig") as fh:
                for r in csv.DictReader(fh):
                    out.append(dict(title=r.get("Document Title") or r.get("Title", ""),
                                    year=r.get("Publication Year") or r.get("Year", ""),
                                    venue=r.get("Publication Title") or r.get("Source", ""),
                                    doi=r.get("DOI", ""), abstract=r.get("Abstract", ""),
                                    authors=r.get("Authors", ""), url=r.get("PDF Link", "")))
        elif p.suffix.lower() == ".bib":
            for entry in re.split(r"\n@", p.read_text(encoding="utf-8", errors="replace")):
                g = lambda k: (re.search(rf"\b{k}\s*=\s*[{{\"](.+?)[}}\"]\s*,?\n", entry, re.S | re.I) or [None, ""])[1]
                if g("title"):
                    out.append(dict(title=" ".join(g("title").split()), year=g("year"), venue=g("booktitle") or g("journal"),
                                    doi=g("doi"), abstract=" ".join(g("abstract").split()), authors=g("author"), url=g("url")))
    return out


def merge(records, existing):
    """Deduplicate on DOI, then arXiv id, then normalised title. Keeps screening columns."""
    by_key = {}
    rows = {r["paper_id"]: r for r in existing}
    for r in existing:
        for k in keys(r):
            by_key[k] = r["paper_id"]
    next_id = 1 + max([int(p[1:]) for p in rows] or [0])
    for src, rec in records:
        ks = keys(rec)
        pid = next((by_key[k] for k in ks if k in by_key), None)
        if pid is None:
            pid = f"P{next_id:04d}"
            next_id += 1
            rows[pid] = {c: "" for c in COLS} | {"paper_id": pid}
        row = rows[pid]
        for c in ["title", "year", "venue", "doi", "arxiv_id", "url", "authors", "abstract"]:
            if not row.get(c) and rec.get(c):
                row[c] = str(rec[c])
        srcs = set(filter(None, row.get("sources", "").split(";"))) | {src}
        row["sources"] = ";".join(sorted(srcs))
        row["query_match"] = str(matches_query(row["title"] + " " + row["abstract"]))
        for k in keys(row):
            by_key[k] = pid
    return list(rows.values())


def keys(r):
    ks = []
    if r.get("doi"):
        ks.append("doi:" + r["doi"].lower().strip())
    if r.get("arxiv_id"):
        ks.append("arxiv:" + re.sub(r"v\d+$", "", r["arxiv_id"].strip()))
    t = norm_title(r.get("title", ""))
    if len(t) > 20:
        ks.append("title:" + t)
    return ks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="candidates.csv")
    ap.add_argument("--since", type=int, default=2015)
    ap.add_argument("--mailto", default="")
    ap.add_argument("--sources", default="openalex,s2,arxiv,dblp")
    ap.add_argument("--import", dest="imports", nargs="*", default=[])
    a = ap.parse_args()

    out = Path(a.out)
    existing = list(csv.DictReader(open(out, newline="", encoding="utf-8"))) if out.exists() else []
    recs = []
    fns = {"openalex": lambda: openalex(a.since, a.mailto), "s2": lambda: semantic_scholar(a.since),
           "arxiv": lambda: arxiv(a.since), "dblp": lambda: dblp(a.since)}
    for s in a.sources.split(","):
        if s in fns:
            print(f"searching {s} ...")
            got = fns[s]()
            print(f"  {len(got)} records")
            recs += [(s, r) for r in got]
    if a.imports:
        got = import_exports(a.imports)
        print(f"imported {len(got)} records")
        recs += [("manual_export", r) for r in got]
    rows = merge(recs, existing)
    rows.sort(key=lambda r: r["paper_id"])
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    n_match = sum(r["query_match"] == "True" for r in rows)
    print(f"{len(rows)} unique records -> {out}  ({n_match} match the full boolean query locally)")
    log = Path(__file__).resolve().parent / "SEARCH_LOG.md"
    with open(log, "a") as fh:
        fh.write(f"- {dt.datetime.now():%Y-%m-%d %H:%M} sources={a.sources} imports={a.imports} "
                 f"raw_records={len(recs)} unique_total={len(rows)} query_match={n_match}\n")


if __name__ == "__main__":
    main()
