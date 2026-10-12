"""Stream Common Crawl WARC files and record where query values reappear in responses.

Passive: reads only Common Crawl's public archive (data.commoncrawl.org). No request is
sent to any archived site.

    python run_warc.py --crawl CC-MAIN-2025-38 --n-warcs 20 --seed 1 --out out/
    python run_warc.py --crawl CC-MAIN-2025-38 --warc-list my_paths.txt --out out/
    python run_warc.py --local-warc file.warc.gz --out out/          # offline / testing

Per WARC it writes two files (so a crash loses at most one WARC, and --resume skips done ones):
  out/pages/<warc>.csv        one row per HTML response with a query string
  out/occurrences/<warc>.csv  one row per reflection (see reflect.Occurrence)
"""
import argparse
import csv
import gzip
import hashlib
import os
import random
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests
from warcio.archiveiterator import ArchiveIterator

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reflect import Occurrence, analyse, candidate_params, to_rows  # noqa: E402

BASE = "https://data.commoncrawl.org/"
MAX_BODY = 2_000_000            # bytes; larger pages are skipped and counted
PAGE_COLS = ["warc", "record_id", "host", "status", "n_params", "n_candidate_params",
             "n_reflected_params", "n_occurrences", "body_bytes", "skipped"]
OCC_COLS = list(Occurrence.__dataclass_fields__) + ["warc", "record_id", "host"]


def warc_paths(crawl, n, seed):
    r = requests.get(f"{BASE}crawl-data/{crawl}/warc.paths.gz", timeout=60)
    r.raise_for_status()
    paths = gzip.decompress(r.content).decode().split()
    random.Random(seed).shuffle(paths)          # uniform random sample of WARC files
    return paths[:n]


def open_stream(path, retries=4):
    if os.path.exists(path):
        return open(path, "rb")
    for k in range(retries):
        try:
            r = requests.get(BASE + path, stream=True, timeout=120)
            r.raise_for_status()
            r.raw.decode_content = False
            return r.raw
        except requests.RequestException as e:
            wait = 2 ** (k + 1)
            print(f"  fetch failed ({e}); retry in {wait}s")
            time.sleep(wait)
    raise RuntimeError(f"could not fetch {path}")


def decode_body(raw, ctype):
    charset = "utf-8"
    for part in ctype.split(";"):
        part = part.strip().lower()
        if part.startswith("charset="):
            charset = part.split("=", 1)[1].strip("\"' ") or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def process(path, out, salt, limit=0):
    name = Path(path).name.replace(".warc.gz", "")
    pf, of = out / "pages" / f"{name}.csv", out / "occurrences" / f"{name}.csv"
    tmp_p, tmp_o = pf.with_suffix(".part"), of.with_suffix(".part")
    n_resp = n_q = n_occ = 0
    t0 = time.time()
    with open(tmp_p, "w", newline="") as fp, open(tmp_o, "w", newline="") as fo:
        wp, wo = csv.DictWriter(fp, PAGE_COLS), csv.DictWriter(fo, OCC_COLS)
        wp.writeheader()
        wo.writeheader()
        for rec in ArchiveIterator(open_stream(path)):
            if rec.rec_type != "response":
                continue
            n_resp += 1
            url = rec.rec_headers.get_header("WARC-Target-URI") or ""
            sp = urlsplit(url)
            if not sp.query:
                continue
            hh = rec.http_headers
            if hh is None:
                continue
            ctype = (hh.get_header("Content-Type") or "").lower()
            if "html" not in ctype:
                continue
            n_q += 1
            rid = rec.rec_headers.get_header("WARC-Record-ID") or ""
            host = (sp.hostname or "").lower()
            status = hh.get_statuscode()
            n_params = len([p for p in sp.query.split("&") if p])
            cands = list(candidate_params(url))
            raw = rec.content_stream().read(MAX_BODY + 1)
            skipped = ""
            occs = []
            if len(raw) > MAX_BODY:
                skipped = "too_large"
            elif cands:
                try:
                    occs = analyse(url, decode_body(raw, ctype), salt=salt)
                except Exception as e:          # never let one page kill a WARC
                    skipped = f"error:{type(e).__name__}"
            n_occ += len(occs)
            wo.writerows(to_rows(occs, warc=name, record_id=rid, host=host))
            wp.writerow(dict(warc=name, record_id=rid, host=host, status=status,
                             n_params=n_params, n_candidate_params=len(cands),
                             n_reflected_params=len({o.param_hash for o in occs}),
                             n_occurrences=len(occs), body_bytes=len(raw), skipped=skipped))
            if limit and n_q >= limit:
                break
    tmp_p.rename(pf)
    tmp_o.rename(of)
    print(f"  {name}: {n_resp} responses, {n_q} HTML with query, {n_occ} reflections, "
          f"{time.time() - t0:.0f}s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crawl", default="CC-MAIN-2025-38")
    ap.add_argument("--n-warcs", type=int, default=10)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--warc-list", help="file with one WARC path per line")
    ap.add_argument("--local-warc", nargs="*", default=[])
    ap.add_argument("--limit", type=int, default=0, help="stop each WARC after N query pages")
    ap.add_argument("--out", default="out")
    ap.add_argument("--salt", default=os.environ.get("REFLECT_SALT", ""),
                    help="secret salt for value hashes; set it and keep it private")
    a = ap.parse_args()

    out = Path(a.out)
    (out / "pages").mkdir(parents=True, exist_ok=True)
    (out / "occurrences").mkdir(parents=True, exist_ok=True)
    if not a.salt:
        a.salt = hashlib.sha256(os.urandom(32)).hexdigest()
        print("note: random salt for this run (hashes are not comparable across runs)")

    if a.local_warc:
        paths = a.local_warc
    elif a.warc_list:
        paths = [l.strip() for l in open(a.warc_list) if l.strip()]
    else:
        paths = warc_paths(a.crawl, a.n_warcs, a.seed)
        (out / "warc_sample.txt").write_text("\n".join(paths) + "\n")

    for p in paths:
        name = Path(p).name.replace(".warc.gz", "")
        if (out / "occurrences" / f"{name}.csv").exists():
            print(f"  skip {name} (done)")
            continue
        process(p, out, a.salt, a.limit)


if __name__ == "__main__":
    main()
