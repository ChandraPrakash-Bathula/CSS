"""Write a small synthetic WARC (fake hosts, inert tokens) for an offline end-to-end test."""
import io
import random
import sys

from warcio.statusandheaders import StatusAndHeaders
from warcio.warcwriter import WARCWriter

PAGES = [
    ("<p>Results for {v}</p>", "q"),
    ('<input value="{v}"><link rel=canonical href="https://{h}/s?q={v}">', "q"),
    ('<script>var term = "{v}";</script>', "term"),
    ("<title>{v} - shop</title>", "item"),
    ("<p>nothing reflected here</p>", "q"),
    ("<p>{e}</p>", "q"),                   # value with special chars, escaped
    ("<p>{r}</p>", "q"),                   # value with special chars, raw
]


def main(path, n=200, seed=0):
    rng = random.Random(seed)
    with open(path, "wb") as fh:
        w = WARCWriter(fh, gzip=True)
        for i in range(n):
            tpl, param = rng.choice(PAGES)
            h = f"site{rng.randint(1, 40)}.test"
            v = f"tok{rng.randint(10000, 99999)}x"
            special = f"a&b\"{v}"
            from html import escape
            from urllib.parse import quote
            val = special if "{e}" in tpl or "{r}" in tpl else v
            body = tpl.format(v=v, h=h, e=escape(special), r=special).encode()
            url = f"https://{h}/s?{param}={quote(val)}&page=1"
            hh = StatusAndHeaders("200 OK", [("Content-Type", "text/html; charset=utf-8")], protocol="HTTP/1.1")
            w.write_record(w.create_warc_record(url, "response", payload=io.BytesIO(body), http_headers=hh))


if __name__ == "__main__":
    main(sys.argv[1])
