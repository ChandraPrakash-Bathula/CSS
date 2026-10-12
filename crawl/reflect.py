"""Where do query-parameter values land in a page? Passive context classification.

Given one archived HTTP exchange (request URL + response HTML) this finds every place a
query-parameter value reappears in the response body and classifies the *output context*
of each occurrence: text node, attribute (which kind, which quoting), script (inside a
string literal or not), style, comment, RCDATA element, and so on.

This is pure analysis of already-archived pages. It sends no request to any site and
never constructs or inserts anything: the "probe" is whatever value the crawler happened
to request.

Two things are measured separately because they need different evidence:

  context      always observable once a value reappears
  encoding     observable only when the value itself contains a character the context
               would need encoded (< > " ' &). For an alphanumeric value every encoding is
               the identity, so we record `encoding_observable = False` rather than guess.

Privacy: raw parameter values can contain personal data. Records keep a salted hash,
the length and character classes of the value, never the value itself.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
from bisect import bisect_right
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit

MIN_LEN = 5                       # shorter values collide with ordinary page text
SPECIAL = set('<>"\'&')

URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster", "cite", "background",
             "longdesc", "manifest", "codebase", "xlink:href", "ping", "srcset", "imagesrcset"}
RCDATA = {"title", "textarea"}
RAWTEXT_SCRIPTISH = {"script", "style"}
JSON_TYPES = {"application/json", "application/ld+json", "importmap", "speculationrules"}
JS_TYPES = {"", "text/javascript", "application/javascript", "module", "text/ecmascript",
            "application/ecmascript", "text/jscript", "text/livescript"}

# value -> encodings a server might apply before emitting it
ENCODERS = {
    "raw": lambda v: v,
    "html_escaped": lambda v: html.escape(v, quote=True),
    "html_escaped_noquote": lambda v: html.escape(v, quote=False),
    "url_encoded": lambda v: quote(v, safe=""),
    "url_encoded_plus": lambda v: quote_plus(v, safe=""),
    "js_escaped": lambda v: json.dumps(v)[1:-1],
}


@dataclass
class Occurrence:
    param_hash: str
    param_name: str          # names are kept: they are schema, not user data
    value_len: int
    value_has_special: bool
    value_classes: str       # e.g. "a9" letters+digits, "a9p" with punctuation
    encoding: str            # which ENCODERS key produced the matching bytes
    encoding_observable: bool
    context: str             # see Classifier docstring
    detail: str              # tag / attribute name / script type
    quote: str               # for attributes: '"', "'", or "" (unquoted); else ""
    in_js_string: str        # for script: "'", '"', "`" or "" (code); else ""
    self_url_echo: bool      # the attribute holds the page's own URL (canonical, og:url, ...)


def value_classes(v: str) -> str:
    out = ""
    if re.search(r"[A-Za-z]", v):
        out += "a"
    if re.search(r"\d", v):
        out += "9"
    if re.search(r"[^A-Za-z0-9\s]", v):
        out += "p"
    if re.search(r"\s", v):
        out += "s"
    return out


def candidate_params(url: str):
    """(name, value) pairs worth looking for. Values too short/plain to be distinctive are dropped."""
    q = urlsplit(url).query
    seen = set()
    for k, v in parse_qsl(q, keep_blank_values=False):
        if len(v) < MIN_LEN or not re.search(r"[A-Za-z]", v) or v in seen:
            continue
        seen.add(v)
        yield k, v


# --------------------------------------------------------------------------------------
# Span map: which context covers each byte offset of the document
# --------------------------------------------------------------------------------------
@dataclass
class Span:
    start: int
    end: int
    kind: str                # "tag" | "text" | "rcdata" | "script" | "style" | "comment" | "other"
    tag: str
    raw: str = ""            # raw start-tag text for kind == "tag"
    script_type: str = ""


class _SpanParser(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=False)
        self.text = text
        self.line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
        self.spans: list[Span] = []
        self.stack_raw: str | None = None      # current rawtext/rcdata element
        self.script_type = ""

    def _off(self) -> int:
        line, col = self.getpos()
        return self.line_starts[line - 1] + col

    def _data_kind(self) -> str:
        if self.stack_raw in ("script",):
            return "script"
        if self.stack_raw == "style":
            return "style"
        if self.stack_raw in RCDATA:
            return "rcdata"
        return "text"

    def handle_starttag(self, tag, attrs):
        raw = self.get_starttag_text() or ""
        s = self._off()
        self.spans.append(Span(s, s + len(raw), "tag", tag, raw))
        if tag in RAWTEXT_SCRIPTISH or tag in RCDATA:
            self.stack_raw = tag
            if tag == "script":
                t = (dict(attrs).get("type") or "").strip().lower()
                self.script_type = t
            if tag in RCDATA:
                # html.parser does not treat title/textarea as RCDATA; we only label it
                pass

    handle_startendtag = handle_starttag

    def handle_endtag(self, tag):
        if tag == self.stack_raw:
            self.stack_raw = None
            self.script_type = ""

    def _data(self, data):
        s = self._off()
        kind = self._data_kind()
        self.spans.append(Span(s, s + len(data), kind, self.stack_raw or "",
                               script_type=self.script_type if kind == "script" else ""))

    handle_data = _data

    def handle_entityref(self, name):
        self._data(f"&{name};")

    def handle_charref(self, name):
        self._data(f"&#{name};")

    def handle_comment(self, data):
        s = self._off()
        self.spans.append(Span(s, s + len(data) + 7, "comment", ""))

    def handle_decl(self, decl):
        s = self._off()
        self.spans.append(Span(s, s + len(decl) + 3, "other", "doctype"))

    def unknown_decl(self, data):
        s = self._off()
        self.spans.append(Span(s, s + len(data) + 9, "other", "cdata"))


def build_spans(doc: str) -> list[Span]:
    p = _SpanParser(doc)
    try:
        p.feed(doc)
        p.close()
    except Exception:            # malformed HTML: keep whatever spans were recorded
        pass
    p.spans.sort(key=lambda s: s.start)
    return p.spans


# attribute tokenizer for one raw start tag: yields (name, quote, value_start, value_end)
_ATTR = re.compile(r"""([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?""")


def tag_attributes(raw: str):
    m = re.match(r"<\s*[^\s/>]+", raw)
    pos = m.end() if m else 0
    for a in _ATTR.finditer(raw, pos):
        name = a.group(1).lower()
        for gi, q in ((2, '"'), (3, "'"), (4, "")):
            if a.group(gi) is not None:
                yield name, q, a.start(gi), a.end(gi)
                break
        else:
            yield name, None, a.start(1), a.end(1)


def js_string_state(code: str, upto: int) -> str:
    """Return the JS string delimiter open at offset `upto` of `code`, or "" if in code.

    A small lexer: strings, template literals (no nesting into ${}), line and block
    comments. Regex literals are not modelled; they are rare around reflected values and
    the error only affects the in-string/in-code split, which we report as approximate.
    """
    i, state = 0, ""
    n = min(upto, len(code))
    while i < n:
        c = code[i]
        if state in ("'", '"', "`"):
            if c == "\\":
                i += 2
                continue
            if c == state:
                state = ""
        elif state == "//":
            if c == "\n":
                state = ""
        elif state == "/*":
            if code.startswith("*/", i):
                state = ""
                i += 2
                continue
        else:
            if c in ("'", '"', "`"):
                state = c
            elif code.startswith("//", i):
                state = "//"
                i += 2
                continue
            elif code.startswith("/*", i):
                state = "/*"
                i += 2
                continue
        i += 1
    if state in ("//", "/*"):
        return "comment"
    return state


class Classifier:
    """Contexts:

      html_text            text node in normal flow
      rcdata               inside <title> or <textarea>
      attr_url             URL-valued attribute (href, src, action, ...)
      attr_event_handler   on* attribute
      attr_style           style attribute
      attr_srcdoc          iframe srcdoc
      attr_meta_content    <meta content=...> (incl. refresh)
      attr_other           any other attribute value
      tag_name_or_attr_name  value appears where markup structure is (attribute name, tag name)
      script_js            inside a JavaScript <script>   (in_js_string tells string vs code)
      script_json          inside a JSON-typed <script>
      script_other         script with another type (templates etc.)
      style_block          inside <style>
      comment              inside an HTML comment
      other                doctype, CDATA, unmatched
    """

    def __init__(self, doc: str):
        self.doc = doc
        self.spans = build_spans(doc)
        self.starts = [s.start for s in self.spans]

    def span_at(self, off: int) -> int:
        """Index of the span covering `off`, or -1."""
        i = bisect_right(self.starts, off) - 1
        while i >= 0:
            s = self.spans[i]
            if s.start <= off < s.end:
                return i
            if s.end <= off and s.kind != "tag":
                return -1
            i -= 1
        return -1

    @staticmethod
    def _is_self_url(val: str, page_path: str) -> bool:
        """True if an attribute value is a link to the page itself (canonical, og:url, ...)."""
        try:
            sp = urlsplit(val.strip())
        except ValueError:
            return False
        return bool(sp.query) and sp.path.rstrip("/") == page_path.rstrip("/")

    def classify(self, off: int, length: int, page_path: str):
        idx = self.span_at(off)
        if idx < 0:
            return "other", "", "", "", False
        s = self.spans[idx]
        if s.kind == "tag":
            rel = off - s.start
            for name, q, vs, ve in tag_attributes(s.raw):
                if q is not None and vs <= rel < max(ve, vs + 1):
                    echo = self._is_self_url(html.unescape(s.raw[vs:ve]), page_path)
                    if name.startswith("on"):
                        ctx = "attr_event_handler"
                    elif name in URL_ATTRS:
                        ctx = "attr_url"
                    elif name == "style":
                        ctx = "attr_style"
                    elif name == "srcdoc":
                        ctx = "attr_srcdoc"
                    elif s.tag == "meta" and name == "content":
                        ctx = "attr_meta_content"
                    else:
                        ctx = "attr_other"
                    return ctx, f"{s.tag}@{name}", q, "", echo
            return "tag_name_or_attr_name", s.tag, "", "", False
        if s.kind == "script":
            t = s.script_type
            if t in JSON_TYPES:
                return "script_json", t, "", "", False
            if t in JS_TYPES:
                # lexer runs from the start of this script's first data span
                first = s
                i = idx
                while i > 0 and self.spans[i - 1].kind == "script":
                    i -= 1
                    first = self.spans[i]
                st = js_string_state(self.doc[first.start:s.end], off - first.start)
                return "script_js", t or "text/javascript", "", st, False
            return "script_other", t, "", "", False
        mapping = {"text": "html_text", "rcdata": "rcdata", "style": "style_block",
                   "comment": "comment", "other": "other"}
        return mapping.get(s.kind, "other"), s.tag, "", "", False


def analyse(url: str, doc: str, salt: str = "", max_per_value: int = 50) -> list[Occurrence]:
    """All reflections of the URL's query values in `doc`, one Occurrence each."""
    params = list(candidate_params(url))
    if not params:
        return []
    clf = Classifier(doc)
    page_path = urlsplit(url).path
    out: list[Occurrence] = []
    for name, v in params:
        has_special = any(c in SPECIAL for c in v)
        h = hashlib.sha256((salt + v).encode("utf-8", "replace")).hexdigest()[:16]
        found: dict[int, str] = {}
        # distinct encoded forms, raw first so an identity encoding is attributed to raw
        forms = []
        for enc, f in ENCODERS.items():
            try:
                fv = f(v)
            except Exception:
                continue
            if fv and all(fv != x for _, x in forms):
                forms.append((enc, fv))
        for enc, fv in forms:
            for m in re.finditer(re.escape(fv), doc):
                if m.start() in found:
                    continue
                found[m.start()] = enc
                if len(found) >= max_per_value:
                    break
        for off, enc in sorted(found.items()):
            ctx, detail, q, js, echo = clf.classify(off, len(v), page_path)
            out.append(Occurrence(
                param_hash=h, param_name=name[:64], value_len=len(v),
                value_has_special=has_special, value_classes=value_classes(v),
                encoding=enc, encoding_observable=has_special,
                context=ctx, detail=detail[:64], quote=q, in_js_string=js,
                self_url_echo=echo))
    return out


def to_rows(occs, **extra):
    return [{**asdict(o), **extra} for o in occs]
