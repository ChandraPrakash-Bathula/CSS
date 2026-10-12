"""Hand-written pages with a known answer for every occurrence. Values are inert tokens."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reflect import analyse, js_string_state  # noqa: E402

URL = "https://example.test/search?q=zqxwvtoken&lang=en"


def ctxs(doc, url=URL):
    return [(o.context, o.quote, o.in_js_string, o.encoding) for o in analyse(url, doc)]


def test_text_node():
    assert ctxs("<p>Results for zqxwvtoken</p>") == [("html_text", "", "", "raw")]


def test_short_value_ignored():
    assert all(o.param_name != "lang" for o in analyse(URL, "<p>en en en</p>"))


def test_attribute_quoting():
    doc = '<input value="zqxwvtoken"><input value=\'zqxwvtoken\'><input value=zqxwvtoken>'
    assert [c[:2] for c in ctxs(doc)] == [("attr_other", '"'), ("attr_other", "'"), ("attr_other", "")]


def test_url_attr_and_self_echo():
    doc = '<link rel=canonical href="https://example.test/search?q=zqxwvtoken&amp;lang=en"><a href="/x?q=zqxwvtoken">'
    o = analyse(URL, doc)
    assert [x.context for x in o] == ["attr_url", "attr_url"]
    assert o[0].self_url_echo is True and o[1].self_url_echo is False


def test_event_style_meta():
    doc = '<div onclick="f(\'zqxwvtoken\')" style="x:zqxwvtoken"></div><meta name=d content="zqxwvtoken">'
    assert [c[0] for c in ctxs(doc)] == ["attr_event_handler", "attr_style", "attr_meta_content"]


def test_script_string_vs_code():
    doc = '<script>var a = "zqxwvtoken"; var b = zqxwvtoken; // zqxwvtoken\n</script>'
    assert [(c[0], c[2]) for c in ctxs(doc)] == [("script_js", '"'), ("script_js", ""), ("script_js", "comment")]


def test_script_json_and_template_literal():
    doc = '<script type="application/ld+json">{"u":"zqxwvtoken"}</script><script>x=`a ${1} zqxwvtoken`</script>'
    assert [(c[0], c[2]) for c in ctxs(doc)] == [("script_json", ""), ("script_js", "`")]


def test_title_style_comment():
    doc = "<title>zqxwvtoken</title><style>.zqxwvtoken{}</style><!-- zqxwvtoken -->"
    assert [c[0] for c in ctxs(doc)] == ["rcdata", "style_block", "comment"]


def test_encoding_observable_only_with_special_chars():
    url = "https://example.test/s?q=tom%26jerry%22show"
    o = analyse(url, "<p>tom&amp;jerry&quot;show</p>")
    assert len(o) == 1 and o[0].encoding == "html_escaped" and o[0].encoding_observable
    o = analyse(url, '<p>tom&jerry"show</p>')
    assert o[0].encoding == "raw"
    assert analyse(URL, "<p>zqxwvtoken</p>")[0].encoding_observable is False


def test_no_raw_value_stored():
    o = analyse(URL, "<p>zqxwvtoken</p>")[0]
    assert "zqxwvtoken" not in repr(o)


def test_js_lexer():
    assert js_string_state("a='x\\'y", 7) == "'"
    assert js_string_state("a='x'; b", 8) == ""
    assert js_string_state("/* 'x */ y", 9) == ""


def test_malformed_html_does_not_crash():
    analyse(URL, "<div <p zqxwvtoken <<< </script> &&& <!--")


def test_self_echo_with_extra_params_and_meta():
    url = "https://example.test/search?q=zqxwvtoken&page=2&sort=new"
    doc = ('<link rel=canonical href="https://example.test/search?q=zqxwvtoken">'
           '<meta property="og:url" content="/search?q=zqxwvtoken">'
           '<a href="/other?q=zqxwvtoken">')
    assert [o.self_url_echo for o in analyse(url, doc)] == [True, True, False]
