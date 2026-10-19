#!/usr/bin/env python3
"""HEC compatibility matrix: send the same edge-case requests to Splunk and to
the plugin, record HTTP status, body and how many events were stored, and diff.

  hec_compat.py run  --url http://127.0.0.1:8088 --token T --ack-token T2 \
                     --count splunk|es ... --out splunk.json
  hec_compat.py diff splunk.json plugin.json

Counting (how many events of each case were indexed) needs a search API:
  --count splunk --mgmt https://127.0.0.1:8089 --auth admin:pw
  --count es     --es http://127.0.0.1:9200 --auth elastic:pw
Every event carries a per-run marker, so runs don't see each other's data.
Standard library only.
"""
import argparse
import base64
import gzip
import http.client
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

CTX = ssl._create_unverified_context()
CHANNEL = str(uuid.uuid4())  # fresh per run: Splunk forgets an ack once it has been reported


def cases(m):
    """(name, path, headers, body, query, expected_events_if_success). `m(n)` makes marker text."""
    J = {"Content-Type": "application/json"}
    C = {"X-Splunk-Request-Channel": CHANNEL, "Content-Type": "application/json"}
    E = "/services/collector/event"
    R = "/services/collector/raw"
    ev = lambda n, **kw: json.dumps(dict({"event": m(n)}, **kw))
    out = [
        ("health", "/services/collector/health", {}, None, {}, 0),
        ("event_string", E, J, ev("a"), {}, 1),
        ("event_object", E, J, json.dumps({"event": {"msg": m("b"), "n": 1}}), {}, 1),
        ("event_number", E, J, json.dumps({"event": 42, "source": m("num")}), {}, 1),
        ("event_bool", E, J, json.dumps({"event": True, "source": m("bool")}), {}, 1),
        ("event_array", E, J, json.dumps({"event": [m("arr")]}), {}, 1),
        ("event_empty_object", E, J, json.dumps({"event": {}, "source": m("eo")}), {}, 1),
        ("event_empty_string", E, J, json.dumps({"event": "", "source": m("es")}), {}, 1),
        ("event_whitespace", E, J, json.dumps({"event": "   ", "source": m("ew")}), {}, 1),
        ("event_null", E, J, json.dumps({"event": None, "source": m("en")}), {}, 1),
        ("event_missing", E, J, json.dumps({"time": 1, "source": m("em")}), {}, 1),
        ("unknown_top_level_key", E, J, json.dumps({"event": m("uk"), "foo": 1}), {}, 1),
        ("batch_concat", E, J, ev("c1") + ev("c2") + ev("c3"), {}, 3),
        ("batch_newlines", E, J, ev("n1") + "\n" + ev("n2") + "\r\n" + ev("n3") + "\n", {}, 3),
        ("batch_json_array", E, J, json.dumps([{"event": m("j1")}, {"event": m("j2")}]), {}, 2),
        ("batch_second_missing_event", E, J, ev("p1") + json.dumps({"source": m("p2")}) + ev("p3"), {}, 3),
        ("batch_third_bad_json", E, J, ev("q1") + ev("q2") + '{"event": "x"', {}, 3),
        ("invalid_json", E, J, "{nope", {}, 1),
        ("trailing_garbage", E, J, ev("tg") + " garbage", {}, 1),
        ("empty_body", E, J, "", {}, 0),
        ("whitespace_body", E, J, "  \n ", {}, 0),
        ("time_int", E, J, ev("t1", time=1760000000), {}, 1),
        ("time_float", E, J, ev("t2", time=1760000000.123), {}, 1),
        ("time_string", E, J, ev("t3", time="1760000000.5"), {}, 1),
        ("time_millis", E, J, ev("t4", time=1760000000123), {}, 1),
        ("time_negative", E, J, ev("t5", time=-5), {}, 1),
        ("time_garbage", E, J, ev("t6", time="yesterday"), {}, 1),
        ("time_iso", E, J, ev("t7", time="2025-10-09T08:53:20Z"), {}, 1),
        ("fields_flat", E, J, ev("f1", fields={"env": "prod", "n": 3}), {}, 1),
        ("fields_array", E, J, ev("f2", fields={"tags": ["a", "b"]}), {}, 1),
        ("fields_nested_object", E, J, ev("f3", fields={"o": {"x": 1}}), {}, 1),
        ("fields_array_of_objects", E, J, ev("f4", fields={"o": [{"x": 1}]}), {}, 1),
        ("fields_not_object", E, J, ev("f5", fields="env=prod"), {}, 1),
        ("fields_null_value", E, J, ev("f6", fields={"k": None}), {}, 1),
        ("index_allowed", E, J, ev("i1", index="rea"), {}, 1),
        ("index_not_allowed", E, J, ev("i2", index="nosuchindex"), {}, 1),
        ("meta_numbers", E, J, json.dumps({"event": m("mn"), "host": 1, "source": 2, "sourcetype": 3}), {}, 1),
        ("event_query_params", E, J, ev("qp"), {"sourcetype": "qp:st", "host": "qphost"}, 1),
        ("text_plain_content_type", E, {"Content-Type": "text/plain"}, ev("ct"), {}, 1),
        ("no_content_type", E, {}, ev("nct"), {}, 1),
        ("gzip_body", E, dict(J, **{"Content-Encoding": "gzip"}), gzip.compress(ev("gz").encode()), {}, 1),
        ("path_bare", "/services/collector", J, ev("pb"), {}, 1),
        ("path_event_1_0", "/services/collector/event/1.0", J, ev("p10"), {}, 1),
        ("raw_no_channel", R, J, m("r0"), {}, 1),
        ("raw_with_channel", R, C, m("r1"), {}, 1),
        ("raw_multiline", R, C,
         f"2025-10-09 08:53:20 first {m('rm')}\n  continuation line\n2025-10-09 08:53:21 second {m('rm')}\n", {}, 2),
        ("raw_crlf_lines", R, C, f"{m('rc')} one\r\n{m('rc')} two\r\n", {}, 2),
        ("raw_query_meta", R, C, m("rq"),
         {"sourcetype": "rq:st", "host": "rqhost", "source": "rqsrc"}, 1),
        ("raw_channel_query_param", R, J, m("rcq"), {"channel": CHANNEL}, 1),
        ("raw_empty", R, C, "", {}, 0),
        ("raw_bad_channel", R, dict(J, **{"X-Splunk-Request-Channel": "not-a-guid"}), m("rbc"), {}, 1),
        ("get_event", E, {"_method": "GET"}, None, {}, 0),
    ]
    return out


AUTH_CASES = [  # (name, header builder) -- body is a single valid event
    ("auth_missing", lambda t: {}),
    ("auth_splunk_lowercase", lambda t: {"Authorization": f"splunk {t}"}),
    ("auth_bearer", lambda t: {"Authorization": f"Bearer {t}"}),
    ("auth_bad_token", lambda t: {"Authorization": "Splunk 00000000-0000-0000-0000-000000000000"}),
    ("auth_basic_token_as_password", lambda t: {"Authorization": "Basic " + base64.b64encode(f"x:{t}".encode()).decode()}),
    ("auth_basic_token_as_user", lambda t: {"Authorization": "Basic " + base64.b64encode(f"{t}:".encode()).decode()}),
    ("auth_query_token", None),
    ("auth_splunk_no_token", lambda t: {"Authorization": "Splunk"}),
]


def send(url, path, headers, body, query, token=None):
    """Exact headers (no implicit Content-Type), so 'no Content-Type' really sends none."""
    h = dict(headers)
    method = h.pop("_method", None)
    if token is not None and "Authorization" not in h:
        h["Authorization"] = f"Splunk {token}"
    q = ("?" + urllib.parse.urlencode(query)) if query else ""
    data = body.encode() if isinstance(body, str) else body
    u = urllib.parse.urlsplit(url)
    conn = (http.client.HTTPSConnection(u.hostname, u.port, context=CTX, timeout=30) if u.scheme == "https"
            else http.client.HTTPConnection(u.hostname, u.port, timeout=30))
    try:
        conn.request(method or ("POST" if data is not None else "GET"), u.path.rstrip("/") + path + q, body=data, headers=h)
        r = conn.getresponse()
        status, text = r.status, r.read().decode(errors="replace")
    finally:
        conn.close()
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = text[:300]
    return status, parsed


def run(a):
    run_id = uuid.uuid4().hex[:10]
    m = lambda n: f"hc{run_id}x{n}"
    res = {"target": a.label, "url": a.url, "run": run_id, "cases": {}}
    for name, path, headers, body, query, _ in cases(m):
        st, b = send(a.url, path, headers, body, query, a.token)
        text = gzip.decompress(body).decode() if isinstance(body, bytes) else (body or "")
        keys = sorted(set(re.findall(f"hc{run_id}x([a-z0-9]+)", text)))
        res["cases"][name] = {"status": st, "body": b, "markers": keys}
    for name, hb in AUTH_CASES:
        body = json.dumps({"event": m("auth")})
        J = {"Content-Type": "application/json"}
        if hb is None:
            st, b = send(a.url, "/services/collector/event", J, body, {"token": a.token})
        else:
            st, b = send(a.url, "/services/collector/event", dict(J, **hb(a.token)), body, {})
        res["cases"][name] = {"status": st, "body": b}
    if a.ack_token:
        H = {"X-Splunk-Request-Channel": CHANNEL, "Content-Type": "application/json"}
        ackc = {}
        ackc["ack_event_no_channel"] = send(a.url, "/services/collector/event", {"Content-Type": "application/json"}, json.dumps({"event": m("ak0")}), {}, a.ack_token)
        ackc["ack_event_with_channel"] = send(a.url, "/services/collector/event", H, json.dumps({"event": m("ak1")}), {}, a.ack_token)
        ackc["ack_event_second"] = send(a.url, "/services/collector/event", H, json.dumps({"event": m("ak2")}), {}, a.ack_token)
        other = str(uuid.uuid4())
        ackc["ack_event_other_channel"] = send(a.url, "/services/collector/event", {"X-Splunk-Request-Channel": other, "Content-Type": "application/json"},
                                               json.dumps({"event": m("ak3")}), {}, a.ack_token)
        ackc["ack_raw_with_channel"] = send(a.url, "/services/collector/raw", H, m("ak4"), {}, a.ack_token)
        time.sleep(a.ack_wait)
        ackc["ack_query_known_and_unknown"] = send(a.url, "/services/collector/ack", H,
                                                   json.dumps({"acks": [0, 1, 2, 99]}), {}, a.ack_token)
        ackc["ack_query_no_channel"] = send(a.url, "/services/collector/ack", {"Content-Type": "application/json"},
                                            json.dumps({"acks": [0]}), {}, a.ack_token)
        ackc["ack_query_bad_body"] = send(a.url, "/services/collector/ack", H, "{nope", {}, a.ack_token)
        ackc["ack_query_noack_token"] = send(a.url, "/services/collector/ack", H, json.dumps({"acks": [0]}), {}, a.token)
        for k, (st, b) in ackc.items():
            res["cases"][k] = {"status": st, "body": b}
    if a.count:
        time.sleep(a.settle)
        counts, stored = count_events(a, run_id)
        for c in res["cases"].values():
            if "markers" in c:
                c["indexed"] = {k: counts.get(k, 0) for k in c["markers"]}
                c["stored"] = {k: stored[k] for k in c["markers"] if k in stored}
    json.dump(res, open(a.out, "w"), indent=1, sort_keys=True)
    print(f"wrote {a.out}: {len(res['cases'])} cases, run {run_id}")


def count_events(a, run_id):
    """-> (marker -> number of stored events, marker -> metadata of the first one stored):
    time (epoch seconds), host, source, sourcetype, as each side stores them."""
    needle = f"hc{run_id}x"
    counts, stored = {}, {}
    if a.count == "splunk":
        auth = base64.b64encode(a.auth.encode()).decode()
        q = f'search index=* "{needle}*" OR source="{needle}*" | rex field=_raw "{needle}(?<k>[a-z0-9]+)" ' \
            f'| eval k=coalesce(k, replace(source, "{needle}", "")) ' \
            f'| stats count, first(_time) as t, first(host) as host, first(source) as source, ' \
            f'first(sourcetype) as sourcetype by k'
        data = urllib.parse.urlencode({"search": q, "output_mode": "json", "earliest_time": "0"}).encode()
        req = urllib.request.Request(a.mgmt + "/services/search/jobs/export", data=data, headers={"Authorization": "Basic " + auth})
        with urllib.request.urlopen(req, context=CTX) as r:
            for line in r:
                d = json.loads(line)
                res = d.get("result")
                if res:
                    counts[res["k"]] = int(res["count"])
                    stored[res["k"]] = {"time": float(res["t"]), "host": res.get("host"), "source": res.get("source"),
                                        "sourcetype": res.get("sourcetype")}
        return counts, stored
    auth = base64.b64encode(a.auth.encode()).decode()
    body = json.dumps({"size": 1000, "_source": ["message", "@timestamp", "splunk.*"],
                       "query": {"query_string": {"query": f"*{needle}*", "fields": ["message", "splunk.source"], "allow_leading_wildcard": True}}})
    req = urllib.request.Request(a.es + "/logs-*/_search", data=body.encode(),
                                 headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"})
    from datetime import datetime
    with urllib.request.urlopen(req, context=CTX) as r:
        for h in json.load(r)["hits"]["hits"]:
            src = h["_source"]
            text = json.dumps(src)
            sp = src.get("splunk", {})
            for k in set(re.findall(needle + r"([a-z0-9]+)", text)):
                counts[k] = counts.get(k, 0) + 1
                stored.setdefault(k, {"time": datetime.fromisoformat(src["@timestamp"].replace("Z", "+00:00")).timestamp(),
                                      "host": sp.get("host"), "source": sp.get("source"), "sourcetype": sp.get("sourcetype")})
    return counts, stored


def meta_diff(a, b, recv_tolerance=120):
    """Compare stored metadata; a time within the last hour on both sides means arrival time.
    Known difference, not reported: without a host, Splunk stores the request's Host header
    ("collector:8088") and the plugin the sender's address."""
    out = {}
    norm = lambda v: re.sub(r"hc[0-9a-f]{10}x", "hcRUNx", v) if isinstance(v, str) else v
    for k in set(a) & set(b):
        for f in ("host", "source", "sourcetype"):
            va, vb = norm(a[k].get(f)), norm(b[k].get(f))
            if f == "host" and isinstance(va, str) and re.fullmatch(r"[\w.-]+:\d+", va or ""):
                continue  # Splunk's default host
            if va != vb:
                out.setdefault(k, {})[f] = (va, vb)
        ta, tb = a[k]["time"], b[k]["time"]
        if abs(ta - tb) > 0.001 and not (abs(ta - time.time()) < 3600 and abs(tb - time.time()) < 3600):
            out.setdefault(k, {})["time"] = (ta, tb)
    return out


def diff(a):
    x, y = json.load(open(a.a)), json.load(open(a.b))
    same = 0
    for k in sorted(set(x["cases"]) | set(y["cases"])):
        cx, cy = x["cases"].get(k, {}), y["cases"].get(k, {})
        vx = (cx.get("status"), cx.get("body"), sorted(cx.get("indexed", {}).values()))
        vy = (cy.get("status"), cy.get("body"), sorted(cy.get("indexed", {}).values()))
        md = meta_diff(cx.get("stored", {}), cy.get("stored", {}))
        if vx == vy and not md:
            same += 1
            continue
        print(f"{k}")
        if md:
            print(f"   stored metadata differs: {md}")
        for t, c in ((x["target"], cx), (y["target"], cy)):
            print(f"   {t:>8}: {c.get('status')} {json.dumps(c.get('body'))[:120]}  indexed={c.get('indexed')}")
    print(f"\n{same} identical of {len(set(x['cases']) | set(y['cases']))}")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--url", required=True)
    r.add_argument("--token", required=True)
    r.add_argument("--ack-token")
    r.add_argument("--label", default="target")
    r.add_argument("--count", choices=["splunk", "es"])
    r.add_argument("--mgmt")
    r.add_argument("--es")
    r.add_argument("--auth")
    r.add_argument("--settle", type=float, default=8)
    r.add_argument("--ack-wait", type=float, default=5)
    r.add_argument("--out", required=True)
    d = sub.add_parser("diff")
    d.add_argument("a")
    d.add_argument("b")
    a = p.parse_args()
    run(a) if a.cmd == "run" else diff(a)


if __name__ == "__main__":
    main()
