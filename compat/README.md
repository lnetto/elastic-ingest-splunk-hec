# HEC compatibility with Splunk

`hec_compat.py` sends 69 edge-case requests to any HEC endpoint and records the status, the body, how many events
were stored and their time, host, source and sourcetype. `splunk-10.0.8.json` is what Splunk Enterprise 10.0.8
answered; the `time` rules below were also checked against Splunk 10.6.

```bash
python3 compat/hec_compat.py run --label plugin --url https://<es>:9200 --token $TOKEN --ack-token $TOKEN \
  --count es --es https://<es>:9200 --auth elastic:$PW --out plugin.json
python3 compat/hec_compat.py diff compat/splunk-10.0.8.json plugin.json
```

## As Splunk does

* A batch with a bad event: the events before it are indexed, and the response names the bad one
  (`invalid-event-number`). A sender doesn't resend after a 400. In a batch sent as one array, events are counted
  by element: `[a,b,{bad` and `[a,b]{bad` index a and b and name event 2.
* A number that isn't JSON (`01`, `1.`, `.5`, `00`) is code 6.
* `time` is digits with at most one decimal point, as a number or a string. An integer of more than 10 digits
  (leading zeros don't count) is seconds and a fraction: milliseconds (`1760000000123`), microseconds and nanoseconds
  are all `2025-10-09T08:53:20.123Z`. A decimal is taken as written, so `1760000000123.0` is the year 57742, which
  Elasticsearch rejects (the event goes to the failure store). A sign (`-0` too), an exponent in a string, spaces, or
  an empty string is code 15; `null`, `true`, an object or an array is code 6. `/raw?time=` follows the same rules.
* `{"event":{}}` is an event; `"event":null` and `fields` that isn't an object are code 6.
* `/ack` needs a channel (a GUID): code 10 without one, 11 for anything else.
* With `envelope: unwrap`, `?host=`, `?source=`, `?sourcetype=` and `?index=` are the defaults for events that
  don't set them.

## Where the plugin differs

* Acknowledgment is one setting for every sender, not per token: a request without a channel is indexed and
  answered without an `ackId` (Splunk: code 10 on a `useACK` token). `/ack` answers `true` for every id, on any
  node (Splunk: `false` for an id it never issued).
* It accepts what Splunk refuses: boolean events, nested `fields` values, any `index`, numbers as `host` /
  `source` / `sourcetype`, extra top-level keys, a lowercase `splunk` scheme, and a JSON number `time` with an
  exponent (`1.76e9`).
* `"time":".5"` is half a second after 1970 (Splunk: the arrival second, plus .5); a decimal time of 10^15 or more
  (`"1760000000123456.7"`) is code 15 (Splunk accepts it, as a date no index can hold).
* An array element without `event` (`[a,{"x":1},c]`): a is indexed and the plugin answers code 12 for event 1;
  Splunk indexes a too, but answers Success and drops c without saying.
* Elasticsearch answers before the plugin for `Authorization: Basic` (Splunk takes the token as the password),
  `Bearer`, `Content-Type: text/plain`, and the wrong HTTP method.
* `/raw` is one event per line. Splunk merges lines into events by the sourcetype's line-breaking and timestamp
  rules, and takes the time from the text.
* Without `host`, Splunk uses the request's `Host` header (the collector's address); the plugin uses the sender's.
