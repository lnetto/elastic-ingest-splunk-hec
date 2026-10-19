package co.elastic.splunkhec;

import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.breaker.NoopCircuitBreaker;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.rest.RestStatus;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HecParserTests {

    @Test
    void batchedEventsConcatenatedNewlinesAndArrays() throws Exception {
        String concatenated = "{\"event\":\"a\",\"sourcetype\":\"st1\"}{\"event\":{\"k\":1},\"time\":1790900000.25,\"host\":\"h\"}";
        List<HecParser.HecEvent> e = HecParser.events(concatenated, Map.of(), false, n -> {});
        assertEquals(2, e.size());
        assertEquals("a", e.get(0).event());
        assertEquals("st1", e.get(0).sourcetype());
        assertEquals(Map.of("k", 1L), e.get(1).event());
        assertEquals(1790900000.25, e.get(1).time());
        assertEquals(3, HecParser.events("{\"event\":\"a\"}\n{\"event\":\"b\"}\r\n\n{\"event\":\"c\"}\n", Map.of(), false, n -> {}).size());
        assertEquals(2, HecParser.events("[{\"event\":\"a\"},{\"event\":\"b\"}]", Map.of(), false, n -> {}).size());
        HecParser.HecEvent f = HecParser.events("{\"event\":\"x\",\"time\":\"1790900000\",\"fields\":{\"env\":\"prod\",\"tags\":[\"a\",\"b\"]}}", Map.of(), false, n -> {}).get(0);
        assertEquals(1790900000.0, f.time());
        assertEquals(List.of("a", "b"), f.fields().get("tags"));
    }

    @Test
    void splunkErrorCodesWithEventNumbers() {
        HecParser.Rejected r = assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"event\":\"ok\"}{\"host\":\"no event\"}", Map.of(), false, n -> {}));
        assertEquals(12, r.outcome.code());
        assertEquals(1, r.eventNumber);
        r = assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"event\":\"ok\"}{\"event\":\"\"}", Map.of(), false, n -> {}));
        assertEquals(13, r.outcome.code());
        r = assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"event\":\"ok\"}{\"event\":\"x\"}{bad json", Map.of(), false, n -> {}));
        assertEquals(6, r.outcome.code());
        assertEquals(2, r.eventNumber);
        assertEquals(5, assertThrows(HecParser.Rejected.class, () -> HecParser.events("  \n", Map.of(), false, n -> {})).outcome.code());
        // the codes Splunk 10.0.8 answers (compat/splunk-10.0.8.json: fields_not_object, time_garbage)
        assertEquals(6, assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"event\":\"x\",\"fields\":\"nope\"}", Map.of(), false, n -> {})).outcome.code());
        assertEquals(15, assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"event\":\"x\",\"time\":\"soon\"}", Map.of(), false, n -> {})).outcome.code());
    }

    @Test
    void rawSplitsLinesAndTakesQueryMetadata() throws Exception {
        List<HecParser.HecEvent> e = HecParser.raw("line one\r\nline two\n\nline three", Map.of("sourcetype", "syslog", "host", "web1", "time", "1790900000"), n -> {});
        assertEquals(3, e.size());
        assertEquals("line two", e.get(1).event());
        assertEquals("syslog", e.get(1).sourcetype());
        assertEquals(1790900000.0, e.get(2).time());
    }

    @Test
    void goodEventsBeforeABadOneAreKept() {
        // Splunk indexes p1 and answers 12 for event 1 (compat/: batch_second_missing_event)
        HecParser.Rejected r = assertThrows(HecParser.Rejected.class,
            () -> HecParser.events("{\"event\":\"p1\"}{\"source\":\"p2\"}{\"event\":\"p3\"}", Map.of(), false, n -> {}));
        assertEquals(12, r.outcome.code());
        assertEquals(1, r.eventNumber);
        assertEquals(List.of("p1"), r.accepted.stream().map(HecParser.HecEvent::event).toList());
        // and q1, q2 when event 2 isn't JSON (batch_third_bad_json), also when the envelope is kept
        for (boolean keep : List.of(false, true)) {
            r = assertThrows(HecParser.Rejected.class,
                () -> HecParser.events("{\"event\":\"q1\"}{\"event\":\"q2\"}{\"event\": \"x\"", Map.of(), keep, n -> {}));
            assertEquals(6, r.outcome.code());
            assertEquals(2, r.eventNumber);
            assertEquals(2, r.accepted.size());
        }
        // nothing to keep when the first one is bad
        assertTrue(assertThrows(HecParser.Rejected.class, () -> HecParser.events("{nope", Map.of(), false, n -> {})).accepted.isEmpty());
    }

    @Test
    void eventValuesAsSplunkJudgesThem() throws Exception {
        assertEquals(Map.of(), HecParser.events("{\"event\":{}}", Map.of(), false, n -> {}).get(0).event());  // Splunk: Success
        assertEquals(6, assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"event\":null}", Map.of(), false, n -> {})).outcome.code());
        assertEquals(12, assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"time\":1}", Map.of(), false, n -> {})).outcome.code());
        assertEquals(13, assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"event\":\"  \"}", Map.of(), false, n -> {})).outcome.code());
    }

    /** What Splunk 10.6's HEC input made of each "time" (2026-10-19, read back as _time through a heavy forwarder). */
    @Test
    void timeAsSplunkReadsIt() throws Exception {
        Object[][] cases = {
            { "1760000000", 1760000000.0 }, { "1760000000.123", 1760000000.123 }, { "\"1760000000.5\"", 1760000000.5 },
            // an integer of more than 10 digits is seconds and a fraction, whatever its length
            { "17600000001", 1760000000.1 }, { "176000000012", 1760000000.12 }, { "1760000000123", 1760000000.123 },
            { "1760000000123456", 1760000000.123456 }, { "1760000000123456789", 1760000000.123456789 },
            { "17600000001234567890", 1760000000.123456789 }, { "\"1760000000123\"", 1760000000.123 },
            { "\"1760000000123456\"", 1760000000.123456 },
            // leading zeros don't count; a decimal point, even a trailing one, means seconds as written
            { "\"01760000000\"", 1760000000.0 }, { "\"001760000000123\"", 1760000000.123 }, { "\"1760000000.\"", 1760000000.0 },
            { "\"1760000000.123456789\"", 1760000000.123456789 }, { "1760000000.123456789", 1760000000.123456789 },
            { "1760000000123.0", 1760000000123.0 }, { "\"1760000000123.\"", 1760000000123.0 },
            { "176000000", 176000000.0 }, { "0", 0.0 }, { "0.5", 0.5 }, { "9999999999", 9999999999.0 },
            // Splunk: code 15
            { "-5", 15 }, { "-1760000000123", 15 }, { "-0.0", 15 }, { "\"-0\"", 15 }, { "\"+1760000000\"", 15 },
            { "\" 1760000000 \"", 15 }, { "\"1760000000 \"", 15 }, { "\"\"", 15 }, { "\" \"", 15 }, { "\"1760000000f\"", 15 },
            { "\"0x10\"", 15 }, { "\"1e9\"", 15 }, { "\"1.76e9\"", 15 }, { "\"NaN\"", 15 }, { "\"2025-10-09T08:53:20Z\"", 15 },
            { "\"yesterday\"", 15 }, { "1e300", 15 },
            // Splunk: code 6
            { "null", 6 }, { "true", 6 }, { "{}", 6 }, { "[]", 6 },
            // where the plugin differs: Splunk takes ".5" as the arrival second plus .5, accepts "1.76e9" as a number
            // and stores 1760000000123456.7 as a date Elasticsearch can't hold
            { "\".5\"", 0.5 }, { "1.76e9", 1.76e9 }, { "\"1760000000123456.7\"", 15 },
        };
        for (Object[] c : cases) {
            String body = "{\"event\":\"x\",\"time\":" + c[0] + "}";
            if (c[1] instanceof Double want) {
                assertEquals(want, HecParser.events(body, Map.of(), false, n -> {}).get(0).time(), 1e-6, String.valueOf(c[0]));
                HecParser.events(body, Map.of(), true, n -> {});  // the envelope kept: checked the same way
            } else {
                for (boolean keep : List.of(false, true)) {
                    HecParser.Rejected r = assertThrows(HecParser.Rejected.class, () -> HecParser.events(body, Map.of(), keep, n -> {}),
                        String.valueOf(c[0]));
                    assertEquals(c[1], r.outcome.code(), String.valueOf(c[0]));
                    assertEquals(0, r.eventNumber);
                }
            }
        }
        // a missing time is no time: the arrival time is used
        assertNull(HecParser.events("{\"event\":\"x\"}", Map.of(), false, n -> {}).get(0).time());
        // /raw?time= by the same rules; Splunk answers 15 with event number 0
        assertEquals(1760000000.123, HecParser.raw("x", Map.of("time", "1760000000123"), n -> {}).get(0).time(), 1e-6);
        for (String t : List.of("-5", "abc", "", "1760000000 ", "NaN")) {
            HecParser.Rejected r = assertThrows(HecParser.Rejected.class, () -> HecParser.raw("x", Map.of("time", t), n -> {}), t);
            assertEquals(15, r.outcome.code(), t);
            assertEquals(0, r.eventNumber, t);
        }
    }

    /** What Splunk 10.6 answered for each (2026-10-19), and which events it indexed. */
    @Test
    void jsonAndBatchEdgesAsSplunkAnswers() throws Exception {
        // numbers that aren't JSON are invalid data (6); -0 is a negative time (15)
        for (String t : List.of("01760000000123", "1760000000.", "1.e3", "00", ".5", "-00", "-", "1e", "1.5e+")) {
            String body = "{\"event\":\"x\",\"time\":" + t + "}";
            assertEquals(6, assertThrows(HecParser.Rejected.class, () -> HecParser.events(body, Map.of(), false, n -> {}), t).outcome.code(), t);
        }
        // Splunk answers 15 for a JSON -0; the plugin reads it as 0 (keeping -0 apart would change it in every event)
        assertEquals(0.0, HecParser.events("{\"event\":\"x\",\"time\":-0}", Map.of(), false, n -> {}).get(0).time());
        assertEquals(15, assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"event\":\"x\",\"time\":1e300}", Map.of(), false, n -> {}))
            .outcome.code());
        assertEquals(0L, Json.parse("0"));
        assertEquals(-12L, Json.parse("-12"));
        assertEquals(1.5e9, Json.parse("1.5E+9"));
        assertEquals("12345678901234567890", Json.parse("12345678901234567890"));
        // a bad element in an array batch: the elements before it are indexed, numbered as elements
        for (boolean keep : List.of(false, true)) {
            HecParser.Rejected r = assertThrows(HecParser.Rejected.class,
                () -> HecParser.events("[{\"event\":\"a1\"},{\"event\":\"a2\"},{\"event\":]", Map.of(), keep, n -> {}));
            assertEquals(List.of(6, 2, 2), List.of(r.outcome.code(), r.eventNumber, r.accepted.size()), "keep=" + keep);
            r = assertThrows(HecParser.Rejected.class,
                () -> HecParser.events("[{\"event\":\"c1\"},{\"event\":\"c2\"}]{bad", Map.of(), keep, n -> {}));
            assertEquals(List.of(6, 2, 2), List.of(r.outcome.code(), r.eventNumber, r.accepted.size()), "keep=" + keep);
            if (keep) {
                assertEquals("{\"event\":\"c2\"}", r.accepted.get(1).event());
            }
            // Splunk answers Success here and drops b3 silently; the plugin names the bad event (b1 indexed either way)
            r = assertThrows(HecParser.Rejected.class,
                () -> HecParser.events("[{\"event\":\"b1\"},{\"nope\":1},{\"event\":\"b3\"}]", Map.of(), keep, n -> {}));
            assertEquals(List.of(12, 1, 1), List.of(r.outcome.code(), r.eventNumber, r.accepted.size()), "keep=" + keep);
        }
        // arrays anywhere in a batch stand for their elements, as in Splunk (all Success, every event indexed)
        for (boolean keep : List.of(false, true)) {
            for (String body : List.of("[{\"event\":\"d1\"},{\"event\":\"d2\"}]{\"event\":\"d3\"}", "{\"event\":\"d1\"}[{\"event\":\"d2\"},{\"event\":\"d3\"}]",
                "[{\"event\":\"d1\"}][{\"event\":\"d2\"}]\n{\"event\":\"d3\"}")) {
                List<HecParser.HecEvent> e = HecParser.events(body, Map.of(), keep, n -> {});
                assertEquals(keep ? List.of("{\"event\":\"d1\"}", "{\"event\":\"d2\"}", "{\"event\":\"d3\"}") : List.of("d1", "d2", "d3"),
                    e.stream().map(HecParser.HecEvent::event).toList(), body);
            }
            HecParser.Rejected r = assertThrows(HecParser.Rejected.class,
                () -> HecParser.events("{\"event\":\"x1\"}[{\"event\":\"x2\"},{\"event\":]", Map.of(), keep, n -> {}));
            assertEquals(List.of(6, 2, 2), List.of(r.outcome.code(), r.eventNumber, r.accepted.size()));
        }
        // a run of digits too long for a long stays text, quickly
        String digits = "1".repeat(25);
        assertEquals(digits, Json.parse(digits));
        // the kept events are reserved on the breaker, as on success
        AtomicLong reserved = new AtomicLong();
        assertThrows(HecParser.Rejected.class, () -> HecParser.events("{\"event\":\"" + "x".repeat(10_000) + "\"}{bad", Map.of(), true, reserved::addAndGet));
        assertTrue(reserved.get() >= 10_000, "reserved " + reserved.get());
    }

    @Test
    void dataChannelsAreGuids() {
        String g = "2c3c9d2a-7a8e-4a51-9d5b-6c1b7d3e9f10";
        assertEquals(g, HecService.channel(g));
        assertEquals(g.toUpperCase(java.util.Locale.ROOT), HecService.channel(g.toUpperCase(java.util.Locale.ROOT)));
        for (String bad : java.util.Arrays.asList(null, "", "ch1", "{" + g + "}", g + "x", g.replace("-", ""))) {
            assertNull(HecService.channel(bad), String.valueOf(bad));
        }
    }

    @Test
    void queryStringGivesDefaultsWhenUnwrapping() throws Exception {
        Map<String, String> q = Map.of("host", "qphost", "sourcetype", "qp:st", "source", "qpsrc", "index", "qpidx");
        HecParser.HecEvent e = HecParser.events("{\"event\":\"a\"}", q, false, n -> {}).get(0);
        assertEquals(List.of("qphost", "qp:st", "qpsrc", "qpidx"), List.of(e.host(), e.sourcetype(), e.source(), e.index()));
        e = HecParser.events("{\"event\":\"a\",\"host\":\"own\"}", q, false, n -> {}).get(0);
        assertEquals("own", e.host());
    }

    @Test
    void gzipBodies() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write("{\"event\":\"zipped\"}".getBytes(StandardCharsets.UTF_8));
        }
        assertEquals("zipped", HecParser.events(HecParser.text(new BytesArray(out.toByteArray()), n -> {}), Map.of(), false, n -> {}).get(0).event());
    }

    @Test
    void gzipBombIsRefused() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            byte[] chunk = new byte[1 << 20];
            for (int i = 0; i <= HecParser.MAX_INFLATED / chunk.length; i++) {
                gz.write(chunk);
            }
        }
        HecParser.Rejected r = assertThrows(HecParser.Rejected.class, () -> HecParser.text(new BytesArray(out.toByteArray()), n -> {}));
        assertEquals(HecService.INVALID_FORMAT, r.outcome);
    }

    @Test
    void tokensFromHeaderAndQueryString() throws Exception {
        HecService svc = new HecService(null, "n1", false);
        String token = "11111111-2222-3333-4444-555555555555";
        svc.tokens.set(List.of("app-team=" + HecService.sha256(token)));
        assertEquals("app-team", svc.authenticate("Splunk " + token, null).name());
        assertEquals(16, assertThrows(HecParser.Rejected.class, () -> svc.authenticate(null, token)).outcome.code());
        svc.setQueryStringAuth(true);
        assertEquals("app-team", svc.authenticate(null, token).name());
        assertEquals(2, assertThrows(HecParser.Rejected.class, () -> svc.authenticate(null, null)).outcome.code());
        assertEquals(4, assertThrows(HecParser.Rejected.class, () -> svc.authenticate("Splunk nope", null)).outcome.code());
        assertEquals(3, assertThrows(HecParser.Rejected.class, () -> svc.authenticate("Bearer x", null)).outcome.code());
        assertEquals(3, assertThrows(HecParser.Rejected.class, () -> svc.authenticate("Splunk", null)).outcome.code());
    }

    @Test
    @SuppressWarnings("unchecked")
    void metricEventsBecomeOneDocumentPerMeasure() throws Exception {
        HecIndexer.Request req = new HecIndexer.Request("r", 0, "n", "1.2.3.4", "1.2.3.4", null, "event", null, null, new HecService.Caller("sha", "t"));
        HecParser.HecEvent multi = HecParser.events("{\"event\":\"metric\",\"fields\":{\"metric_name:system.cpu.load_average.15m\":2.71,"
            + "\"metric_name:system.cpu.load_average.1m\":\"1.5\",\"metric_type\":\"Gauge\",\"region\":\"us-east\"}}", Map.of(), false, n -> {}).get(0);
        List<Map<String, Object>> docs = HecIndexer.toSources(multi, req, false);
        assertEquals(2, docs.size());
        Map<String, Object> m = (Map<String, Object>) docs.get(0).get("metric");
        assertEquals("system.cpu.load_average.15m", m.get("name"));
        assertEquals(2.71, m.get("value"));
        assertEquals("Gauge", m.get("type"));
        assertEquals(1.5, ((Map<String, Object>) docs.get(1).get("metric")).get("value"));
        assertEquals(Map.of("region", "us-east"), ((Map<String, Object>) docs.get(0).get("splunk")).get("fields"));
        HecParser.HecEvent single = HecParser.events("{\"event\":\"metric\",\"fields\":{\"metric_name\":\"cpu.idle\",\"_value\":95.5}}", Map.of(), false, n -> {}).get(0);
        assertEquals("cpu.idle", ((Map<String, Object>) HecIndexer.toSources(single, req, false).get(0).get("metric")).get("name"));
        assertEquals(1, HecIndexer.toSources(HecParser.events("{\"event\":\"not a metric\"}", Map.of(), false, n -> {}).get(0), req, false).size());
    }

    @Test
    void hostileInputIsRejectedNotFatal() throws Exception {
        // 200,000 nested arrays used to overflow the stack, which stops the Elasticsearch node
        String deep = "{\"event\":" + "[".repeat(200_000) + "]".repeat(200_000) + "}";
        assertEquals(6, assertThrows(HecParser.Rejected.class, () -> HecParser.events(deep, Map.of(), false, n -> {})).outcome.code());
        String ok = "{\"event\":" + "[".repeat(Json.MAX_DEPTH - 1) + "]".repeat(Json.MAX_DEPTH - 1) + "}";
        assertEquals(1, HecParser.events(ok, Map.of(), false, n -> {}).size());
        assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(5000)));
        // times that can't be dates: a 400 with the event number (Splunk's 15), not a 500 or 1970
        for (String t : List.of("\"NaN\"", "\"Infinity\"", "\"-Infinity\"", "1e300")) {
            HecParser.Rejected r = assertThrows(HecParser.Rejected.class,
                () -> HecParser.events("{\"event\":\"ok\"}{\"event\":\"x\",\"time\":" + t + "}", Map.of(), false, n -> {}));
            assertEquals(15, r.outcome.code());
            assertEquals(1, r.eventNumber);
        }
        assertEquals(15, assertThrows(HecParser.Rejected.class, () -> HecParser.raw("x", Map.of("time", "NaN"), n -> {})).outcome.code());
        // a target no event can be written to is refused when it is set, not discovered as lost events
        for (String bad : List.of("Bad-Target", "bad target", "", "logs-splunk.{nope}-default", "_x", "a/b")) {
            assertThrows(IllegalArgumentException.class, () -> HecSettings.validateTarget(bad), bad);
        }
        HecSettings.validateTarget("logs-splunk.{sourcetype}-default");
        HecSettings.validateTarget("logs-myapp-default");
        HecSettings.validateTarget("splunk-{index}");
        // a long sourcetype must still make a valid data stream name
        assertEquals(HecIndexer.MAX_NAME_PART, HecIndexer.sanitize("a".repeat(300)).length());
    }

    @Test
    void responseJsonMatchesSplunk() {
        assertEquals("{\"text\":\"Success\",\"code\":0}", HecService.SUCCESS.json(Map.of()));
        assertEquals("{\"text\":\"Invalid data format\",\"code\":6,\"invalid-event-number\":2}",
            HecService.INVALID_FORMAT.json(Map.of("invalid-event-number", 2)));
        assertThrows(NumberFormatException.class, () -> HecParser.epochSeconds(""));  // Splunk: code 15
    }

    /** A breaker with a fixed limit, like Elasticsearch's request breaker. */
    static final class LimitedBreaker extends NoopCircuitBreaker {
        final long limit;
        final AtomicLong used = new AtomicLong();

        LimitedBreaker(long limit) {
            super(CircuitBreaker.REQUEST);
            this.limit = limit;
        }

        @Override
        public void addEstimateBytesAndMaybeBreak(long bytes, String label) {
            if (used.addAndGet(bytes) > limit) {
                used.addAndGet(-bytes);
                throw new IllegalStateException("over limit");  // stands in for CircuitBreakingException, which needs a node to load
            }
        }

        @Override
        public void addWithoutBreaking(long bytes) {
            used.addAndGet(bytes);
        }
    }

    @Test
    void inflatingReservesEveryByteAndGivesItBack() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(new byte[3 << 20]);
        }
        BytesArray body = new BytesArray(out.toByteArray());
        LimitedBreaker roomy = new LimitedBreaker(Long.MAX_VALUE);
        AtomicLong shared = new AtomicLong();
        try (HecRestHandler.Reservation r = new HecRestHandler.Reservation(roomy, Long.MAX_VALUE, shared)) {
            assertEquals(3 << 20, HecParser.text(body, r::add).length());
            assertEquals((3L << 20) * HecRestHandler.Reservation.FACTOR, roomy.used.get());
        }
        assertEquals(0, roomy.used.get());
        assertEquals(0, shared.get());

        // the breaker trips part way through inflating: nothing more is kept, and what was reserved is returned
        LimitedBreaker tight = new LimitedBreaker(1 << 20);
        HecRestHandler.Reservation r = new HecRestHandler.Reservation(tight, Long.MAX_VALUE, shared);
        assertThrows(IllegalStateException.class, () -> HecParser.text(body, r::add));
        r.close();
        r.close();
        assertEquals(0, tight.used.get());
        assertEquals(0, shared.get());
    }

    @Test
    void sharedBudgetAdmitsOneBigBatchButNotTwo() {
        AtomicLong shared = new AtomicLong();
        LimitedBreaker breaker = new LimitedBreaker(Long.MAX_VALUE);
        long budget = 100;
        HecRestHandler.Reservation first = new HecRestHandler.Reservation(breaker, budget, shared);
        first.add(50);  // 200 > budget, but nothing else is held: let it in
        first.add(10);  // still the only one
        HecRestHandler.Reservation second = new HecRestHandler.Reservation(breaker, budget, shared);
        assertThrows(HecRestHandler.Busy.class, () -> second.add(1));
        assertEquals(240, shared.get());
        first.close();
        second.add(20);  // 80, within budget
        HecRestHandler.Reservation third = new HecRestHandler.Reservation(breaker, budget, shared);
        third.add(5);    // 100, still within
        assertThrows(HecRestHandler.Busy.class, () -> third.add(1));
        second.close();
        third.close();
        assertEquals(0, shared.get());
        assertEquals(0, breaker.used.get());
    }

    @Test
    void clusterFailuresAreRetriedEventFailuresAreNot() {
        for (RestStatus st : List.of(RestStatus.TOO_MANY_REQUESTS, RestStatus.SERVICE_UNAVAILABLE, RestStatus.UNAUTHORIZED,
            RestStatus.FORBIDDEN, RestStatus.NOT_FOUND, RestStatus.INTERNAL_SERVER_ERROR)) {
            assertTrue(HecIndexer.retryable(st), st.toString());
        }
        for (RestStatus st : List.of(RestStatus.BAD_REQUEST, RestStatus.CONFLICT)) {
            assertFalse(HecIndexer.retryable(st), st.toString());
        }
    }

    @Test
    void numbersStayFastAndExact() throws Exception {
        assertEquals(42L, Json.parse("42"));
        assertEquals(-9223372036854775808L, Json.parse("-9223372036854775808"));
        assertEquals("9223372036854775808", Json.parse("9223372036854775808"));   // beyond a long: kept as text
        assertEquals(1.5, Json.parse("1.5"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("-"));
        // a megabyte of digits: BigInteger took seconds on this
        long t = System.nanoTime();
        assertEquals(1 << 20, ((String) Json.parse("1".repeat(1 << 20))).length());
        assertTrue(System.nanoTime() - t < 1_000_000_000L, "a long number should parse in linear time");
    }

    @Test
    void parsedValuesAreReservedNotJustTheText() throws Exception {
        // tiny events cost far more heap than their bytes: each value is reserved as it is made
        String body = "{\"event\":\"a\"}".repeat(10_000);
        AtomicLong reserved = new AtomicLong();
        assertEquals(10_000, HecParser.events(body, Map.of(), false, reserved::addAndGet).size());
        assertEquals(20_000L * Json.VALUE_COST, reserved.get());   // an object and a string per event

        AtomicLong rawReserved = new AtomicLong();
        List<HecParser.HecEvent> lines = HecParser.raw("a\r\nb\n\n  \nc", Map.of("sourcetype", "s"), rawReserved::addAndGet);
        assertEquals(List.of("a", "b", "c"), lines.stream().map(HecParser.HecEvent::event).toList());
        assertEquals(3L * Json.VALUE_COST, rawReserved.get());

        // the reservation refuses part way: parsing stops there
        LimitedBreaker tight = new LimitedBreaker(1 << 20);
        try (HecRestHandler.Reservation r = new HecRestHandler.Reservation(tight, Long.MAX_VALUE, new AtomicLong())) {
            assertThrows(IllegalStateException.class, () -> HecParser.events(body.repeat(10), Map.of(), false, r::add));
        }
        assertEquals(0, tight.used.get());
        // no fields: no map per event
        assertTrue(HecParser.events("{\"event\":\"a\"}", Map.of(), false, n -> {}).get(0).fields().isEmpty());
    }

    @Test
    void senderAddressIsTheEntryTheProxyAdded() {
        assertEquals("203.0.113.9", HecRestHandler.clientAddress("1.2.3.4, 203.0.113.9", "10.0.0.1"));
        assertEquals("203.0.113.9", HecRestHandler.clientAddress("203.0.113.9:5555", "10.0.0.1"));
        assertEquals("2001:db8::1", HecRestHandler.clientAddress("[2001:db8::1]:443", "10.0.0.1"));
        assertEquals("10.0.0.1", HecRestHandler.clientAddress("1.2.3.4, unknown", "10.0.0.1"));
        assertEquals("10.0.0.1", HecRestHandler.clientAddress(null, "10.0.0.1"));
        assertNull(HecRestHandler.clientAddress(null, null));
    }

    @Test
    @SuppressWarnings("unchecked")
    void documentHasTheExpectedFields() throws Exception {
        HecIndexer.Request req = new HecIndexer.Request("r", 0, "n", "203.0.113.9", "10.0.0.1", "1.2.3.4, 203.0.113.9", "event",
            "ch1", "curl/8", new HecService.Caller("sha", "t"));
        Map<String, Object> d = HecIndexer.toSources(HecParser.events("{\"event\":{\"user\":\"ann\"},\"sourcetype\":\"st\"}", Map.of(), false, n -> {}).get(0), req, false).get(0);
        assertEquals("{\"user\":\"ann\"}", d.get("message"));
        assertEquals(Map.of("forwarded_ip", "203.0.113.9"), d.get("network"));
        Map<String, Object> splunk = (Map<String, Object>) d.get("splunk");
        assertNull(splunk.get("event"));           // the text only: nothing parsed out of it
        assertEquals("ch1", splunk.get("channel"));
        assertEquals("203.0.113.9", splunk.get("host"));
        Map<String, Object> r = (Map<String, Object>) splunk.get("request");
        assertEquals("10.0.0.1", r.get("remote_address"));
        assertEquals("1.2.3.4, 203.0.113.9", r.get("x_forwarded_for"));
        assertEquals("n", r.get("node"));
        assertEquals(Map.of("endpoint", "event"), splunk.get("hec"));
    }

    @Test
    void keptEnvelopeIsTheEventAsSent() throws Exception {
        String a = "{\"event\": {\"user\":\"ann\"}, \"time\": 1790900000.5,\"tags{}\":\"t1\",\"tags{}\":\"t2\"}";
        String b = "{\"event\":\"plain\",\"sourcetype\":\"own\"}";
        Map<String, String> params = Map.of("sourcetype", "q", "index", "main");
        List<HecParser.HecEvent> e = HecParser.events(a + "\n" + b, params, true, n -> {});
        assertEquals(List.of(a, b), e.stream().map(HecParser.HecEvent::event).toList());
        assertNull(e.get(0).time());
        assertEquals("q", e.get(1).sourcetype());   // the query string's, not the event's: a pipeline unwraps it
        assertEquals("main", e.get(1).index());
        assertTrue(e.get(0).fields().isEmpty());
        // a batch sent as one array: each element is an event
        assertEquals(List.of(a, b), HecParser.events("[ " + a + " ,\n" + b + "]", Map.of(), true, n -> {}).stream()
            .map(HecParser.HecEvent::event).toList());
        // checked exactly as when unwrapped
        assertEquals(12, assertThrows(HecParser.Rejected.class, () -> HecParser.events(b + "{\"host\":\"x\"}", Map.of(), true, n -> {}))
            .outcome.code());
        assertEquals(6, assertThrows(HecParser.Rejected.class, () -> HecParser.events(b + "{bad", Map.of(), true, n -> {})).outcome.code());
        // the kept text is reserved too
        AtomicLong unwrapped = new AtomicLong(), kept = new AtomicLong();
        HecParser.events(a + b, Map.of(), false, unwrapped::addAndGet);
        HecParser.events(a + b, Map.of(), true, kept::addAndGet);
        assertEquals(unwrapped.get() + a.length() + b.length(), kept.get());
        // a metric envelope is one document, its text
        HecIndexer.Request req = new HecIndexer.Request("r", 0, "n", "1.2.3.4", "1.2.3.4", null, "event", null, null, new HecService.Caller("sha", "t"));
        String metric = "{\"event\":\"metric\",\"fields\":{\"metric_name\":\"cpu\",\"_value\":1}}";
        List<Map<String, Object>> docs = HecIndexer.toSources(HecParser.events(metric, Map.of(), true, n -> {}).get(0), req, false);
        assertEquals(1, docs.size());
        assertEquals(metric, docs.get(0).get("message"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void minimalMetadataLeavesOutTheRequest() {
        HecIndexer.Request req = new HecIndexer.Request("r", 0, "n", "203.0.113.9", "10.0.0.1", "203.0.113.9", "event",
            "ch1", "curl/8", new HecService.Caller("sha", "t"));
        HecParser.HecEvent e = new HecParser.HecEvent("{\"event\":\"x\"}", null, null, null, "st", "main", Map.of());
        Map<String, Object> d = HecIndexer.toSource(e, req, true);
        assertEquals(java.util.Set.of("@timestamp", "message", "host", "splunk", "agent", "event"), d.keySet());
        assertEquals(Map.of("module", "splunk_hec"), d.get("event"));
        assertEquals(Map.of("type", "curl", "version", "8"), d.get("agent"));
        Map<String, Object> splunk = (Map<String, Object>) d.get("splunk");
        assertEquals(java.util.Set.of("host", "source", "sourcetype", "index", "token_name", "channel", "hec"), splunk.keySet());
        assertEquals(Map.of("endpoint", "event"), splunk.get("hec"));
        Map<String, Object> full = HecIndexer.toSource(e, req, false);
        assertTrue(full.keySet().containsAll(java.util.Set.of("network", "user_agent", "event")));
        assertEquals("splunk_hec", ((Map<String, Object>) full.get("event")).get("module"));
        assertEquals(Map.of("original", "curl/8"), full.get("user_agent"));
    }

    @Test
    void agentIsTheSenderFromItsUserAgent() {
        assertEquals(Map.of("type", "Python-urllib", "version", "3.12"), HecIndexer.agent("Python-urllib/3.12"));
        assertEquals(Map.of("type", "Fluent-Bit", "version", "3.2.1"), HecIndexer.agent("Fluent-Bit/3.2.1"));
        assertEquals(Map.of("type", "OpenTelemetry Collector Contrib", "version", "0.120.0"),
            HecIndexer.agent("OpenTelemetry Collector Contrib/0.120.0 (linux/amd64)"));
        assertEquals(Map.of("type", "curl", "version", "8.5.0"), HecIndexer.agent("curl/8.5.0"));
        assertEquals(Map.of("type", "Mozilla", "version", "5.0"), HecIndexer.agent("Mozilla/5.0 (X11; Linux x86_64)"));
        assertEquals(Map.of("type", "myscript"), HecIndexer.agent("myscript (build 7)"));
        assertNull(HecIndexer.agent(null));
        assertNull(HecIndexer.agent("  "));
        assertNull(HecIndexer.agent("/weird"));
        assertNull(HecIndexer.agent(" /1.0"));
        assertEquals(Map.of("type", "tool"), HecIndexer.agent("tool/"));
    }

    @Test
    void noUserAgentNoAgent() {
        HecIndexer.Request req = new HecIndexer.Request("r", 0, "n", null, null, null, "event", null, null, new HecService.Caller("sha", "t"));
        HecParser.HecEvent e = new HecParser.HecEvent("x", null, null, null, "st", null, Map.of());
        for (boolean minimal : new boolean[] { true, false }) {
            Map<String, Object> d = HecIndexer.toSource(e, req, minimal);
            assertFalse(d.containsKey("agent"));
            assertFalse(d.containsKey("user_agent"));
        }
    }

    @Test
    void envelopeAndMetadataSettings() {
        org.elasticsearch.common.settings.Settings none = org.elasticsearch.common.settings.Settings.EMPTY;
        assertEquals("keep", HecSettings.ENVELOPE.get(none));
        assertEquals("minimal", HecSettings.METADATA.get(none));
        assertEquals("unwrap", HecSettings.ENVELOPE.get(org.elasticsearch.common.settings.Settings.builder().put("splunk_hec.envelope", "unwrap").build()));
        assertThrows(IllegalArgumentException.class,
            () -> HecSettings.METADATA.get(org.elasticsearch.common.settings.Settings.builder().put("splunk_hec.metadata", "none").build()));
    }

    @Test
    void defaultTargetIsOneStream() {
        assertEquals("logs-splunk.hec-default", HecSettings.TARGET.getDefault(org.elasticsearch.common.settings.Settings.EMPTY));
    }
}
