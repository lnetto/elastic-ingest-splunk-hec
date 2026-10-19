package co.elastic.splunkhec;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongConsumer;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/**
 * Turns HEC request bodies into events, the way Splunk's collector does.
 *
 * <ul>
 *   <li><b>/services/collector/event</b>: one or more JSON objects, concatenated or one per line (a
 *       "batch"); a JSON array is accepted too. Each has {@code event} (string or object, required, not
 *       blank) and optional {@code time} (epoch seconds), {@code host}, {@code source}, {@code sourcetype},
 *       {@code index}, {@code fields} (indexed fields).</li>
 *   <li><b>/services/collector/raw</b>: plain text, one event per line; metadata from the query string
 *       ({@code host}, {@code source}, {@code sourcetype}, {@code index}, {@code time}).</li>
 * </ul>
 * A bad event stops the batch as Splunk does: the events before it are still indexed, and the sender gets
 * Splunk's code with the 0-based number of the bad event ({@link Rejected#accepted}).
 */
final class HecParser {

    /** One event, before it becomes a document. */
    record HecEvent(Object event, Double time, String host, String source, String sourcetype, String index, Map<String, Object> fields) {}

    /**
     * A rejection with Splunk's code; {@code eventNumber} is -1 when it isn't about one event. {@code accepted}: the
     * good events before the bad one, which Splunk indexes anyway (a sender doesn't resend after a 400).
     */
    static final class Rejected extends Exception {
        final HecService.Outcome outcome;
        final int eventNumber;
        final List<HecEvent> accepted;

        Rejected(HecService.Outcome outcome, int eventNumber) {
            this(outcome, eventNumber, List.of());
        }

        Rejected(HecService.Outcome outcome, int eventNumber, List<HecEvent> accepted) {
            super(outcome.text());
            this.outcome = outcome;
            this.eventNumber = eventNumber;
            this.accepted = accepted;
        }
    }

    /** Inflated-size cap: Elasticsearch's default http.max_content_length, so gzip can't carry more than a plain body. */
    static final int MAX_INFLATED = 100 * 1024 * 1024;

    private HecParser() {}

    /**
     * Gzip-compressed bodies are inflated (senders set Content-Encoding: gzip; some proxies strip the header). Reads the
     * request's own buffer in place: a copy would be heap the circuit breaker doesn't see. {@code reserve} is told each
     * inflated chunk before it is kept, so it can refuse (throw) before the memory is used.
     */
    static String text(BytesReference body, LongConsumer reserve) throws Rejected {
        return text(body, MAX_INFLATED, reserve);
    }

    static String text(BytesReference body, int maxInflated, LongConsumer reserve) throws Rejected {
        if (body.length() >= 2 && (body.get(0) & 0xff) == 0x1f && (body.get(1) & 0xff) == 0x8b) {
            // inflated into pages, not one growing array: no doubling and copying, so 1x the text plus the String
            try (InputStream in = new GZIPInputStream(body.streamInput()); BytesStreamOutput out = new BytesStreamOutput()) {
                byte[] chunk = new byte[64 * 1024];
                for (int n; (n = in.read(chunk)) > 0; ) {
                    if (out.size() + n > maxInflated) {
                        throw new Rejected(HecService.INVALID_FORMAT, -1);
                    }
                    reserve.accept(n);
                    out.write(chunk, 0, n);
                }
                return out.bytes().utf8ToString();
            } catch (IOException e) {
                throw new Rejected(HecService.INVALID_FORMAT, -1);
            }
        }
        return body.utf8ToString();
    }

    /**
     * {@code reserve} is told the parsed values' heap as they are made (see {@link Json#VALUE_COST}). With
     * {@code keep}, each event is checked the same way but kept as sent: its JSON text is the event, and the metadata
     * is the query string's ({@code host}, {@code source}, {@code sourcetype}, {@code index}), as for /raw. Unwrapped,
     * the query string still gives the defaults for events that don't say, as Splunk's /event does.
     */
    static List<HecEvent> events(String body, Map<String, String> params, boolean keep, LongConsumer reserve) throws Rejected {
        if (body.isBlank()) {
            throw new Rejected(HecService.NO_DATA, -1);
        }
        List<Object> values;
        List<String> texts = keep ? new ArrayList<>() : null;
        Json.SequenceException badJson = null;
        try {
            values = Json.parseSequence(body, reserve, texts);  // an array's elements are events of their own
        } catch (Json.SequenceException e) {
            values = e.parsed;  // the events before the bad one
            badJson = e;
        }
        List<HecEvent> out = new ArrayList<>(values.size());
        for (int i = 0; i < values.size(); i++) {
            HecService.Outcome bad = check(values.get(i));
            if (bad != null) {
                throw new Rejected(bad, i, out);
            }
            Map<?, ?> m = (Map<?, ?>) values.get(i);
            Double time = epochSeconds(m.get("time"));
            Map<String, Object> fields = Map.of();
            if (m.get("fields") instanceof Map<?, ?> f && f.isEmpty() == false) {
                Map<String, Object> copy = new LinkedHashMap<>();
                f.forEach((k, v) -> copy.put(String.valueOf(k), v));
                fields = copy;
            }
            out.add(keep
                ? new HecEvent(texts.get(i), null, params.get("host"), params.get("source"), params.get("sourcetype"), params.get("index"),
                    Map.of())
                : new HecEvent(m.get("event"), time, or(str(m.get("host")), params.get("host")), or(str(m.get("source")), params.get("source")),
                    or(str(m.get("sourcetype")), params.get("sourcetype")), or(str(m.get("index")), params.get("index")), fields));
        }
        if (badJson != null) {
            throw new Rejected(HecService.INVALID_FORMAT, badJson.index, out);
        }
        return out;
    }

    /**
     * Why Splunk refuses this event, or null. Codes as Splunk 10.0.8 answers them (compat/splunk-10.0.8.json):
     * not an object or "event": null → 6, no "event" → 12, a blank string → 13 ({} is an event), "fields" not an
     * object → 6, "time" null, true/false, an object or an array → 6, any other "time" that isn't an epoch time → 15.
     */
    static HecService.Outcome check(Object value) {
        if (!(value instanceof Map<?, ?> m)) {
            return HecService.INVALID_FORMAT;
        }
        if (m.containsKey("event") == false) {
            return HecService.EVENT_REQUIRED;
        }
        Object event = m.get("event");
        if (event == null) {
            return HecService.INVALID_FORMAT;
        }
        if (event instanceof String s && s.isBlank()) {
            return HecService.EVENT_BLANK;
        }
        if (m.get("fields") != null && m.get("fields") instanceof Map<?, ?> == false) {
            return HecService.INVALID_FORMAT;
        }
        Object time = m.get("time");
        if (m.containsKey("time") && (time == null || time instanceof Boolean || time instanceof Map || time instanceof List)) {
            return HecService.INVALID_FORMAT;
        }
        try {
            epochSeconds(time);
        } catch (NumberFormatException e) {
            return HecService.INDEXED_FIELDS;
        }
        return null;
    }

    /** One event per non-blank line; CRLF and LF both end a line. Each line is reserved as it is made. */
    static List<HecEvent> raw(String body, Map<String, String> params, LongConsumer reserve) throws Rejected {
        if (body.isBlank()) {
            throw new Rejected(HecService.NO_DATA, -1);
        }
        Double time;
        try {
            time = epochSeconds(params.get("time"));
        } catch (NumberFormatException e) {
            throw new Rejected(HecService.INDEXED_FIELDS, 0);  // Splunk's answer for a bad ?time=
        }
        String host = params.get("host"), source = params.get("source"), sourcetype = params.get("sourcetype"), index = params.get("index");
        List<HecEvent> out = new ArrayList<>();
        int unreserved = 0;
        for (int start = 0; start < body.length(); ) {
            int nl = body.indexOf('\n', start);
            int end = nl < 0 ? body.length() : nl;
            int stop = end > start && body.charAt(end - 1) == '\r' ? end - 1 : end;
            if (isBlank(body, start, stop) == false) {
                if (++unreserved == 256) {
                    reserve.accept(256L * Json.VALUE_COST);
                    unreserved = 0;
                }
                out.add(new HecEvent(body.substring(start, stop), time, host, source, sourcetype, index, Map.of()));
            }
            start = end + 1;
        }
        reserve.accept((long) unreserved * Json.VALUE_COST);
        return out;
    }

    /** Beyond this (year ~31 million) a time can't be a date; NaN and Infinity aren't either. */
    static final double MAX_EPOCH_SECONDS = 1e15;

    /**
     * HEC time as Splunk 10.6 reads it (checked against a heavy forwarder's HEC input): digits with at most one
     * decimal point, no sign, exponent, or spaces, as a number or a string. An integer of more than 10 digits (leading
     * zeros don't count) is seconds followed by a fraction: milliseconds (1760000000123), microseconds and
     * nanoseconds all land on the same instant. Anything else throws, which Splunk answers with code 15.
     */
    static Double epochSeconds(Object t) {
        if (t == null) {
            return null;
        }
        double d;
        if (t instanceof Double || t instanceof Float) {
            d = ((Number) t).doubleValue();
            if (Double.doubleToRawLongBits(d) < 0) {  // negative, -0.0 included
                throw new NumberFormatException("not an epoch time: " + t);
            }
        } else {
            // Long and Integer, a number too long for a long (Json keeps it as its digits), or a string
            String s = t.toString();
            if (TIME.matcher(s).matches() == false) {
                throw new NumberFormatException("not an epoch time: " + t);
            }
            if (s.indexOf('.') < 0) {
                String digits = s.replaceFirst("^0+(?=.)", "");
                s = digits.length() > 10 ? digits.substring(0, 10) + "." + digits.substring(10) : digits;
            }
            d = Double.parseDouble(s);
        }
        if (Double.isFinite(d) == false || d >= MAX_EPOCH_SECONDS) {
            throw new NumberFormatException("not an epoch time: " + t);
        }
        return d;
    }

    /** Digits with at most one decimal point, at least one digit. */
    private static final Pattern TIME = Pattern.compile("(?=[0-9.]*[0-9])[0-9]*(\\.[0-9]*)?");

    private static boolean isBlank(String s, int from, int to) {
        for (int k = from; k < to; k++) {
            if (Character.isWhitespace(s.charAt(k)) == false) {
                return false;
            }
        }
        return true;
    }

    private static String or(String a, String b) {
        return a != null ? a : b;
    }

    private static String str(Object o) {
        return o == null ? null : o instanceof String s ? (s.isEmpty() ? null : s) : String.valueOf(o);
    }
}
