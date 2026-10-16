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
 * A bad batch is rejected whole, with Splunk's code and the 0-based number of the first bad event.
 */
final class HecParser {

    /** One event, before it becomes a document. */
    record HecEvent(Object event, Double time, String host, String source, String sourcetype, String index, Map<String, Object> fields) {}

    /** A rejection with Splunk's code; {@code eventNumber} is -1 when it isn't about one event. */
    static final class Rejected extends Exception {
        final HecService.Outcome outcome;
        final int eventNumber;

        Rejected(HecService.Outcome outcome, int eventNumber) {
            super(outcome.text());
            this.outcome = outcome;
            this.eventNumber = eventNumber;
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
     * is the query string's ({@code host}, {@code source}, {@code sourcetype}, {@code index}), as for /raw.
     */
    static List<HecEvent> events(String body, Map<String, String> params, boolean keep, LongConsumer reserve) throws Rejected {
        if (body.isBlank()) {
            throw new Rejected(HecService.NO_DATA, -1);
        }
        List<Object> values;
        List<String> texts = keep ? new ArrayList<>() : null;
        try {
            values = Json.parseSequence(body, reserve, texts);
        } catch (Json.SequenceException e) {
            throw new Rejected(HecService.INVALID_FORMAT, e.index);
        }
        if (values.size() == 1 && values.get(0) instanceof List<?> array) {
            values = new ArrayList<>(array);
        }
        List<HecEvent> out = new ArrayList<>(values.size());
        for (int i = 0; i < values.size(); i++) {
            if (!(values.get(i) instanceof Map<?, ?> m)) {
                throw new Rejected(HecService.INVALID_FORMAT, i);
            }
            if (m.containsKey("event") == false || m.get("event") == null) {
                throw new Rejected(HecService.EVENT_REQUIRED, i);
            }
            Object event = m.get("event");
            if (event instanceof String s && s.isBlank() || event instanceof Map<?, ?> em && em.isEmpty()) {
                throw new Rejected(HecService.EVENT_BLANK, i);
            }
            Double time;
            try {
                time = epochSeconds(m.get("time"));
            } catch (NumberFormatException e) {
                throw new Rejected(HecService.INVALID_FORMAT, i);
            }
            Map<String, Object> fields = Map.of();
            if (m.get("fields") instanceof Map<?, ?> f && f.isEmpty() == false) {
                Map<String, Object> copy = new LinkedHashMap<>();
                f.forEach((k, v) -> copy.put(String.valueOf(k), v));
                fields = copy;
            } else if (m.get("fields") != null && m.get("fields") instanceof Map<?, ?> == false) {
                throw new Rejected(HecService.INDEXED_FIELDS, i);
            }
            out.add(keep
                ? new HecEvent(texts.get(i), null, params.get("host"), params.get("source"), params.get("sourcetype"), params.get("index"),
                    Map.of())
                : new HecEvent(event, time, str(m.get("host")), str(m.get("source")), str(m.get("sourcetype")), str(m.get("index")),
                    fields));
        }
        return out;
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
            throw new Rejected(HecService.INVALID_FORMAT, -1);
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

    /** HEC time: epoch seconds, integer or fractional, as a number or a numeric string. */
    static Double epochSeconds(Object t) {
        if (t == null) {
            return null;
        }
        double d;
        if (t instanceof Number n) {
            d = n.doubleValue();
        } else {
            String s = t.toString().trim();
            if (s.isEmpty()) {
                return null;
            }
            d = Double.parseDouble(s);
        }
        if (Double.isFinite(d) == false || Math.abs(d) >= MAX_EPOCH_SECONDS) {
            throw new NumberFormatException("not an epoch time: " + t);
        }
        return d;
    }

    private static boolean isBlank(String s, int from, int to) {
        for (int k = from; k < to; k++) {
            if (Character.isWhitespace(s.charAt(k)) == false) {
                return false;
            }
        }
        return true;
    }

    private static String str(Object o) {
        return o == null ? null : o instanceof String s ? (s.isEmpty() ? null : s) : String.valueOf(o);
    }
}
