package co.elastic.splunkhec;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongConsumer;

/**
 * Minimal JSON reader/writer. Splunk senders may repeat keys
 * ({@code "tags{}":"t1","tags{}":"t2"}), which Elasticsearch's parser rejects as duplicates; here a
 * repeated key collects its values into a list instead.
 */
final class Json {

    /**
     * Deeper input is rejected: parsing recurses on Netty's network threads, where a few hundred levels can
     * already overflow the stack, and a StackOverflowError stops the node. Mappings stop at 20 levels anyway.
     */
    static final int MAX_DEPTH = 100;

    /**
     * Heap a parsed value costs beyond its text, in the units {@code reserve} takes (bytes of text): maps, lists,
     * strings and boxed numbers are objects, so a body of many tiny values takes far more heap than its size says.
     */
    static final int VALUE_COST = 100;
    /** Values counted before they are reserved together. */
    private static final int RESERVE_EVERY = 256;

    private final String s;
    private final LongConsumer reserve;
    /** When not null: the text of each top-level value, or of each element when that value is an array. */
    private final List<String> texts;
    private int i;
    private int depth;
    private int unreserved;
    private long unreservedText;
    /** The elements so far of the top-level array being parsed: a sequence that fails inside one still has them. */
    private List<Object> topArray;

    private Json(String s, LongConsumer reserve, List<String> texts) {
        this.s = s;
        this.reserve = reserve;
        this.texts = texts;
    }

    /**
     * A value in a sequence didn't parse; {@code index} is its 0-based position as Splunk counts (an array's
     * elements one by one), {@code parsed} the values before it: {@code [a,b,{bad} → a, b, index 2}.
     */
    static final class SequenceException extends Exception {
        final int index;
        final List<Object> parsed;

        SequenceException(int index, String message, List<Object> parsed) {
            super(message);
            this.index = index;
            this.parsed = parsed;
        }
    }

    /**
     * Values one after another, separated by optional whitespace: {"a":1}{"b":2}\n{"c":3}. A top-level array stands
     * for its elements, as in Splunk ({"a":1}[{"b":2},{"c":3}] is three values). {@code reserve} is told the cost of
     * the values as they are parsed, and may refuse (throw) before more are made.
     */
    static List<Object> parseSequence(String text, LongConsumer reserve) throws SequenceException {
        return parseSequence(text, reserve, null);
    }

    /** Also adds to {@code texts} each value's text exactly as sent (each element's, for an array), reserving their length too. */
    static List<Object> parseSequence(String text, LongConsumer reserve, List<String> texts) throws SequenceException {
        Json p = new Json(text, reserve, texts);
        List<Object> out = new ArrayList<>();
        p.ws();
        while (p.i < p.s.length()) {
            int start = p.i;
            boolean array = p.s.charAt(start) == '[';
            p.topArray = null;
            try {
                Object v = p.value();
                if (array) {
                    out.addAll((List<?>) v);
                } else {
                    out.add(v);
                    p.keepText(start);
                }
            } catch (IllegalArgumentException e) {
                // what was parsed is kept (the events before the bad one are indexed): reserve it as on success
                reserve.accept((long) p.unreserved * VALUE_COST + p.unreservedText);
                if (array && p.topArray != null) {
                    out.addAll(p.topArray);
                }
                throw new SequenceException(out.size(), e.getMessage(), out);
            }
            p.ws();
        }
        reserve.accept((long) p.unreserved * VALUE_COST + p.unreservedText);
        return out;
    }

    private void keepText(int start) {
        if (texts != null) {
            texts.add(s.substring(start, i));
            unreservedText += i - start;
        }
    }

    static Object parse(String text) {
        Json p = new Json(text, n -> {}, null);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) {
            throw p.error("trailing characters");
        }
        return v;
    }

    private Object value() {
        if (i >= s.length()) {
            throw error("unexpected end");
        }
        if (++unreserved == RESERVE_EVERY) {
            reserve.accept((long) RESERVE_EVERY * VALUE_COST + unreservedText);
            unreserved = 0;
            unreservedText = 0;
        }
        char c = s.charAt(i);
        return switch (c) {
            case '{', '[' -> {
                if (++depth > MAX_DEPTH) {
                    throw error("nested deeper than " + MAX_DEPTH);
                }
                Object v = c == '{' ? object() : array();
                depth--;
                yield v;
            }
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> {
                if (c == '-' || (c >= '0' && c <= '9')) {
                    yield number();
                }
                throw error("unexpected character '" + c + "'");
            }
        };
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        i++;
        ws();
        if (peek() == '}') {
            i++;
            return m;
        }
        while (true) {
            ws();
            if (peek() != '"') {
                throw error("expected a key");
            }
            String k = string();
            ws();
            expect(':');
            ws();
            Object v = value();
            if (m.containsKey(k)) {
                Object prev = m.get(k);
                if (prev instanceof Multi multi) {
                    multi.add(v);
                } else {
                    Multi multi = new Multi();
                    multi.add(prev);
                    multi.add(v);
                    m.put(k, multi);
                }
            } else {
                m.put(k, v);
            }
            ws();
            char c = next();
            if (c == '}') {
                return m;
            }
            if (c != ',') {
                throw error("expected ',' or '}'");
            }
        }
    }

    /** Values of a repeated key; a plain list once parsing is done. */
    private static final class Multi extends ArrayList<Object> {}

    private List<Object> array() {
        List<Object> a = new ArrayList<>();
        if (depth == 1) {
            topArray = a;
        }
        i++;
        ws();
        if (peek() == ']') {
            i++;
            return a;
        }
        while (true) {
            ws();
            int start = i;
            a.add(value());
            if (depth == 1) {
                keepText(start);
            }
            ws();
            char c = next();
            if (c == ']') {
                return a;
            }
            if (c != ',') {
                throw error("expected ',' or ']'");
            }
        }
    }

    private String string() {
        i++;
        StringBuilder b = null;
        int start = i;
        while (true) {
            if (i >= s.length()) {
                throw error("unterminated string");
            }
            char c = s.charAt(i);
            if (c == '"') {
                String out = b == null ? s.substring(start, i) : b.append(s, start, i).toString();
                i++;
                return out;
            }
            if (c == '\\') {
                if (b == null) {
                    b = new StringBuilder();
                }
                b.append(s, start, i);
                i++;
                char e = next();
                switch (e) {
                    case '"', '\\', '/' -> b.append(e);
                    case 'b' -> b.append('\b');
                    case 'f' -> b.append('\f');
                    case 'n' -> b.append('\n');
                    case 'r' -> b.append('\r');
                    case 't' -> b.append('\t');
                    case 'u' -> {
                        if (i + 4 > s.length()) {
                            throw error("bad \\u escape");
                        }
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> throw error("bad escape \\" + e);
                }
                start = i;
            } else {
                i++;
            }
        }
    }

    /**
     * A JSON number, strictly: -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?. Splunk refuses the rest (01, 1., .5,
     * 00) as invalid JSON. Integers are Longs; one beyond a long is kept as its text (BigInteger would take seconds
     * on a long run of digits).
     */
    private Object number() {
        int start = i;
        boolean fraction = false;
        if (peek() == '-') {
            i++;
        }
        if (peek() == '0') {
            i++;
        } else if (peek() >= '1' && peek() <= '9') {
            digits();
        } else {
            throw error("bad number");
        }
        if (peek() == '.') {
            i++;
            fraction = true;
            if (digits() == 0) {
                throw error("bad number " + s.substring(start, i));
            }
        }
        if (peek() == 'e' || peek() == 'E') {
            i++;
            fraction = true;
            if (peek() == '+' || peek() == '-') {
                i++;
            }
            if (digits() == 0) {
                throw error("bad number " + s.substring(start, i));
            }
        }
        if (peek() >= '0' && peek() <= '9') {
            throw error("bad number " + s.substring(start, i + 1));  // 01, -00
        }
        String n = s.substring(start, i);
        if (fraction) {
            return Double.parseDouble(n);
        }
        int digits = n.length() - (n.startsWith("-") ? 1 : 0);
        if (digits <= 18) {
            return Long.parseLong(n);
        }
        if (digits > 19) {
            return n;
        }
        try {
            return Long.parseLong(n);
        } catch (NumberFormatException tooBig) {
            return n;
        }
    }

    private int digits() {
        int from = i;
        while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') {
            i++;
        }
        return i - from;
    }

    private Object literal(String word, Object v) {
        if (s.startsWith(word, i) == false) {
            throw error("unexpected token");
        }
        i += word.length();
        return v;
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                i++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        return i < s.length() ? s.charAt(i) : '\0';
    }

    private char next() {
        if (i >= s.length()) {
            throw error("unexpected end");
        }
        return s.charAt(i++);
    }

    private void expect(char c) {
        if (next() != c) {
            throw error("expected '" + c + "'");
        }
    }

    private IllegalArgumentException error(String msg) {
        return new IllegalArgumentException("invalid JSON at " + i + ": " + msg);
    }

    /** Serializes parsed values back to JSON (used when an event body is an object, not a string). */
    static String write(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v);
        return b.toString();
    }

    private static void write(StringBuilder b, Object v) {
        if (v == null) {
            b.append("null");
        } else if (v instanceof String str) {
            b.append('"');
            for (int k = 0; k < str.length(); k++) {
                char c = str.charAt(k);
                switch (c) {
                    case '"' -> b.append("\\\"");
                    case '\\' -> b.append("\\\\");
                    case '\n' -> b.append("\\n");
                    case '\r' -> b.append("\\r");
                    case '\t' -> b.append("\\t");
                    default -> {
                        if (c < 0x20) {
                            b.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
                        } else {
                            b.append(c);
                        }
                    }
                }
            }
            b.append('"');
        } else if (v instanceof Map<?, ?> m) {
            b.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (first == false) {
                    b.append(',');
                }
                first = false;
                write(b, String.valueOf(e.getKey()));
                b.append(':');
                write(b, e.getValue());
            }
            b.append('}');
        } else if (v instanceof List<?> l) {
            b.append('[');
            for (int k = 0; k < l.size(); k++) {
                if (k > 0) {
                    b.append(',');
                }
                write(b, l.get(k));
            }
            b.append(']');
        } else {
            b.append(v);
        }
    }
}
