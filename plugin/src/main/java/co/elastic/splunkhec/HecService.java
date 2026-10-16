package co.elastic.splunkhec;

import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.breaker.NoopCircuitBreaker;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Token checks, Splunk's response codes, and ack ids. */
final class HecService {

    /** A Splunk HEC response: HTTP status, Splunk's numeric code and text. */
    record Outcome(int status, int code, String text) {
        String json(Map<String, Object> extra) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("text", text);
            m.put("code", code);
            m.putAll(extra);
            return Json.write(m);
        }
    }

    // Splunk's HEC status codes, same HTTP statuses and texts
    static final Outcome SUCCESS = new Outcome(200, 0, "Success");
    static final Outcome NO_TOKEN = new Outcome(401, 2, "Token is required");
    static final Outcome INVALID_AUTH = new Outcome(401, 3, "Invalid authorization");
    static final Outcome BAD_TOKEN = new Outcome(403, 4, "Invalid token");
    static final Outcome NO_DATA = new Outcome(400, 5, "No data");
    static final Outcome INVALID_FORMAT = new Outcome(400, 6, "Invalid data format");
    static final Outcome INTERNAL = new Outcome(500, 8, "Internal server error");
    static final Outcome BUSY = new Outcome(503, 9, "Server is busy");
    static final Outcome EVENT_REQUIRED = new Outcome(400, 12, "Event field is required");
    static final Outcome EVENT_BLANK = new Outcome(400, 13, "Event field cannot be blank");
    static final Outcome ACK_DISABLED = new Outcome(400, 14, "ACK is disabled");
    static final Outcome INDEXED_FIELDS = new Outcome(400, 15, "Error in handling indexed fields");
    static final Outcome QUERY_AUTH_DISABLED = new Outcome(400, 16, "Query string authorization is not enabled");
    static final Outcome HEALTHY = new Outcome(200, 17, "HEC is healthy");

    /** The caller's token: its fingerprint and the name it was given ("" when unnamed). */
    record Caller(String sha256, String name) {}

    final TokenRegistry tokens = new TokenRegistry();
    final HecIndexer indexer;
    private final String nodeName;
    private volatile boolean queryStringAuth;
    private volatile boolean ack;
    private volatile boolean keepEnvelope = true;
    /** Ack ids handed out per channel; a response is only sent once its events are indexed, so every issued id is acked. */
    private final AtomicLong ackIds = new AtomicLong();
    /** Elasticsearch's request breaker: a request's decoded text, parsed events and documents are reserved on it. */
    volatile CircuitBreaker memory = new NoopCircuitBreaker(CircuitBreaker.REQUEST);

    HecService(HecIndexer indexer, String nodeName, boolean queryStringAuth) {
        this.indexer = indexer;
        this.nodeName = nodeName;
        this.queryStringAuth = queryStringAuth;
    }

    void setQueryStringAuth(boolean enabled) {
        this.queryStringAuth = enabled;
    }

    void setAck(boolean enabled) {
        this.ack = enabled;
    }

    boolean ack() {
        return ack;
    }

    void setEnvelope(String envelope) {
        this.keepEnvelope = envelope.equals("keep");
    }

    boolean keepEnvelope() {
        return keepEnvelope;
    }

    String nodeName() {
        return nodeName;
    }

    long nextAckId() {
        return ackIds.getAndIncrement();
    }

    /**
     * The token from {@code Authorization: Splunk <token>}, or {@code ?token=} when query-string auth is on. Throws
     * the Splunk outcome to send when it isn't allowed.
     */
    Caller authenticate(String authorization, String queryToken) throws HecParser.Rejected {
        String token = null;
        if (authorization != null && authorization.isBlank() == false) {
            String a = authorization.trim();
            int sp = a.indexOf(' ');
            String scheme = sp < 0 ? a : a.substring(0, sp);
            String value = sp < 0 ? "" : a.substring(sp + 1).trim();
            if (scheme.equalsIgnoreCase("Splunk")) {
                token = value;
            } else {
                throw new HecParser.Rejected(INVALID_AUTH, -1);
            }
        } else if (queryToken != null && queryToken.isBlank() == false) {
            if (queryStringAuth == false) {
                throw new HecParser.Rejected(QUERY_AUTH_DISABLED, -1);
            }
            token = queryToken.trim();
        }
        if (token == null || token.isEmpty()) {
            throw new HecParser.Rejected(NO_TOKEN, -1);
        }
        String name = tokens.match(token);
        if (name == null) {
            throw new HecParser.Rejected(BAD_TOKEN, -1);
        }
        return new Caller(sha256(token), name);
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
