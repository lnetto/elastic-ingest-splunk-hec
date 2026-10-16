package co.elastic.splunkhec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.xpack.core.security.action.user.AuthenticateAction;
import org.elasticsearch.xpack.core.security.action.user.AuthenticateRequest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * Turns HEC events into documents and bulk-indexes them as the keystore API key.
 */
final class HecIndexer {

    private static final Logger logger = LogManager.getLogger(HecIndexer.class);

    /**
     * {@code retryable}: answer 503 so the sender resends (back-pressure, or the key can't write).
     * {@code firstFailed}: 0-based number of the first event that failed for good, or -1.
     */
    record Result(int indexed, int failed, boolean retryable, int firstFailed) {
        static final Result NONE = new Result(0, 0, false, -1);

        /** This result followed by the next slice's. */
        Result then(Result next) {
            return new Result(indexed + next.indexed, failed + next.failed, retryable || next.retryable,
                firstFailed >= 0 ? firstFailed : next.firstFailed);
        }
    }

    /** The request the events came in. */
    record Request(String id, long receivedMillis, String node, String client, String peer, String xForwardedFor, String endpoint, String channel, String userAgent,
                   HecService.Caller caller) {}

    private final Client client;
    private final ThreadContext threadContext;
    private final boolean security;
    private volatile String authorization;
    private volatile String target;
    private volatile boolean minimal;

    HecIndexer(Client client, ThreadContext threadContext, Settings settings) {
        this.client = client;
        this.threadContext = threadContext;
        this.security = settings.getAsBoolean("xpack.security.enabled", true);
        this.target = HecSettings.TARGET.get(settings);
        setMetadata(HecSettings.METADATA.get(settings));
        setApiKey(settings);
    }

    /**
     * Reads splunk_hec.api_key. Secure settings are only readable while the node starts and during
     * POST _nodes/reload_secure_settings, which calls this again: a new or rotated key needs no restart.
     */
    void setApiKey(Settings settings) {
        try (SecureString key = HecSettings.API_KEY.exists(settings) ? HecSettings.API_KEY.get(settings) : null) {
            this.authorization = key == null ? null : "ApiKey " + key;
        }
        if (authorization == null && security) {
            logger.warn("splunk_hec.api_key is not set in the keystore; HEC requests are answered 503 until it is");
        }
    }

    void setTarget(String target) {
        this.target = target;
    }

    void setMetadata(String metadata) {
        this.minimal = metadata.equals("minimal");
    }

    /** Without a key, with security on, nothing can be indexed: health says so. */
    boolean ready() {
        return security == false || authorization != null;
    }

    /** One bulk request's worth of a batch: a large batch is indexed slice by slice, so only one slice of documents is in memory. */
    static final int SLICE_EVENTS = 2000;
    static final long SLICE_BYTES = 8 * 1024 * 1024;

    void index(List<HecParser.HecEvent> events, Request req, ActionListener<Result> listener) {
        String auth = authorization;
        if (security == false) {
            indexFrom(events, 0, req, null, Result.NONE, listener);
            return;
        }
        Result notIndexed = new Result(0, events.size(), true, -1);
        if (auth == null) {
            keyProblem("is not set in the keystore", null);
            listener.onResponse(notIndexed);
            return;
        }
        // An action this node runs for itself, with credentials that don't authenticate (an invalidated, expired or
        // mistyped key), runs as the internal _system user instead of failing, and _system can write to any existing
        // index. So check first that the key really authenticates as an API key, and never index otherwise.
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            threadContext.putHeader("Authorization", auth);
            client.execute(AuthenticateAction.INSTANCE, AuthenticateRequest.INSTANCE, ActionListener.wrap(r -> {
                if (r.authentication().isApiKey()) {
                    indexFrom(events, 0, req, auth, Result.NONE, listener);
                } else {
                    keyProblem("authenticates as [" + r.authentication().getEffectiveSubject().getUser().principal() + "], not as an API key",
                        null);
                    listener.onResponse(notIndexed);
                }
            }, e -> {
                keyProblem("doesn't authenticate", e);
                listener.onResponse(notIndexed);
            }));
        }
    }

    private final AtomicLong lastKeyWarning = new AtomicLong();

    /** Once a minute at most: every request fails the same way until the key is fixed. */
    private void keyProblem(String what, Exception e) {
        long now = System.nanoTime(), last = lastKeyWarning.get();
        if ((last == 0 || now - last > TimeUnit.MINUTES.toNanos(1)) && lastKeyWarning.compareAndSet(last, now)) {
            logger.warn("splunk_hec.api_key " + what + "; answering 503 and not indexing", e);
        }
    }

    private void indexFrom(List<HecParser.HecEvent> events, int start, Request req, String auth, Result before,
                           ActionListener<Result> listener) {
        BulkRequest bulk = new BulkRequest();
        boolean minimal = this.minimal;
        // event number of each bulk item: a metric event can be several documents
        List<Integer> eventOf = new ArrayList<>();
        int next = start;
        while (next < events.size() && bulk.numberOfActions() < SLICE_EVENTS && bulk.estimatedSizeInBytes() < SLICE_BYTES) {
            HecParser.HecEvent e = events.get(next);
            events.set(next, null);  // the document holds it now; let the parsed event go
            for (Map<String, Object> src : toSources(e, req, minimal)) {
                bulk.add(new IndexRequest(resolveTarget(e)).opType(DocWriteRequest.OpType.CREATE).source(src));
                eventOf.add(next);
            }
            next++;
        }
        int end = next;
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            if (auth != null) {
                threadContext.putHeader("Authorization", auth);
            }
            client.bulk(bulk, ActionListener.wrap(r -> {
                Result sum = before.then(summarize(r, eventOf));
                if (end < events.size() && sum.retryable() == false) {
                    indexFrom(events, end, req, auth, sum, listener);
                } else {
                    // a retryable failure stops the batch: the sender resends all of it
                    int skipped = events.size() - end;
                    listener.onResponse(new Result(sum.indexed(), sum.failed() + skipped, sum.retryable(), sum.firstFailed()));
                }
            }, e -> {
                logger.warn("splunk_hec bulk of {} events failed; the sender will retry", events.size() - start, e);
                listener.onResponse(new Result(before.indexed(), before.failed() + events.size() - start, true, before.firstFailed()));
            }));
        }
    }

    static Result summarize(BulkResponse resp, List<Integer> eventOf) {
        int failed = 0;
        boolean retryable = false;
        int firstFailed = -1;
        BulkItemResponse.Failure first = null;
        BulkItemResponse[] items = resp.getItems();
        for (int n = 0; n < items.length; n++) {
            BulkItemResponse item = items[n];
            if (item.isFailed()) {
                failed++;
                RestStatus st = item.getFailure().getStatus();
                if (retryable(st)) {
                    retryable = true;
                } else if (firstFailed < 0) {
                    firstFailed = eventOf.get(n);
                }
                if (first == null) {
                    first = item.getFailure();
                }
            }
        }
        if (first != null) {
            logger.warn("splunk_hec: {}/{} events failed (retry={}), first: [{}] {}", failed, resp.getItems().length, retryable,
                first.getIndex(), first.getMessage());
        }
        return new Result(items.length - failed, failed, retryable, firstFailed);
    }

    /**
     * Item failures that are about the cluster, not the event, so the sender should resend: back-pressure,
     * the API key lacking privileges, the target deleted while the bulk ran (404: the retry recreates the
     * data stream), or an internal error. Anything else is the event's own problem: the sender is told which
     * event, instead of Success.
     */
    static boolean retryable(RestStatus st) {
        return st == RestStatus.TOO_MANY_REQUESTS || st == RestStatus.SERVICE_UNAVAILABLE
            || st == RestStatus.UNAUTHORIZED || st == RestStatus.FORBIDDEN || st == RestStatus.NOT_FOUND
            || st == RestStatus.INTERNAL_SERVER_ERROR;
    }

    String resolveTarget(HecParser.HecEvent e) {
        String t = this.target;
        if (t.indexOf('{') < 0) {
            return t;
        }
        return t.replace("{index}", sanitize(e.index())).replace("{sourcetype}", sanitize(sourcetype(e)));
    }

    /** Longest name part: two of them still fit Elasticsearch's 255-byte limit on backing index names. */
    static final int MAX_NAME_PART = 100;

    private static final Pattern NOT_NAME_CHAR = Pattern.compile("[^a-z0-9_.]");
    private static final Pattern WINDOWS_PATH = Pattern.compile("^[A-Za-z]:\\\\.*");

    /** Data stream name parts: lowercase, no '-', no characters ES rejects, not too long. */
    static String sanitize(String v) {
        if (v == null || v.isEmpty()) {
            return "unknown";
        }
        String s = NOT_NAME_CHAR.matcher(v.toLowerCase(Locale.ROOT)).replaceAll("_");
        s = s.startsWith("_") || s.startsWith(".") ? "x" + s : s;
        return s.length() > MAX_NAME_PART ? s.substring(0, MAX_NAME_PART) : s;
    }

    /** Splunk's defaults when the sender gives none: sourcetype httpevent, source http:<token name>, host = the sender. */
    static String sourcetype(HecParser.HecEvent e) {
        return e.sourcetype() != null ? e.sourcetype() : "httpevent";
    }

    /**
     * One document per event; a Splunk metric event ({@code "event":"metric"}) becomes one document per
     * measurement instead, with {@code metric.name}/{@code metric.value} and the other fields as dimensions.
     * Splunk's formats: single ({@code metric_name} + {@code _value}) and multi ({@code "metric_name:<name>": value},
     * what the OpenTelemetry Collector sends). Left as fields, the dotted names would nest into objects.
     */
    static List<Map<String, Object>> toSources(HecParser.HecEvent e, Request req, boolean minimal) {
        if ("metric".equals(e.event()) == false) {
            return List.of(toSource(e, req, minimal));
        }
        Map<String, Object> dims = new java.util.LinkedHashMap<>();
        Map<String, Object> measures = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, Object> f : e.fields().entrySet()) {
            String k = f.getKey();
            if (k.startsWith("metric_name:")) {
                measures.put(k.substring("metric_name:".length()), f.getValue());
            } else if (k.equals("metric_name") || k.equals("_value")) {
                continue;
            } else {
                dims.put(k, f.getValue());
            }
        }
        if (e.fields().get("metric_name") != null) {
            measures.put(String.valueOf(e.fields().get("metric_name")), e.fields().get("_value"));
        }
        if (measures.isEmpty()) {
            return List.of(toSource(e, req, minimal));
        }
        Object type = dims.remove("metric_type");
        List<Map<String, Object>> out = new java.util.ArrayList<>(measures.size());
        for (Map.Entry<String, Object> m : measures.entrySet()) {
            HecParser.HecEvent one = new HecParser.HecEvent(e.event(), e.time(), e.host(), e.source(), e.sourcetype(), e.index(), dims);
            Map<String, Object> src = toSource(one, req, minimal);
            Map<String, Object> metric = new HashMap<>();
            metric.put("name", m.getKey());
            Double v = number(m.getValue());
            if (v != null) {
                metric.put("value", v);
            }
            if (type != null) {
                metric.put("type", String.valueOf(type));
            }
            src.put("metric", metric);
            src.put("message", m.getKey() + "=" + m.getValue());
            out.add(src);
        }
        return out;
    }

    private static Double number(Object v) {
        if (v instanceof Number n) {
            return n.doubleValue();
        }
        try {
            return v == null ? null : Double.parseDouble(v.toString().trim());
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    /** {@code minimal}: without the request's details (splunk_hec.metadata). */
    static Map<String, Object> toSource(HecParser.HecEvent e, Request req, boolean minimal) {
        Map<String, Object> src = new HashMap<>();
        String received = Instant.ofEpochMilli(req.receivedMillis()).toString();
        Instant time = e.time() == null ? null : Instant.ofEpochSecond((long) Math.floor(e.time()),
            Math.round((e.time() - Math.floor(e.time())) * 1_000_000d) * 1000);
        src.put("@timestamp", (time != null ? time : Instant.ofEpochMilli(req.receivedMillis())).toString());

        Map<String, Object> splunk = new HashMap<>();
        if (time != null) {
            splunk.put("time", time.toString());
        }
        // the event as sent; an object event is its JSON text. Nothing is parsed out of it.
        src.put("message", e.event() instanceof String s ? s : Json.write(e.event()));
        String host = e.host() != null ? e.host() : req.client();
        String source = e.source() != null ? e.source() : "http:" + (req.caller().name().isEmpty() ? "hec" : req.caller().name());
        if (host != null) {
            src.put("host", Map.of("name", host));
            splunk.put("host", host);
        }
        if (source.startsWith("/") || WINDOWS_PATH.matcher(source).matches()) {
            src.put("log", Map.of("file", Map.of("path", source)));
        }
        splunk.put("source", source);
        splunk.put("sourcetype", sourcetype(e));
        if (e.index() != null) {
            splunk.put("index", e.index());
        }
        if (e.fields().isEmpty() == false) {
            splunk.put("fields", e.fields());
        }
        if (req.caller().name().isEmpty() == false) {
            splunk.put("token_name", req.caller().name());
        }
        putIfNotNull(splunk, "channel", req.channel());
        splunk.put("hec", Map.of("endpoint", req.endpoint()));
        src.put("splunk", splunk);
        Map<String, Object> agent = agent(req.userAgent());
        if (agent != null) {
            src.put("agent", agent);
        }
        Map<String, Object> event = new HashMap<>();
        event.put("module", "splunk_hec");
        src.put("event", event);
        if (minimal) {
            return src;
        }
        splunk.put("token_sha256", req.caller().sha256());
        Map<String, Object> r = new HashMap<>();
        r.put("id", req.id());
        r.put("received", received);
        putIfNotNull(r, "node", req.node());
        putIfNotNull(r, "remote_address", req.peer());
        putIfNotNull(r, "x_forwarded_for", req.xForwardedFor());
        splunk.put("request", r);
        if (req.client() != null) {
            src.put("network", Map.of("forwarded_ip", req.client()));
        }
        if (req.userAgent() != null) {
            src.put("user_agent", Map.of("original", req.userAgent()));
        }
        event.put("ingested", received);
        return src;
    }

    /**
     * What sent the event, from the User-Agent's first product token: "OpenTelemetry Collector Contrib/0.120.0
     * (linux/amd64)" is type "OpenTelemetry Collector Contrib", version "0.120.0". Null without a User-Agent.
     */
    static Map<String, Object> agent(String userAgent) {
        String ua = userAgent == null ? "" : userAgent.trim();
        if (ua.isEmpty()) {
            return null;
        }
        int slash = ua.indexOf('/');
        if (slash < 0) {
            return Map.of("type", ua.split("\\s", 2)[0]);
        }
        String type = ua.substring(0, slash).trim();
        if (type.isEmpty()) {
            return null;   // a version of nothing names no sender
        }
        int end = slash + 1;
        while (end < ua.length() && Character.isWhitespace(ua.charAt(end)) == false && ua.charAt(end) != ';' && ua.charAt(end) != ')') {
            end++;
        }
        String version = ua.substring(slash + 1, end);
        return version.isEmpty() ? Map.of("type", type) : Map.of("type", type, "version", version);
    }

    private static void putIfNotNull(Map<String, Object> m, String k, Object v) {
        if (v != null) {
            m.put(k, v);
        }
    }
}
