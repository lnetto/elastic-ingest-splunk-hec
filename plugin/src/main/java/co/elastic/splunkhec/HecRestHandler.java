package co.elastic.splunkhec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.client.internal.node.NodeClient;
import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.breaker.CircuitBreakingException;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.bytes.ReleasableBytesReference;
import org.elasticsearch.common.network.InetAddresses;
import org.elasticsearch.common.util.concurrent.AbstractRunnable;
import org.elasticsearch.common.util.concurrent.EsRejectedExecutionException;
import org.elasticsearch.core.Releasable;
import org.elasticsearch.core.Releasables;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestRequest.Method.POST;

/**
 * Splunk's HTTP Event Collector API on the Elasticsearch HTTP port (9200 / Elastic Cloud 443), so any HEC
 * sender (OpenTelemetry, Fluent Bit, Vector, Splunk logging libraries, cloud add-ons) can point at
 * Elasticsearch unchanged. Requests arrive as the privilege-less anonymous user (see
 * {@link HecSecurityExtension}); the HEC token is checked here and events are indexed as the plugin's key.
 */
final class HecRestHandler implements RestHandler {

    private static final Logger logger = LogManager.getLogger(HecRestHandler.class);

    static final String BASE = "/services/collector";

    private final Supplier<HecService> service;

    HecRestHandler(Supplier<HecService> service) {
        this.service = service;
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(POST, BASE),
            new Route(POST, BASE + "/event"),
            new Route(POST, BASE + "/event/1.0"),
            new Route(POST, BASE + "/raw"),
            new Route(POST, BASE + "/raw/1.0"),
            new Route(GET, BASE + "/health"),
            new Route(POST, BASE + "/health"),
            new Route(GET, BASE + "/health/1.0"),
            new Route(POST, BASE + "/health/1.0"),
            new Route(POST, BASE + "/ack"),
            new Route(POST, BASE + "/ack/1.0")
        );
    }

    /**
     * HEC bodies aren't one of Elasticsearch's content types: without this, application/octet-stream or no
     * Content-Type at all gets 406. text/plain and form-encoded still do, before the plugin sees them.
     */
    @Override
    public boolean mediaTypesValid(RestRequest request) {
        return true;
    }

    @Override
    public boolean canTripCircuitBreaker() {
        return true;
    }

    @Override
    public void handleRequest(RestRequest request, RestChannel channel, NodeClient client) {
        // ES rejects requests with unread query parameters; HEC senders add their own (channel, sourcetype …)
        Map<String, String> params = new HashMap<>();
        for (String k : new ArrayList<>(request.params().keySet())) {
            params.put(k, request.param(k));
        }
        String path = request.path();
        HecService svc = service.get();
        if (path.startsWith(BASE + "/health")) {
            // without the plugin's key nothing can be indexed: tell load balancers, as Splunk does when it can't take events
            send(channel, svc.indexer.ready() ? HecService.HEALTHY : HecService.BUSY, Map.of());
            return;
        }
        String reqChannel = firstNonBlank(request.header("X-Splunk-Request-Channel"), params.get("channel"));
        HecService.Caller caller;
        try {
            caller = svc.authenticate(request.header("Authorization"), params.get("token"));
        } catch (HecParser.Rejected r) {
            send(channel, r.outcome, Map.of());
            return;
        }
        if (path.startsWith(BASE + "/ack")) {
            // a small body (at most MAX_ACK_BODY), read in place before this method returns and the request releases it
            if (svc.ack() == false) {
                send(channel, HecService.ACK_DISABLED, Map.of());
            } else {
                ack(channel, request.hasContent() ? request.content() : ReleasableBytesReference.empty(), svc.memory);
            }
            return;
        }
        boolean raw = path.startsWith(BASE + "/raw");
        String peer = directPeer(request), xff = request.header("X-Forwarded-For");
        HecIndexer.Request req = new HecIndexer.Request(UUID.randomUUID().toString(), System.currentTimeMillis(), svc.nodeName(),
            clientAddress(xff, peer), peer, xff, raw ? "raw" : "event", reqChannel, request.header("User-Agent"), caller);
        // Inflating and parsing a batch of up to 100 MB takes a while: not on the network thread, which serves other
        // connections too. The body is kept until it has been read.
        ReleasableBytesReference bytes = request.hasContent() ? request.content().retain() : ReleasableBytesReference.empty();
        Releasable body = Releasables.releaseOnce(bytes);
        Reservation memory = new Reservation(svc.memory);
        try {
            client.threadPool().executor(ThreadPool.Names.WRITE).execute(new AbstractRunnable() {
                @Override
                protected void doRun() {
                    process(svc, channel, bytes, body, raw, params, req, reqChannel, memory);
                }

                @Override
                public void onRejection(Exception e) {
                    body.close();
                    memory.close();
                    send(channel, HecService.BUSY, Map.of());
                }

                @Override
                public void onFailure(Exception e) {
                    body.close();
                    memory.close();
                    logger.warn("splunk_hec request failed", e);
                    send(channel, HecService.INTERNAL, Map.of());
                }
            });
        } catch (EsRejectedExecutionException e) {
            body.close();
            memory.close();
            send(channel, HecService.BUSY, Map.of());
        }
    }

    /** Decode, parse and index one batch, then answer; on a WRITE thread. */
    private static void process(HecService svc, RestChannel channel, BytesReference bytes, Releasable body, boolean raw,
                                Map<String, String> params, HecIndexer.Request req, String reqChannel, Reservation memory) {
        // Decoding, parsing and building the documents takes several times the body in heap that Elasticsearch's own
        // accounting (the in-flight body) doesn't see; reserve it on the request breaker so a flood of large batches
        // gets "server busy" instead of an OutOfMemoryError. Released when the response is sent.
        try {
            List<HecParser.HecEvent> events;
            try {
                memory.add(bytes.length());
                String text = HecParser.text(bytes, memory::add);  // gzip: reserves the inflated size as it goes
                body.close();                                       // the text is a copy: the request buffer can go
                events = raw ? HecParser.raw(text, params, memory::add) : HecParser.events(text, params, svc.keepEnvelope(), memory::add);
            } catch (HecParser.Rejected r) {
                memory.close();
                send(channel, r.outcome, r.eventNumber >= 0 ? Map.of("invalid-event-number", r.eventNumber) : Map.of());
                return;
            } finally {
                body.close();
            }
            svc.indexer.index(events, req, ActionListener.runBefore(ActionListener.wrap(result -> {
                if (result.retryable()) {
                    send(channel, HecService.BUSY, Map.of());
                } else if (result.firstFailed() >= 0) {
                    // an event Elasticsearch refused (and no failure store took): say which, as Splunk does for a bad event
                    send(channel, HecService.INVALID_FORMAT, Map.of("invalid-event-number", result.firstFailed()));
                } else {
                    // with a channel the sender may poll /ack; the events are already indexed, so every id we hand out is acked
                    send(channel, HecService.SUCCESS, svc.ack() && reqChannel != null ? Map.of("ackId", svc.nextAckId()) : Map.of());
                }
            }, e -> {
                logger.warn("splunk_hec request failed", e);
                send(channel, HecService.INTERNAL, Map.of());
            }), memory::close));
        } catch (CircuitBreakingException | Busy e) {
            memory.close();
            send(channel, HecService.BUSY, Map.of());
        } catch (RuntimeException e) {
            memory.close();
            throw e;
        }
    }

    /** The node is out of room for another batch right now; the sender gets 503 "Server is busy" and retries. */
    static final class Busy extends RuntimeException {
        Busy() {
            super("splunk_hec: decoding budget in use", null, false, false);
        }
    }

    /**
     * Heap held for one request, {@link #FACTOR} per byte of text, on two counters: Elasticsearch's request breaker
     * (which also checks the heap actually in use) and the plugin's own budget, shared by every HEC request on the
     * node. The breaker alone isn't enough: it compares used heap with the new bytes only, so requests that have
     * reserved but not yet allocated don't count, and several big batches pass together. {@link #close} gives the
     * bytes back, once.
     */
    static final class Reservation implements Releasable {
        /** Heap per byte of request text: the decoded text, the String, the parsed events and one slice of documents. */
        static final int FACTOR = 4;
        /** All HEC requests on a node together: a quarter of the heap. */
        static final long BUDGET = Runtime.getRuntime().maxMemory() / 4;
        static final AtomicLong inUse = new AtomicLong();

        private final CircuitBreaker breaker;
        private final long budget;
        private final AtomicLong shared;
        private long bytes;

        Reservation(CircuitBreaker breaker) {
            this(breaker, BUDGET, inUse);
        }

        Reservation(CircuitBreaker breaker, long budget, AtomicLong shared) {
            this.breaker = breaker;
            this.budget = budget;
            this.shared = shared;
        }

        void add(long textBytes) {
            if (textBytes <= 0) {
                return;
            }
            long n = textBytes * FACTOR;
            long after = shared.addAndGet(n);
            // over budget, unless this request is the only one holding any: a batch bigger than the budget still gets in
            // when the node is otherwise idle, so it isn't refused forever
            if (after > budget && after - n - bytes > 0) {
                shared.addAndGet(-n);
                throw new Busy();
            }
            try {
                breaker.addEstimateBytesAndMaybeBreak(n, "splunk_hec request");
            } catch (RuntimeException e) {
                shared.addAndGet(-n);
                throw e;
            }
            bytes += n;
        }

        @Override
        public synchronized void close() {
            breaker.addWithoutBreaking(-bytes);
            shared.addAndGet(-bytes);
            bytes = 0;
        }
    }

    /** An ack query is a list of ids; anything bigger is not one. */
    static final int MAX_ACK_BODY = 1024 * 1024;

    /** {"acks":[0,1,2]} → {"acks":{"0":true,"1":true,"2":true}}: a 200 is only sent after indexing, so all are done. */
    private static void ack(RestChannel channel, BytesReference body, CircuitBreaker breaker) {
        Map<String, Object> acks = new LinkedHashMap<>();
        try (Reservation memory = new Reservation(breaker)) {
            if (body.length() <= MAX_ACK_BODY
                && Json.parse(HecParser.text(body, MAX_ACK_BODY, memory::add)) instanceof Map<?, ?> m
                && m.get("acks") instanceof List<?> ids) {
                for (Object id : ids) {
                    acks.put(String.valueOf(id instanceof Double d && d == Math.rint(d) ? (long) (double) d : id), true);
                }
            } else {
                send(channel, HecService.INVALID_FORMAT, Map.of());
                return;
            }
        } catch (IllegalArgumentException | HecParser.Rejected e) {
            send(channel, HecService.INVALID_FORMAT, Map.of());
            return;
        } catch (CircuitBreakingException | Busy e) {
            send(channel, HecService.BUSY, Map.of());
            return;
        }
        channel.sendResponse(new RestResponse(RestStatus.OK, "application/json; charset=UTF-8", Json.write(Map.of("acks", acks))));
    }

    private static void send(RestChannel channel, HecService.Outcome o, Map<String, Object> extra) {
        channel.sendResponse(new RestResponse(RestStatus.fromCode(o.status()), "application/json; charset=UTF-8", o.json(extra)));
    }

    private static String firstNonBlank(String a, String b) {
        return a != null && a.isBlank() == false ? a : b != null && b.isBlank() == false ? b : null;
    }

    /**
     * The sender's address: the last X-Forwarded-For entry when it is an IP address (proxies may add a port, or write
     * "unknown"), else the direct peer. The last entry is the one the proxy in front of Elasticsearch added; earlier
     * ones come from the sender and can say anything.
     */
    static String clientAddress(String xff, String peer) {
        if (xff != null && xff.isBlank() == false) {
            String last = xff.substring(xff.lastIndexOf(',') + 1).trim();
            if (last.startsWith("[") && last.indexOf(']') > 0) {
                last = last.substring(1, last.indexOf(']')); // [v6]:port
            } else if (last.indexOf(':') > 0 && last.indexOf(':') == last.lastIndexOf(':')) {
                last = last.substring(0, last.indexOf(':')); // v4:port
            }
            if (InetAddresses.isInetAddress(last)) {
                return last;
            }
        }
        return peer;
    }

    /** The direct TCP peer; on Elastic Cloud, the proxy. */
    static String directPeer(RestRequest request) {
        if (request.getHttpChannel() != null && request.getHttpChannel().getRemoteAddress() instanceof InetSocketAddress a) {
            return a.getAddress().getHostAddress();
        }
        return null;
    }
}
