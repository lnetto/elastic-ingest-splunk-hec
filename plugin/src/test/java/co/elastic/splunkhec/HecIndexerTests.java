package co.elastic.splunkhec;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.SecureSettings;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.xpack.core.security.action.user.AuthenticateResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.user.User;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The indexing path against a fake client: which bulks are sent, and what the sender is told. */
class HecIndexerTests {

    static final HecIndexer.Request REQ = new HecIndexer.Request("id", 0, "node", "10.0.0.1", "10.0.0.1", null, "event", null, null,
        new HecService.Caller("sha", "t"));

    /** A client that answers authenticate with {@code who} and each bulk with {@code answer}, recording the bulks. */
    static final class FakeClient {
        final List<BulkRequest> bulks = new ArrayList<>();
        Authentication who;
        Function<BulkRequest, BulkResponse> answer = FakeClient::allIndexed;

        Client client() {
            return (Client) Proxy.newProxyInstance(Client.class.getClassLoader(), new Class<?>[] { Client.class }, (proxy, m, args) -> {
                if (m.getName().equals("bulk") && args.length == 2) {
                    BulkRequest b = (BulkRequest) args[0];
                    bulks.add(b);
                    @SuppressWarnings("unchecked")
                    ActionListener<BulkResponse> l = (ActionListener<BulkResponse>) args[1];
                    l.onResponse(answer.apply(b));
                    return null;
                }
                if (m.getName().equals("execute") && args.length == 3) {
                    @SuppressWarnings("unchecked")
                    ActionListener<AuthenticateResponse> l = (ActionListener<AuthenticateResponse>) args[2];
                    l.onResponse(new AuthenticateResponse(who, false));
                    return null;
                }
                throw new UnsupportedOperationException(m.getName());
            });
        }

        static BulkResponse allIndexed(BulkRequest b) {
            return respond(b, n -> null);
        }

        /** {@code status} gives each item's failure status, or null for success. */
        static BulkResponse respond(BulkRequest b, Function<Integer, RestStatus> status) {
            BulkItemResponse[] items = new BulkItemResponse[b.numberOfActions()];
            for (int n = 0; n < items.length; n++) {
                RestStatus st = status.apply(n);
                items[n] = st == null
                    ? BulkItemResponse.success(n, DocWriteRequest.OpType.CREATE,
                        new IndexResponse(new ShardId(new Index("x", "u"), 0), "d" + n, 1, 1, 1, true))
                    : BulkItemResponse.failure(n, DocWriteRequest.OpType.CREATE,
                        new BulkItemResponse.Failure("x", "d" + n, new IllegalArgumentException("refused"), st));
            }
            return new BulkResponse(items, 1);
        }
    }

    /** The keystore with one string in it. */
    record OneSecret(String name, String value) implements SecureSettings {
        public boolean isLoaded() {
            return true;
        }

        public Set<String> getSettingNames() {
            return Set.of(name);
        }

        public SecureString getString(String setting) {
            return new SecureString(value.toCharArray());
        }

        public InputStream getFile(String setting) {
            throw new UnsupportedOperationException();
        }

        public byte[] getSHA256Digest(String setting) {
            throw new UnsupportedOperationException();
        }

        public void close() {}

        public void writeTo(StreamOutput out) {
            throw new UnsupportedOperationException();
        }
    }

    static HecIndexer indexer(FakeClient fake, boolean withKey) {
        Settings.Builder s = Settings.builder();
        if (withKey) {
            s.setSecureSettings(new OneSecret("splunk_hec.api_key", "a2V5OnNlY3JldA=="));
        }
        return new HecIndexer(fake.client(), new ThreadContext(Settings.EMPTY), s.build());
    }

    static List<HecParser.HecEvent> events(int n) {
        List<HecParser.HecEvent> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(new HecParser.HecEvent("e" + i, null, null, null, "st", null, Map.of()));
        }
        return out;
    }

    static HecIndexer.Result run(HecIndexer ix, int n) {
        AtomicReference<HecIndexer.Result> out = new AtomicReference<>();
        ix.index(events(n), REQ, ActionListener.wrap(out::set, e -> { throw new AssertionError(e); }));
        return out.get();
    }

    static Authentication apiKey() {
        return Authentication.newApiKeyAuthentication(AuthenticationResult.success(new User("hec"),
            Map.of("_security_api_key_id", "k1", "_security_api_key_name", "splunk-hec")), "node");
    }

    @Test
    void keyThatIsNotAnApiKeyIndexesNothing() {
        FakeClient fake = new FakeClient();
        fake.who = Authentication.newRealmAuthentication(new User("elastic"), new Authentication.RealmRef("native", "native", "node"));
        HecIndexer.Result r = run(indexer(fake, true), 10);
        assertTrue(r.retryable());
        assertEquals(0, fake.bulks.size());
    }

    @Test
    void noKeyIndexesNothingAndIsNotReady() {
        FakeClient fake = new FakeClient();
        HecIndexer ix = indexer(fake, false);
        assertFalse(ix.ready());
        assertTrue(run(ix, 10).retryable());
        assertEquals(0, fake.bulks.size());
    }

    @Test
    void largeBatchIsSentInSlices() {
        FakeClient fake = new FakeClient();
        fake.who = apiKey();
        HecIndexer ix = indexer(fake, true);
        assertTrue(ix.ready());
        HecIndexer.Result r = run(ix, 2500);
        assertEquals(List.of(2000, 500), fake.bulks.stream().map(BulkRequest::numberOfActions).toList());
        assertEquals(new HecIndexer.Result(2500, 0, false, -1), r);
        assertEquals("logs-splunk.hec-default", fake.bulks.get(0).requests().get(0).index());
    }

    @Test
    void backPressureStopsTheBatch() {
        FakeClient fake = new FakeClient();
        fake.who = apiKey();
        fake.answer = b -> FakeClient.respond(b, n -> n == 7 ? RestStatus.TOO_MANY_REQUESTS : null);
        HecIndexer.Result r = run(indexer(fake, true), 2500);
        assertEquals(1, fake.bulks.size());   // no second slice: the sender resends all of it
        assertTrue(r.retryable());
        assertEquals(1 + 500, r.failed());
    }

    @Test
    void refusedEventIsReportedNotSuccess() {
        FakeClient fake = new FakeClient();
        fake.who = apiKey();
        // second slice, its 4th item: event 2003
        fake.answer = b -> FakeClient.respond(b, n -> fake.bulks.size() == 2 && n == 3 ? RestStatus.BAD_REQUEST : null);
        HecIndexer.Result r = run(indexer(fake, true), 2500);
        assertEquals(2, fake.bulks.size());
        assertFalse(r.retryable());
        assertEquals(1, r.failed());
        assertEquals(2003, r.firstFailed());
    }
}
