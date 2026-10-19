package co.elastic.splunkhec;

import org.elasticsearch.common.settings.SecureSetting;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;

import java.util.List;
import java.util.regex.Pattern;

/** The plugin's settings: allowed tokens, where events go, and the key it writes with. */
public final class HecSettings {

    private HecSettings() {}

    /** Allowed HEC tokens as SHA-256 fingerprints, optionally named: "app-team=<sha256 hex>". */
    public static final Setting<List<String>> TOKEN_SHA256 = Setting.stringListSetting(
        "splunk_hec.token_sha256",
        Property.NodeScope,
        Property.Dynamic
    );

    /** What Elasticsearch accepts as an index or data stream name, once the placeholders are filled in
     * (declared before TARGET, whose default is validated when it is created). */
    private static final Pattern INDEX_NAME = Pattern.compile("[a-z0-9][a-z0-9_.+-]{0,199}");

    /**
     * Target index / data stream; {index} and {sourcetype} are replaced with each event's values. One stream by
     * default: with a placeholder, every new value a sender makes up is a new data stream, with its own shards.
     */
    public static final Setting<String> TARGET = Setting.simpleString(
        "splunk_hec.target",
        "logs-splunk.hec-default",
        HecSettings::validateTarget,
        Property.NodeScope,
        Property.Dynamic
    );

    /**
     * Rejects a target no event could be written to: every bulk item would fail without retry, and the
     * sender would still be told its events were indexed.
     */
    static void validateTarget(String target) {
        String filled = target.replace("{index}", "x").replace("{sourcetype}", "x");
        if (INDEX_NAME.matcher(filled).matches() == false || filled.equals(".") || filled.equals("..")) {
            throw new IllegalArgumentException("splunk_hec.target [" + target + "] is not a valid index or data stream name: lowercase "
                + "letters, digits, '_', '.', '+', '-', not starting with '_', '.', '+' or '-'; placeholders {index} and {sourcetype}");
        }
    }

    /** Accept ?token=… in the URL (Splunk's allowQueryStringAuth). Off: tokens in URLs end up in logs. */
    public static final Setting<Boolean> QUERY_STRING_AUTH = Setting.boolSetting(
        "splunk_hec.query_string_auth",
        false,
        Property.NodeScope,
        Property.Dynamic
    );

    /**
     * Indexer acknowledgment (Splunk's per-token useACK): with a channel, successes carry an ackId and
     * /services/collector/ack answers. Every acked id is already indexed: a 200 is only sent after the bulk.
     */
    public static final Setting<Boolean> ACK = Setting.boolSetting("splunk_hec.ack", false, Property.NodeScope, Property.Dynamic);

    /** Encoded Elasticsearch API key the plugin writes with (keystore). */
    public static final Setting<SecureString> API_KEY = SecureSetting.secureString("splunk_hec.api_key", null);

    /**
     * Install and keep up to date the index template for logs-splunk.hec-* (HecTemplateRegistry). Turning it off stops
     * that; a template already installed stays.
     */
    public static final Setting<Boolean> TEMPLATES_ENABLED = Setting.boolSetting(
        "splunk_hec.templates.enabled",
        true,
        Property.NodeScope,
        Property.Dynamic
    );

    /**
     * What /event documents hold. "keep": each event's JSON object exactly as sent, in message; an ingest pipeline
     * unwraps it (time, event, host, source, sourcetype, index, fields). "unwrap": the plugin does that itself, and
     * message is the event alone. /raw is the same either way.
     */
    public static final Setting<String> ENVELOPE = oneOf("splunk_hec.envelope", "keep", "unwrap");

    /**
     * What the plugin adds about the request. "minimal": the token's name, the endpoint, the channel and the Splunk
     * metadata. "full" adds splunk.request.*, splunk.token_sha256, network.forwarded_ip, user_agent.original and
     * event.ingested; indexing is slower, since those fields cost about as much as a small event.
     */
    public static final Setting<String> METADATA = oneOf("splunk_hec.metadata", "minimal", "full");

    /** A dynamic setting that takes one of {@code values}; the first is the default. */
    private static Setting<String> oneOf(String key, String... values) {
        List<String> allowed = List.of(values);
        return new Setting<>(key, values[0], v -> {
            if (allowed.contains(v) == false) {
                throw new IllegalArgumentException(key + " must be one of " + allowed + ", not [" + v + "]");
            }
            return v;
        }, Property.NodeScope, Property.Dynamic);
    }

    public static List<Setting<?>> all() {
        return List.of(TOKEN_SHA256, TARGET, QUERY_STRING_AUTH, ACK, API_KEY, TEMPLATES_ENABLED, ENVELOPE, METADATA);
    }
}
