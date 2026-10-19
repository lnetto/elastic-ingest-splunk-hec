package co.elastic.splunkhec;

import org.apache.lucene.util.SetOnce;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.features.NodeFeature;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.plugins.ReloadablePlugin;
import org.elasticsearch.rest.RestHandler;

import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Splunk HTTP Event Collector endpoints on Elasticsearch: {@code /services/collector} (event, batched
 * JSON), {@code /services/collector/raw}, {@code /services/collector/health} and {@code /services/collector/ack}.
 */
public class SplunkHecPlugin extends Plugin implements ActionPlugin, ReloadablePlugin {

    private final SetOnce<HecService> service = new SetOnce<>();
    private final SetOnce<HecIndexer> indexer = new SetOnce<>();
    private final SetOnce<HecTemplateRegistry> templates = new SetOnce<>();

    @Override
    public List<Setting<?>> getSettings() {
        return HecSettings.all();
    }

    @Override
    public Collection<?> createComponents(PluginServices services) {
        Settings settings = services.environment().settings();
        HecIndexer indexer = new HecIndexer(services.client(), services.threadPool().getThreadContext(), settings);
        HecService svc = new HecService(indexer, settings.get("node.name"), HecSettings.QUERY_STRING_AUTH.get(settings));
        svc.tokens.set(HecSettings.TOKEN_SHA256.get(settings));
        svc.setAck(HecSettings.ACK.get(settings));
        svc.setEnvelope(HecSettings.ENVELOPE.get(settings));
        svc.memory = services.indicesService().getCircuitBreakerService().getBreaker(CircuitBreaker.REQUEST);
        ClusterSettings cs = services.clusterService().getClusterSettings();
        cs.addSettingsUpdateConsumer(HecSettings.TARGET, indexer::setTarget);
        cs.addSettingsUpdateConsumer(HecSettings.TOKEN_SHA256, svc.tokens::set, TokenRegistry::validate);
        cs.addSettingsUpdateConsumer(HecSettings.QUERY_STRING_AUTH, svc::setQueryStringAuth);
        cs.addSettingsUpdateConsumer(HecSettings.ACK, svc::setAck);
        cs.addSettingsUpdateConsumer(HecSettings.ENVELOPE, svc::setEnvelope);
        cs.addSettingsUpdateConsumer(HecSettings.METADATA, indexer::setMetadata);
        this.indexer.set(indexer);
        service.set(svc);
        HecTemplateRegistry registry = new HecTemplateRegistry(settings, services.clusterService(), services.threadPool(),
            services.client(), services.xContentRegistry(), services.featureService());
        registry.setEnabled(HecSettings.TEMPLATES_ENABLED.get(settings));
        registry.initialize();
        templates.set(registry);
        return List.of();
    }

    @Override
    public void close() {
        if (templates.get() != null) {
            templates.get().close();
        }
    }

    @Override
    public Collection<RestHandler> getRestHandlers(
        RestHandlersServices restHandlersServices,
        Supplier<DiscoveryNodes> nodesInCluster,
        Predicate<NodeFeature> clusterSupportsFeature
    ) {
        return List.of(new HecRestHandler(service::get));
    }

    /** POST _nodes/reload_secure_settings: picks up a new or rotated splunk_hec.api_key without a restart. */
    @Override
    public void reload(Settings settings) {
        HecIndexer ix = indexer.get();
        if (ix != null) {
            ix.setApiKey(settings);
        }
    }
}
