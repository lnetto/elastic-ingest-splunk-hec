package co.elastic.splunkhec;

import org.elasticsearch.client.internal.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.features.FeatureService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.ClientHelper;
import org.elasticsearch.xpack.core.template.YamlTemplateRegistry;

/**
 * Installs the index template for the default target, logs-splunk.hec-*, the way Elasticsearch's own inputs
 * (Prometheus remote write, OTLP) do: the elected master puts it, and puts it again when resources.yaml's
 * version goes up. It also installs logs-splunk.hec@default-pipeline, the streams' default pipeline (set in logs-splunk.hec@settings),
 * which calls the logs-splunk.hec@custom ingest pipeline. The template includes logs@custom and logs-splunk.hec@custom, the
 * component templates that are yours: settings and mappings for these streams go there.
 */
final class HecTemplateRegistry extends YamlTemplateRegistry {

    HecTemplateRegistry(
        Settings nodeSettings,
        ClusterService clusterService,
        ThreadPool threadPool,
        Client client,
        NamedXContentRegistry xContentRegistry,
        FeatureService featureService
    ) {
        super(nodeSettings, clusterService, threadPool, client, xContentRegistry, featureService);
    }

    @Override
    public void initialize() {
        super.initialize();
        clusterService.getClusterSettings().addSettingsUpdateConsumer(HecSettings.TEMPLATES_ENABLED, this::setEnabled);
    }

    @Override
    protected String getOrigin() {
        return ClientHelper.STACK_ORIGIN;
    }

    @Override
    public String getName() {
        return "ingest-splunk-hec";
    }

    @Override
    protected String getVersionProperty() {
        return "splunk_hec.template.version";
    }
}
