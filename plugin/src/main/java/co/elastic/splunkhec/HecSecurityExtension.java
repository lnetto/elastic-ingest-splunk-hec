package co.elastic.splunkhec;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.RoleRetrievalResult;

import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

/**
 * Defines the role {@code splunk_hec_anonymous} with no privileges at all. HEC senders authenticate with
 * {@code Authorization: Splunk <token>}, which no Elasticsearch realm understands, so they arrive as the
 * anonymous user (xpack.security.authc.anonymous.roles includes splunk_hec_anonymous) and the plugin
 * checks the token itself, then indexes as its own API key.
 */
public final class HecSecurityExtension implements SecurityExtension {

    static final String ANONYMOUS_ROLE = "splunk_hec_anonymous";

    private static final RoleDescriptor EMPTY = new RoleDescriptor(ANONYMOUS_ROLE, new String[0], new RoleDescriptor.IndicesPrivileges[0], null);

    @Override
    public String extensionName() {
        return "splunk-hec";
    }

    @Override
    public List<BiConsumer<Set<String>, ActionListener<RoleRetrievalResult>>> getRolesProviders(SecurityComponents components) {
        return List.of((names, listener) -> listener.onResponse(RoleRetrievalResult.success(names.contains(ANONYMOUS_ROLE) ? Set.of(EMPTY) : Set.of())));
    }
}
