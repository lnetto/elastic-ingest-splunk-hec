package co.elastic.splunkhec;

import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.xcontent.XContentType;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** What the installed templates map. */
class TemplateTests {

    @Test
    @SuppressWarnings("unchecked")
    void indexedFieldsAreOneFlattenedField() throws Exception {
        // however many keys senders make up, splunk.fields is one field: it can't reach the 1,000-field limit
        Map<String, Object> t;
        try (InputStream in = getClass().getResourceAsStream("/component-templates/logs-splunk.hec@mappings.yaml")) {
            t = XContentHelper.convertToMap(XContentType.YAML.xContent(), in, true);
        }
        Map<String, Object> splunk = (Map<String, Object>) ((Map<String, Object>) ((Map<String, Object>) ((Map<String, Object>) t
            .get("template")).get("mappings")).get("properties")).get("splunk");
        Map<String, Object> fields = (Map<String, Object>) ((Map<String, Object>) splunk.get("properties")).get("fields");
        assertEquals("flattened", fields.get("type"));
    }
}
