package co.elastic.splunkhec;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Allowed HEC tokens, from {@code splunk_hec.token_sha256}: SHA-256 fingerprints, optionally
 * named ({@code name=<sha256>}). The name becomes {@code splunk.token_name} on every event that token sends.
 */
final class TokenRegistry {

    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9_.:@-]{1,128}");

    /** Fingerprint -> name ("" when unnamed). */
    private volatile Map<String, String> allowed = Map.of();

    void set(List<String> entries) {
        validate(entries);
        Map<String, String> m = new HashMap<>();
        for (String e : entries) {
            String[] nv = split(e);
            m.put(nv[1].toLowerCase(Locale.ROOT), nv[0]);
        }
        allowed = Map.copyOf(m);
    }

    /** Rejects a bad PUT _cluster/settings up front. */
    static void validate(List<String> entries) {
        for (String e : entries) {
            String[] nv = split(e);
            if (SHA256.matcher(nv[1].toLowerCase(Locale.ROOT)).matches() == false) {
                throw new IllegalArgumentException("splunk_hec.token_sha256: [" + nv[1] + "] is not a SHA-256 hex digest");
            }
        }
    }

    /** "name=value" or "value" -> {name or "", value}. */
    private static String[] split(String entry) {
        String e = entry.trim();
        int eq = e.indexOf('=');
        if (eq <= 0) {
            return new String[] { "", e };
        }
        String name = e.substring(0, eq).trim();
        if (NAME.matcher(name).matches() == false) {
            throw new IllegalArgumentException("splunk_hec token name [" + name + "] must match " + NAME.pattern());
        }
        return new String[] { name, e.substring(eq + 1).trim() };
    }

    /** Name of the matching token ("" if unnamed), or null if the token is not allowed. */
    String match(String token) {
        return token == null || token.isEmpty() ? null : allowed.get(HecService.sha256(token));
    }
}
