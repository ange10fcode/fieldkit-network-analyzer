package com.fieldkit.analyzer;

/**
 * Resolves the selected LAN target without changing any saved input.
 * Detected network information is consulted only when Auto is selected.
 * This class deliberately has no Android dependencies so target selection can be
 * checked independently of connectivity callbacks and the activity lifecycle.
 */
public final class LanSelection {
    public static final String AUTO = "Auto";
    public static final String CIDR = "CIDR";
    public static final String RANGE = "Range";
    public static final String HOST = "Host";

    private LanSelection() {}

    /**
     * Returns a canonical IPv4 host or start-end range, ready for NetworkTools.lan.
     * CIDRs use Ip.range's host bounds: /31 includes both addresses and /32 one.
     * All modes share the scanner's 4,096-address limit.
     */
    public static String resolve(String mode, String detected, String cidr,
                                 String start, String end, String single) {
        if (AUTO.equals(mode)) {
            String subnet = trim(detected);
            if (subnet.isEmpty()) {
                throw new IllegalArgumentException("No local IPv4 subnet detected. Connect to a network or choose CIDR, Range, or Host to enter a target manually.");
            }
            try {
                return normalized(Ip.range(normalizeCidr(subnet)));
            } catch (IllegalArgumentException error) {
                throw new IllegalArgumentException("Cannot scan the detected subnet: " + error.getMessage()
                        + " Choose CIDR, Range, or Host for a manual target.", error);
            }
        }
        if (CIDR.equals(mode)) {
            String subnet = trim(cidr);
            if (subnet.isEmpty()) throw new IllegalArgumentException("Enter a CIDR subnet, for example 192.168.1.0/24.");
            if (!subnet.contains("/")) throw new IllegalArgumentException("CIDR requires a prefix, for example 192.168.1.0/24.");
            return normalized(Ip.range(normalizeCidr(subnet)));
        }
        if (RANGE.equals(mode)) {
            String first = trim(start), last = trim(end);
            if (first.isEmpty() || last.isEmpty()) {
                throw new IllegalArgumentException("Enter both a start IPv4 address and an end IPv4 address.");
            }
            // Parse each field independently: neither can contain another range,
            // a CIDR, a hostname, or any other implicit target expression.
            first = Ip.format(Ip.parse(first));
            last = Ip.format(Ip.parse(last));
            return normalized(Ip.range(first + "-" + last));
        }
        if (HOST.equals(mode)) {
            String host = trim(single);
            if (host.isEmpty()) throw new IllegalArgumentException("Enter a single IPv4 address, for example 192.168.1.10.");
            return normalized(Ip.range(Ip.format(Ip.parse(host))));
        }
        throw new IllegalArgumentException("Choose Auto, CIDR, Range, or Host as the LAN target mode.");
    }

    private static String trim(String value) { return value == null ? "" : value.trim(); }

    private static String normalizeCidr(String value) {
        String[] parts = value.split("/", -1);
        if (parts.length == 2) return parts[0].trim() + "/" + parts[1].trim();
        return value;
    }

    private static String normalized(long[] range) {
        String first = Ip.format(range[0]);
        return range[0] == range[1] ? first : first + "-" + Ip.format(range[1]);
    }
}
