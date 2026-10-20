package com.fieldkit.analyzer;

/** Plain JVM regression checks for manual versus detected LAN target selection. */
public final class UiStateTests {
    private static int checks;
    private interface Action { void run(); }

    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
    private static void equal(String expected, String actual, String message) {
        check(expected.equals(actual), message + ": expected " + expected + ", got " + actual);
    }
    private static void rejects(Action action, String message) {
        try { action.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError(message);
    }

    public static void main(String[] args) {
        // A Wi-Fi / Ethernet switch must never silently replace a chosen manual
        // target. Unused manual fields may also contain unfinished edits.
        String[] detectedNetworks = { "192.168.1.0/24", "172.16.4.0/24", "", null, "10.0.0.0/8" };
        for (String detected : detectedNetworks) {
            equal("10.20.30.1-10.20.30.254",
                    LanSelection.resolve(LanSelection.CIDR, detected, "10.20.30.99/24", "draft", "", ""),
                    "CIDR survives connectivity change or oversized detected network");
            equal("10.20.30.8-10.20.30.24",
                    LanSelection.resolve(LanSelection.RANGE, detected, "draft", "10.20.30.8", "10.20.30.24", ""),
                    "Explicit endpoints survive connectivity change");
            equal("10.20.30.8",
                    LanSelection.resolve(LanSelection.HOST, detected, "draft", "", "draft", "10.20.30.8"),
                    "Single host survives connectivity change");
        }
        equal("192.168.1.1-192.168.1.254",
                LanSelection.resolve(LanSelection.AUTO, "192.168.1.0/24", "draft", "draft", "draft", "draft"),
                "Auto uses current detected subnet despite manual drafts");
        equal("172.16.4.1-172.16.4.254",
                LanSelection.resolve(LanSelection.AUTO, "172.16.4.0/24", "192.168.1.0/24", "", "", ""),
                "Auto follows a new subnet instead of reusing manual input");
        rejects(() -> LanSelection.resolve(LanSelection.AUTO, "", "192.168.1.0/24", "", "", ""),
                "Auto does not silently reuse a stale manual subnet while disconnected");
        try {
            LanSelection.resolve(LanSelection.AUTO, null, "", "", "", "");
            throw new AssertionError("Missing detection must fail");
        } catch (IllegalArgumentException expected) {
            check(expected.getMessage().contains("manually"), "Missing subnet error offers manual targeting");
        }

        equal("192.0.2.10-192.0.2.11", LanSelection.resolve(LanSelection.CIDR, "", "192.0.2.11/31", "", "", ""), "/31 retains both hosts");
        equal("192.0.2.11", LanSelection.resolve(LanSelection.CIDR, "", "192.0.2.11/32", "", "", ""), "/32 stays one host");
        equal("255.255.255.255", LanSelection.resolve(LanSelection.HOST, "", "", "", "", "255.255.255.255"), "Unsigned IPv4 upper boundary");
        equal("0.0.0.0", LanSelection.resolve(LanSelection.HOST, "", "", "", "", "0.0.0.0"), "IPv4 lower boundary");
        equal("192.168.1.1-192.168.1.254", LanSelection.resolve(LanSelection.CIDR, "", " 192.168.1.88 / 24 ", "", "", ""), "Trim pasted CIDR spacing");
        equal("10.0.0.1-10.0.0.3", LanSelection.resolve(LanSelection.RANGE, "", "", " 010.000.000.001 ", " 10.0.0.3 ", ""), "Normalize range addresses");
        equal("10.0.0.1", LanSelection.resolve(LanSelection.RANGE, "", "", "10.0.0.1", "10.0.0.1", ""), "Equal explicit endpoints scan one host");
        equal("10.0.0.0-10.0.15.255", LanSelection.resolve(LanSelection.RANGE, "", "", "10.0.0.0", "10.0.15.255", ""), "Allow maximum 4096 explicit addresses");

        rejects(() -> LanSelection.resolve(LanSelection.CIDR, "192.168.1.0/24", "", "", "", ""), "Blank CIDR never falls back to automatic");
        rejects(() -> LanSelection.resolve(LanSelection.CIDR, "", "192.168.1.2", "", "", ""), "CIDR requires a prefix");
        rejects(() -> LanSelection.resolve(LanSelection.CIDR, "", "192.168.1.0/33", "", "", ""), "Reject prefix overflow");
        rejects(() -> LanSelection.resolve(LanSelection.CIDR, "", "192.168.1.0/24/32", "", "", ""), "Reject multiple prefixes");
        rejects(() -> LanSelection.resolve(LanSelection.CIDR, "", "192.168.1.1-192.168.1.2/24", "", "", ""), "Reject range inside CIDR field");
        rejects(() -> LanSelection.resolve(LanSelection.RANGE, "192.168.1.0/24", "", "10.0.0.1", "", ""), "Range requires end despite detected network");
        rejects(() -> LanSelection.resolve(LanSelection.RANGE, "", "", "", "10.0.0.5", ""), "Range requires start");
        rejects(() -> LanSelection.resolve(LanSelection.RANGE, "", "", "10.0.0.5", "10.0.0.1", ""), "Reject reversed range");
        rejects(() -> LanSelection.resolve(LanSelection.RANGE, "", "", "10.0.0.1/24", "10.0.0.5", ""), "Start is an address rather than CIDR");
        rejects(() -> LanSelection.resolve(LanSelection.RANGE, "", "", "10.0.0.1", "10.0.0.2-10.0.0.5", ""), "End is one address");
        rejects(() -> LanSelection.resolve(LanSelection.HOST, "192.168.1.0/24", "", "", "", null), "Blank host never falls back to automatic");
        rejects(() -> LanSelection.resolve(LanSelection.HOST, "", "", "", "", "example.com"), "Host is DNS-free IPv4");
        rejects(() -> LanSelection.resolve(LanSelection.HOST, "", "", "", "", "192.168.1.1/32"), "Host rejects a CIDR expression");
        rejects(() -> LanSelection.resolve(LanSelection.HOST, "", "", "", "", "10.0.0.256"), "Reject address overflow");
        rejects(() -> LanSelection.resolve(LanSelection.HOST, "", "", "", "", "2001:db8::1"), "Reject IPv6 in IPv4 LAN scan");
        rejects(() -> LanSelection.resolve(LanSelection.RANGE, "", "", "10.0.0.0", "10.0.16.0", ""), "Reject 4097-address range");
        rejects(() -> LanSelection.resolve(LanSelection.CIDR, "", "10.0.0.0/19", "", "", ""), "Reject oversized manual subnet");
        rejects(() -> LanSelection.resolve(LanSelection.AUTO, "10.0.0.0/8", "10.0.0.0/24", "", "", ""), "Auto does not silently narrow oversized subnet");
        rejects(() -> LanSelection.resolve("Unknown", "192.168.1.0/24", "", "", "", ""), "Reject unknown mode without falling back");

        // Feeding normalized CIDR output to the scanner must not discard its
        // first and last usable hosts a second time.
        long[] usable = Ip.range(LanSelection.resolve(LanSelection.CIDR, "", "192.168.1.0/24", "", "", ""));
        check(usable[1] - usable[0] + 1 == 254, "Resolved CIDR retains all 254 usable /24 addresses");
        System.out.println("UiStateTests: " + checks + " checks passed (manual/auto selection and strict IPv4 scan bounds).");
    }
}
