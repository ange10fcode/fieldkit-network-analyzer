package com.fieldkit.analyzer;

import java.util.HashSet;
import java.util.Set;

/** Regression fixtures for VPN overlays, retained physical prefixes, and honest scan suggestions. */
public final class NetworkInventoryTests {
    private static int assertions;
    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
    public static void main(String[] args) {
        String vpn = NetworkInventoryLogic.kind(true, true, true, false, false);
        String wifi = NetworkInventoryLogic.kind(false, true, false, false, false);
        String cellular = NetworkInventoryLogic.kind(false, false, true, false, false);
        check(vpn.equals("VPN"), "VPN with physical underlay capabilities retains VPN identity");
        check(wifi.equals("Wi-Fi"), "Physical Wi-Fi retains Wi-Fi identity");
        check(cellular.equals("Cellular"), "Physical cellular retains cellular identity");
        // Android supplies three independent handles, with a VPN carrying the per-app default.
        String[] kinds = {vpn, cellular, wifi};
        String[] addresses = {"100.90.80.70/32", "10.123.45.6/30", "192.168.12.34/24"};
        boolean[] hasIpv4 = {true, true, true}, defaults = {true, false, false};
        int picked = NetworkInventoryLogic.preferredLanIndex(kinds, hasIpv4, defaults);
        check(picked == 2, "LAN default chooses physical Wi-Fi despite default VPN with Wi-Fi capability");
        check(NetworkInventoryLogic.ipv4Range(addresses[picked]).equals("192.168.12.0/24"), "Wi-Fi suggestion uses its own prefix");
        check(NetworkInventoryLogic.ipv4Range(addresses[0]).equals("100.90.80.70/32"), "VPN /32 is never broadened to invented peers");
        check(NetworkInventoryLogic.ipv4Range(addresses[1]).equals("10.123.45.4/30"), "Cellular /30 retains provider prefix");
        check(NetworkInventoryLogic.preferredLanIndex(new String[]{vpn, "Ethernet"}, new boolean[]{true,true}, new boolean[]{true,false}) == 1,
                "Physical Ethernet also outranks default VPN");
        check(NetworkInventoryLogic.preferredLanIndex(new String[]{vpn, wifi}, new boolean[]{true,false}, new boolean[]{true,false}) == 0,
                "IPv6-only Wi-Fi does not fabricate an IPv4 suggestion");
        check(NetworkInventoryLogic.preferredLanIndex(new String[]{wifi,cellular}, new boolean[]{false,false}, new boolean[]{true,false}) == -1,
                "No IPv4 produces no fake subnet");
        check(NetworkInventoryLogic.ipv4Range("192.0.2.3/31").equals("192.0.2.2/31"), "/31 is retained");
        check(NetworkInventoryLogic.ipv4Range("192.0.2.3/0").equals("0.0.0.0/0"), "A broad prefix is reported honestly, scanner bounds handle it");
        check(NetworkInventoryLogic.ipv4Range("999.0.0.1/24").isEmpty(), "Invalid IPv4 rejected");
        check(NetworkInventoryLogic.ipv4Range("192.0.2.1/33").isEmpty(), "Invalid prefix rejected");
        check(NetworkInventoryLogic.ipv4Range("2001:db8::1/64").isEmpty(), "IPv6 is never converted into an IPv4 scan range");
        Set<String> seen = new HashSet<>();
        seen.add(NetworkInventoryLogic.addressKey("wlan0", "192.168.12.34"));
        check(seen.contains(NetworkInventoryLogic.addressKey("wlan0", "192.168.12.34")), "Fallback excludes an already reported interface/address");
        check(!seen.contains(NetworkInventoryLogic.addressKey("tun0", "192.168.12.34")), "Same address on a distinct interface is retained");
        check(NetworkInventoryLogic.addressKey("wlan0", "fe80::ab%wlan0").equals(NetworkInventoryLogic.addressKey("wlan0", "fe80::ab%7")),
                "Equivalent IPv6 scope labels deduplicate per interface");
        check(NetworkInventoryLogic.interfaceKind("rmnet_data1").equals("Cellular"), "Cellular interface hint recognized");
        check(NetworkInventoryLogic.interfaceKind("tun0").equals("VPN"), "Tunnel interface hint recognized");
        check(NetworkInventoryLogic.interfaceKind("mystery0").equals("Other"), "Unknown interfaces do not acquire invented transport");
        check(NetworkInventoryLogic.kind(false,false,true,false,false).equals("Cellular"), "CGNAT ranges never determine VPN ownership");
        boolean rejected = false;
        try { NetworkInventoryLogic.preferredLanIndex(new String[]{wifi}, new boolean[0], new boolean[0]); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check(rejected, "Mismatched snapshot arrays rejected");
        System.out.println("NetworkInventoryTests: " + assertions + " assertions passed");
    }
}
