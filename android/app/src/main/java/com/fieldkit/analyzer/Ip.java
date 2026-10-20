package com.fieldkit.analyzer;

import java.util.Set;
import java.util.TreeSet;

/** Strict, DNS-free IPv4 calculations and bounded user input parsing. */
public final class Ip {
    private Ip() {}
    public static long parse(String value) {
        String s = value == null ? "" : value.trim();
        String[] p = s.split("\\.", -1);
        if (p.length != 4) throw new IllegalArgumentException("Enter an IPv4 address, for example 192.168.1.1.");
        long n = 0;
        for (String a : p) {
            if (!a.matches("[0-9]{1,3}")) throw new IllegalArgumentException("Invalid IPv4 address: " + s);
            int v = Integer.parseInt(a);
            if (v > 255) throw new IllegalArgumentException("IPv4 octets must be 0–255: " + s);
            n = (n << 8) | v;
        }
        return n;
    }
    public static String format(long n) {
        if (n < 0 || n > 0xffffffffL) throw new IllegalArgumentException("IPv4 address outside 32-bit range.");
        return ((n >>> 24) & 255) + "." + ((n >>> 16) & 255) + "." + ((n >>> 8) & 255) + "." + (n & 255);
    }
    public static long mask(int prefix) {
        if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("IPv4 prefix must be 0–32.");
        return prefix == 0 ? 0 : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
    }
    public static String network(String address, int prefix) { return format(parse(address) & mask(prefix)); }
    /** CIDRs omit network/broadcast for /0–/30; /31 and /32 retain all addresses. */
    public static long[] range(String text) {
        if (text == null || text.trim().isEmpty()) throw new IllegalArgumentException("Enter an IPv4 address, start–end range, or CIDR.");
        String s = text.trim().replace('\u2013', '-');
        long start, end;
        if (s.contains("/")) {
            String[] p = s.split("/", -1);
            if (p.length != 2 || !p[1].matches("[0-9]{1,2}")) throw new IllegalArgumentException("Invalid CIDR prefix.");
            int prefix = Integer.parseInt(p[1]);
            long m = mask(prefix), n = parse(p[0]) & m;
            start = n; end = n | (0xffffffffL ^ m);
            if (prefix < 31) { start++; end--; }
        } else if (s.contains("-")) {
            String[] p = s.split("-", -1);
            if (p.length != 2) throw new IllegalArgumentException("Use start-address - end-address.");
            start = parse(p[0]); end = parse(p[1]);
        } else start = end = parse(s);
        if (end < start) throw new IllegalArgumentException("The end address must be at or after the start address.");
        if (end - start + 1 > 4096) throw new IllegalArgumentException("A LAN scan is limited to 4,096 addresses. Choose a smaller range.");
        return new long[] { start, end };
    }
    public static byte[] magicPacket(String mac) {
        String s = mac == null ? "" : mac.trim().replace(":", "").replace("-", "").replace(".", "");
        if (!s.matches("[0-9a-fA-F]{12}")) throw new IllegalArgumentException("Enter a six-byte MAC address, for example AA:BB:CC:DD:EE:FF.");
        byte[] packet = new byte[102], address = new byte[6];
        for (int i = 0; i < 6; i++) { packet[i] = (byte) 0xff; address[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16); }
        for (int i = 0; i < 16; i++) System.arraycopy(address, 0, packet, 6 + i * 6, 6);
        return packet;
    }
    public static int[] ports(String input) {
        if (input == null || input.trim().isEmpty()) throw new IllegalArgumentException("Enter ports such as 22,80,443 or 1-1024.");
        Set<Integer> values = new TreeSet<>();
        for (String token : input.trim().split("[,;\\s]+")) {
            String[] p = token.split("-", -1);
            if (p.length > 2 || !p[0].matches("[0-9]{1,5}") || (p.length == 2 && !p[1].matches("[0-9]{1,5}"))) throw new IllegalArgumentException("Invalid port entry: " + token);
            int a = Integer.parseInt(p[0]), b = p.length == 2 ? Integer.parseInt(p[1]) : a;
            if (a < 1 || b > 65535 || b < a) throw new IllegalArgumentException("Ports must be 1–65535 with ascending ranges.");
            for (int v = a; v <= b; v++) values.add(v);
        }
        int[] out = new int[values.size()]; int i = 0;
        for (int n : values) out[i++] = n;
        return out;
    }
}
