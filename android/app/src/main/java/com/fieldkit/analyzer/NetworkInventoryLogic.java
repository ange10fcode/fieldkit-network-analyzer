package com.fieldkit.analyzer;

import java.util.Locale;

/** Android-independent rules for naming links and calculating truthful address suggestions. */
public final class NetworkInventoryLogic {
    private NetworkInventoryLogic() { }

    /** A VPN can also advertise its Wi-Fi/cellular underlay: VPN identity must win. */
    public static String kind(boolean vpn, boolean wifi, boolean cellular, boolean ethernet, boolean bluetooth) {
        if (vpn) return "VPN";
        if (wifi) return "Wi-Fi";
        if (ethernet) return "Ethernet";
        if (cellular) return "Cellular";
        if (bluetooth) return "Bluetooth";
        return "Other";
    }

    /** Interface names are only descriptive hints, never proof of routing or VPN ownership. */
    public static String interfaceKind(String name) {
        String n = name == null ? "" : name.toLowerCase(Locale.US);
        if (n.startsWith("tun") || n.startsWith("tap") || n.startsWith("tailscale") ||
                n.startsWith("wg") || n.startsWith("ipsec")) return "VPN";
        if (n.startsWith("wlan") || n.startsWith("wifi")) return "Wi-Fi";
        if (n.startsWith("rmnet") || n.startsWith("v4-rmnet") || n.startsWith("ccmni") ||
                n.startsWith("pdp") || n.startsWith("wwan") || n.startsWith("ccinet")) return "Cellular";
        if (n.startsWith("eth") || n.startsWith("en") || n.startsWith("usb")) return "Ethernet";
        return "Other";
    }

    /** A /32 stays a /32; never invent a VPN peer subnet or broaden a cellular prefix. */
    public static String ipv4Range(String cidr) {
        if (cidr == null) return "";
        String[] fields = cidr.split("/", -1);
        if (fields.length != 2) return "";
        try {
            int prefix = Integer.parseInt(fields[1]);
            if (prefix < 0 || prefix > 32) return "";
            String[] octets = fields[0].split("\\.", -1);
            if (octets.length != 4) return "";
            long address = 0;
            for (String octet : octets) {
                if (!octet.matches("[0-9]{1,3}")) return "";
                int value = Integer.parseInt(octet);
                if (value > 255) return "";
                address = (address << 8) | value;
            }
            long mask = prefix == 0 ? 0 : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
            long network = address & mask;
            return ((network >>> 24) & 255) + "." + ((network >>> 16) & 255) + "." +
                    ((network >>> 8) & 255) + "." + (network & 255) + "/" + prefix;
        } catch (NumberFormatException ignored) { return ""; }
    }

    public static String addressKey(String interfaceName, String address) {
        String raw = address == null ? "" : address;
        int scope = raw.indexOf('%');
        if (scope >= 0) raw = raw.substring(0, scope);
        return (interfaceName == null ? "" : interfaceName) + "|" + raw.toLowerCase(Locale.US);
    }

    public static int kindRank(String kind) {
        if ("Wi-Fi".equals(kind)) return 0;
        if ("Ethernet".equals(kind)) return 1;
        if ("Cellular".equals(kind)) return 2;
        if ("VPN".equals(kind)) return 3;
        return 4;
    }

    public static int preferredLanIndex(String[] kinds, boolean[] hasIpv4, boolean[] defaults) {
        if (kinds.length != hasIpv4.length || kinds.length != defaults.length)
            throw new IllegalArgumentException("Connection arrays must have equal lengths");
        // Never interpret a VPN's Wi-Fi underlay capability as a physical Wi-Fi link.
        for (String wanted : new String[]{"Wi-Fi", "Ethernet"})
            for (int i = 0; i < kinds.length; i++) if (wanted.equals(kinds[i]) && hasIpv4[i]) return i;
        for (int i = 0; i < kinds.length; i++) if (defaults[i] && hasIpv4[i]) return i;
        for (int i = 0; i < kinds.length; i++) if (hasIpv4[i]) return i;
        return -1;
    }
}
