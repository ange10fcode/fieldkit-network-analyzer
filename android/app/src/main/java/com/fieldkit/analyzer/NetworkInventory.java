package com.fieldkit.analyzer;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Separate snapshots for every Android network and any additional observable local interfaces. */
public final class NetworkInventory {
    private NetworkInventory() { }

    public static final class Connection {
        public final String id, name, kind, interfaceName;
        public final boolean defaultNetwork, observedOnly, validated, metered;
        public final int mtu;
        public final Network network;
        public final LinkProperties properties;
        public final NetworkCapabilities capabilities;
        public final String[] ipv4Cidrs, ipv6Cidrs, interfaceObservedCidrs;

        private Connection(String id, String kind, String iface, boolean isDefault, Network network,
                LinkProperties properties, NetworkCapabilities capabilities, int observedMtu, List<String> v4, List<String> v6, List<String> observedAddresses) {
            this.id = id;
            this.name = kind;
            this.kind = kind;
            this.interfaceName = iface == null ? "" : iface;
            this.defaultNetwork = isDefault;
            this.network = network;
            this.properties = properties;
            this.capabilities = capabilities;
            this.mtu = properties == null || properties.getMtu() <= 0 ? observedMtu : properties.getMtu();
            this.observedOnly = network == null;
            this.validated = capabilities != null && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
            this.metered = capabilities == null || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
            this.ipv4Cidrs = v4.toArray(new String[0]);
            this.ipv6Cidrs = v6.toArray(new String[0]);
            this.interfaceObservedCidrs = observedAddresses.toArray(new String[0]);
        }

        public String title() {
            return name + (interfaceName.isEmpty() ? "" : " · " + interfaceName) +
                    (defaultNetwork ? " · default" : "") + (observedOnly ? " · interface only" : "");
        }
        public String[] cidrs() {
            String[] all = new String[ipv4Cidrs.length + ipv6Cidrs.length];
            System.arraycopy(ipv4Cidrs, 0, all, 0, ipv4Cidrs.length);
            System.arraycopy(ipv6Cidrs, 0, all, ipv4Cidrs.length, ipv6Cidrs.length);
            return all;
        }
        public String recommendedRange() {
            for (String cidr : ipv4Cidrs) {
                String range = NetworkInventoryLogic.ipv4Range(cidr);
                if (!range.isEmpty()) return range;
            }
            return "";
        }
        public String firstIpv4() {
            return ipv4Cidrs.length == 0 ? "" : ipv4Cidrs[0].substring(0, ipv4Cidrs[0].indexOf('/'));
        }
        public String gateway() {
            if (properties != null) for (RouteInfo route : properties.getRoutes())
                if (route.isDefaultRoute() && route.hasGateway() && route.getGateway() instanceof Inet4Address)
                    return route.getGateway().getHostAddress();
            return "";
        }
        public String dnsServer() {
            return properties == null || properties.getDnsServers().isEmpty() ? "" :
                    properties.getDnsServers().get(0).getHostAddress();
        }
        public boolean canBind() { return network != null; }
        public boolean isInterfaceObservation(String cidr) {
            for (String observed : interfaceObservedCidrs) if (observed.equals(cidr)) return true;
            return observedOnly;
        }
    }

    public static List<Connection> snapshot(Context context) {
        List<Connection> result = new ArrayList<>();
        Set<String> covered = new HashSet<>();
        ConnectivityManager manager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager != null) try {
            Network active = manager.getActiveNetwork();
            for (Network network : manager.getAllNetworks()) {
                try {
                    LinkProperties properties = manager.getLinkProperties(network);
                    NetworkCapabilities caps = manager.getNetworkCapabilities(network);
                    // Each Network retains its own properties. A VPN never supplies the physical link's fields.
                    String iface = properties == null ? "" : properties.getInterfaceName();
                    List<String> v4 = new ArrayList<>(), v6 = new ArrayList<>();
                    if (properties != null) for (LinkAddress link : properties.getLinkAddresses()) {
                        addAddress(link.getAddress(), link.getPrefixLength(), v4, v6);
                        covered.add(NetworkInventoryLogic.addressKey(iface, link.getAddress().getHostAddress()));
                    }
                    String kind = caps == null ? "Other" : NetworkInventoryLogic.kind(
                            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
                            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
                            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET),
                            caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH));
                    result.add(new Connection("network:" + network.toString(), kind, iface,
                            network.equals(active), network, properties, caps, 0, v4, v6, Collections.emptyList()));
                } catch (RuntimeException ignored) { /* Network may disappear during the snapshot. */ }
            }
        } catch (RuntimeException ignored) { /* Device policies may limit network visibility. */ }

        // Useful with VPNs/OEMs that omit an underlay from getAllNetworks. These entries cannot be bound.
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces != null) while (interfaces.hasMoreElements()) {
                NetworkInterface nic = interfaces.nextElement();
                if (!nic.isUp() || nic.isLoopback()) continue;
                List<String> v4 = new ArrayList<>(), v6 = new ArrayList<>();
                for (InterfaceAddress link : nic.getInterfaceAddresses()) {
                    InetAddress address = link.getAddress();
                    if (address == null || covered.contains(NetworkInventoryLogic.addressKey(nic.getName(), address.getHostAddress()))) continue;
                    addAddress(address, link.getNetworkPrefixLength(), v4, v6);
                }
                if (!v4.isEmpty() || !v6.isEmpty()) {
                    int existing = -1;
                    for (int i = 0; i < result.size(); i++)
                        if (nic.getName().equals(result.get(i).interfaceName)) { existing = i; break; }
                    if (existing >= 0) {
                        Connection before = result.get(existing);
                        List<String> merged4 = new ArrayList<>(), merged6 = new ArrayList<>(), observed = new ArrayList<>();
                        Collections.addAll(merged4, before.ipv4Cidrs);
                        Collections.addAll(merged6, before.ipv6Cidrs);
                        Collections.addAll(observed, before.interfaceObservedCidrs);
                        merged4.addAll(v4); merged6.addAll(v6); observed.addAll(v4); observed.addAll(v6);
                        result.set(existing, new Connection(before.id, before.kind, before.interfaceName, before.defaultNetwork,
                                before.network, before.properties, before.capabilities, nic.getMTU(), merged4, merged6, observed));
                    } else {
                        List<String> observed = new ArrayList<>(v4); observed.addAll(v6);
                        result.add(new Connection("interface:" + nic.getName(), NetworkInventoryLogic.interfaceKind(nic.getName()),
                                nic.getName(), false, null, null, null, nic.getMTU(), v4, v6, observed));
                    }
                }
            }
        } catch (Exception ignored) { /* Android 11+ and some vendors restrict interface/address access. */ }
        Collections.sort(result, (a, b) -> {
            int rank = Integer.compare(NetworkInventoryLogic.kindRank(a.kind), NetworkInventoryLogic.kindRank(b.kind));
            if (rank != 0) return rank;
            int iface = a.interfaceName.compareTo(b.interfaceName);
            if (iface != 0) return iface;
            int observed = Boolean.compare(a.observedOnly, b.observedOnly);
            return observed != 0 ? observed : a.id.compareTo(b.id);
        });
        return result;
    }

    public static Connection lookup(Context context, String id) {
        if (id == null || id.isEmpty()) return null;
        for (Connection connection : snapshot(context)) if (id.equals(connection.id)) return connection;
        return null;
    }

    public static Connection preferredForLan(Context context) {
        List<Connection> connections = snapshot(context);
        String[] kinds = new String[connections.size()];
        boolean[] hasIpv4 = new boolean[connections.size()], defaults = new boolean[connections.size()];
        for (int i = 0; i < connections.size(); i++) {
            Connection connection = connections.get(i);
            kinds[i] = connection.kind;
            hasIpv4[i] = connection.ipv4Cidrs.length > 0;
            defaults[i] = connection.defaultNetwork;
        }
        int index = NetworkInventoryLogic.preferredLanIndex(kinds, hasIpv4, defaults);
        return index < 0 ? null : connections.get(index);
    }

    private static void addAddress(InetAddress address, int prefix, List<String> v4, List<String> v6) {
        if (address == null || address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isMulticastAddress()) return;
        boolean ipv4 = address instanceof Inet4Address;
        if (prefix < 0 || prefix > (ipv4 ? 32 : 128)) return;
        String cidr = address.getHostAddress() + "/" + prefix;
        List<String> target = ipv4 ? v4 : v6;
        if (!target.contains(cidr)) target.add(cidr);
    }
}
