package com.fieldkit.analyzer;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.net.RouteInfo;
import android.net.TrafficStats;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.SystemClock;
import android.telephony.SignalStrength;
import android.telephony.TelephonyManager;
import android.util.Xml;

import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xmlpull.v1.XmlPullParser;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.parsers.DocumentBuilderFactory;

/** Android platform network inspection and bounded, read-only service discovery. */
@SuppressWarnings("deprecation")
public final class AndroidNetwork {
    public static final String DEFAULT_SERVICE_TYPES =
            "_http._tcp.,_https._tcp.,_ipp._tcp.,_printer._tcp.,_airplay._tcp.,_raop._tcp.,_googlecast._tcp.,_smb._tcp.";
    private AndroidNetwork() { }

    public static Report dashboard(Context context, Task task) throws Exception {
        task.check();
        Report report = new Report("Network information", "All visible networks", "Parameter", "Value", "Details");
        List<NetworkInventory.Connection> connections = NetworkInventory.snapshot(context);
        boolean wifiDetails = false, cellularDetails = false;
        for (NetworkInventory.Connection connection : connections) {
            task.check();
            report.add("[NETWORK]", connection.title(), connection.id);
            appendConnection(connection, report, task);
            if (!wifiDetails && "Wi-Fi".equals(connection.kind)) {
                appendWifi(context, report);
                wifiDetails = true;
            }
            if (!cellularDetails && "Cellular".equals(connection.kind)) {
                appendCellular(context, report);
                cellularDetails = true;
            }
        }
        if (connections.isEmpty()) report.note("Android reports no visible IP networks. Connect to Wi-Fi, cellular, or Ethernet and refresh.");
        if (!wifiDetails) {
            report.add("[NETWORK]", "Wi-Fi radio", "wifi-radio");
            appendWifi(context, report);
        }
        if (!cellularDetails) {
            report.add("[NETWORK]", "Cellular radio", "cellular-radio");
            report.add("Cellular IP network", "Not visible to this app", "Radio/SIM registration can exist without an active cellular data link. Android or the VPN may hide underlying networks.");
            appendCellular(context, report);
        }
        report.add("[NETWORK]", "Device traffic", "traffic");
        report.add("Device traffic received", bytes(TrafficStats.getTotalRxBytes()), "All networks since boot; OS counters");
        report.add("Device traffic sent", bytes(TrafficStats.getTotalTxBytes()), "All networks since boot; OS counters");
        report.add("App traffic received", bytes(TrafficStats.getUidRxBytes(android.os.Process.myUid())), "This app UID since boot");
        report.add("App traffic sent", bytes(TrafficStats.getUidTxBytes(android.os.Process.myUid())), "This app UID since boot");
        report.note("Wi-Fi, cellular, Ethernet and VPN links are inspected separately. A VPN may list its Wi-Fi/cellular underlay in its capabilities; those fields do not replace physical-link addresses.");
        report.note("Android/OEM/VPN policy can hide network handles or interface addresses. Interface-only entries show local observations; they do not prove a usable route and cannot be selected for socket binding. Cellular radio registration alone is not a scannable network.");
        report.note("Public IP, estimated location and ASN require the separate Public IP lookup action. This dashboard makes no external lookup requests.");
        task.emit(report);
        return report;
    }

    private static void appendConnection(NetworkInventory.Connection connection, Report report, Task task) throws Exception {
        LinkProperties properties = connection.properties;
        NetworkCapabilities caps = connection.capabilities;
        report.add("Connection", connection.kind, connection.observedOnly ? "Observed local interface; Android network handle unavailable" : "Android network " + connection.network);
        report.add("Default for this app", connection.defaultNetwork ? "Yes" : "No", "Per-app Android default; other visible links retain their own addresses");
        report.add("Interface", value(connection.interfaceName), (connection.mtu > 0 ? "MTU " + connection.mtu : "MTU unavailable") +
                (connection.observedOnly ? " · local interface observation" : ""));
        if (connection.cidrs().length == 0) report.add("IP addresses", "Not reported", "Android has not exposed an address for this link");
        for (String cidr : connection.cidrs()) {
            task.check();
            int slash = cidr.lastIndexOf('/');
            String literal = cidr.substring(0, slash);
            int prefix = Integer.parseInt(cidr.substring(slash + 1));
            // Inventory contains numeric addresses only; no DNS request is made here.
            InetAddress address;
            try { address = InetAddress.getByName(literal); }
            catch (java.net.UnknownHostException changedInterface) {
                report.add(literal.contains(":") ? "IPv6 address" : "IPv4 address", literal,
                        "/" + prefix + " · interface changed while reading address scope");
                continue;
            }
            report.add(address instanceof Inet4Address ? "IPv4 address" : "IPv6 address", literal,
                    "/" + prefix + " · " + scope(address) + (connection.isInterfaceObservation(cidr) ? " · local interface observation" : ""));
            if (address instanceof Inet4Address) {
                long raw = ipv4(address), mask = mask(prefix);
                report.add("Subnet mask", ip(mask), "/" + prefix);
                report.add("Network address", ip(raw & mask), "From this interface's IPv4 prefix");
                report.add("Broadcast address", prefix >= 31 ? "Not applicable" : ip((raw & mask) | (~mask & 0xffffffffL)),
                        prefix >= 31 ? "No conventional broadcast on /31 or /32" : "Calculated subnet broadcast");
            }
        }
        if (connection.interfaceObservedCidrs.length > 0 && !connection.observedOnly)
            report.add("Additional interface addresses", Integer.toString(connection.interfaceObservedCidrs.length),
                    "Observed on this same interface; absent from Android LinkProperties. Routing properties still come from the Android network.");
        if (connection.observedOnly) {
            report.add("Routing / DNS", "Not exposed", "This interface has no Android Network handle; gateway, validation, proxy and binding are unavailable");
            return;
        }
        report.add("Internet validated", caps == null ? "Unavailable" : connection.validated ? "Yes" : "No", "Android connectivity validation for this network");
        report.add("Metered", caps == null ? "Unavailable" : connection.metered ? "Yes" : "No", "Per-network capability; speed tests may use mobile data");
        if (properties == null) {
            report.add("Link properties", "Not exposed", "This network may be changing or restricted by Android");
            return;
        }
        for (RouteInfo route : properties.getRoutes()) {
            report.add(route.isDefaultRoute() ? "Default route" : "Route", route.getDestination().toString(),
                    "via " + (route.hasGateway() ? route.getGateway().getHostAddress() : "on-link") + " · " + value(route.getInterface()));
        }
        if (properties.getRoutes().isEmpty()) report.add("Routes", "None reported", "Android LinkProperties for this network");
        for (InetAddress dns : properties.getDnsServers())
            report.add("DNS server", dns.getHostAddress(), dns instanceof Inet6Address ? "IPv6" : "IPv4");
        if (properties.getDnsServers().isEmpty()) report.add("DNS", "None reported", "Android LinkProperties for this network");
        report.add("Search domains", value(properties.getDomains()), "Reported for this network");
        if (Build.VERSION.SDK_INT >= 28) report.add("Private DNS", properties.isPrivateDnsActive() ? "Active" : "Inactive", value(properties.getPrivateDnsServerName()));
        if (Build.VERSION.SDK_INT >= 30 && properties.getDhcpServerAddress() != null)
            report.add("DHCP server", properties.getDhcpServerAddress().getHostAddress(), "Reported for this network");
        ProxyInfo proxy = properties.getHttpProxy();
        report.add("HTTP proxy", proxy == null ? "None reported" : proxy.toString(), "Per-network proxy configuration");
        report.add("Estimated link bandwidth", caps == null ? "Unavailable" : caps.getLinkDownstreamBandwidthKbps() +
                " down / " + caps.getLinkUpstreamBandwidthKbps() + " up kbit/s", "OS estimate; this is not a speed-test measurement");
    }

    private static void appendWifi(Context context, Report report) {
        WifiManager wifi = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wifi == null) { report.note("This device has no Wi-Fi manager."); return; }
        try {
            WifiInfo info = wifi.getConnectionInfo();
            if (info == null || info.getNetworkId() < 0) {
                report.add("Wi-Fi connection", "Not connected or restricted", "Android may redact location-sensitive connection information");
                return;
            }
            String ssid = info.getSSID(), bssid = info.getBSSID();
            boolean redacted = ssid == null || WifiManager.UNKNOWN_SSID.equals(ssid) || bssid == null ||
                    "02:00:00:00:00:00".equals(bssid);
            report.add("Wi-Fi SSID", ssid == null || WifiManager.UNKNOWN_SSID.equals(ssid) ? "Unavailable / restricted" : ssid,
                    "Current Wi-Fi connection");
            report.add("Wi-Fi BSSID", bssid == null || "02:00:00:00:00:00".equals(bssid) ? "Unavailable / restricted" : bssid,
                    "Access point identifier; not the phone's hardware MAC");
            int rssi = info.getRssi(), frequency = info.getFrequency();
            report.add("Wi-Fi RSSI", rssi <= -127 ? "Unavailable" : rssi + " dBm",
                    rssi <= -127 ? "Android did not provide RSSI" : signal(rssi));
            report.add("Wi-Fi frequency", frequency > 0 ? frequency + " MHz" : "Unavailable",
                    "Channel " + (channel(frequency) < 0 ? "unknown" : channel(frequency)) + " · " + band(frequency));
            report.add("Wi-Fi link speed", info.getLinkSpeed() < 0 ? "Unavailable" : info.getLinkSpeed() + " Mbit/s",
                    "Negotiated connection rate; not internet throughput");
            boolean found = false;
            try {
                for (ScanResult result : wifi.getScanResults()) {
                    if (bssid != null && bssid.equalsIgnoreCase(result.BSSID)) {
                        report.add("Wi-Fi channel width", widthText(result.channelWidth), "From the matching cached BSSID scan entry");
                        report.add("Wi-Fi security", value(result.capabilities), "Advertised by access point; cached scan");
                        found = true;
                        break;
                    }
                }
            } catch (SecurityException ignored) { }
            if (!found) report.add("Wi-Fi channel width / security", "Unavailable", "No permitted cached scan entry matches the connected BSSID");
            if (redacted) report.note("Android redacts SSID/BSSID without the required Wi-Fi/location permissions and enabled Location services.");
        } catch (RuntimeException e) {
            report.note("Wi-Fi connection details are unavailable or restricted by device permissions: " + message(e));
        }
    }

    private static void appendCellular(Context context, Report report) {
        TelephonyManager phone = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (phone == null) return;
        try {
            String operator = phone.getNetworkOperator();
            report.add("Mobile operator", value(phone.getNetworkOperatorName()), "Current network operator, if registered");
            if (operator != null && operator.matches("[0-9]{5,6}")) {
                report.add("Mobile country code", operator.substring(0, 3), "MCC");
                report.add("Mobile network code", operator.substring(3), "MNC");
            }
            report.add("SIM state", Integer.toString(phone.getSimState()), "Android SIM state code; no SIM identifiers are read");
            if (context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED) {
                report.add("Mobile technology", technology(phone.getDataNetworkType()), "Data network technology");
                if (Build.VERSION.SDK_INT >= 28) {
                    SignalStrength strength = phone.getSignalStrength();
                    report.add("Cellular signal", strength == null ? "Unavailable" : strength.getLevel() + " / 4",
                            "OS normalized signal level; registration details may be restricted");
                }
                if (Build.VERSION.SDK_INT >= 26 && phone.getServiceState() != null)
                    report.add("Cellular service state", Integer.toString(phone.getServiceState().getState()),
                            "0 in service · 1 out of service · 2 emergency only · 3 radio off");
            } else report.note("Phone permission is optional. Cellular technology, signal, and registration are omitted until it is granted; no IMEI/IMSI is requested.");
        } catch (RuntimeException e) {
            report.note("Cellular details are restricted by Android, carrier policy, or device support: " + message(e));
        }
    }

    public static Report wifi(Context context, Task task) throws Exception {
        Report report = new Report("Wi-Fi analyzer", "Nearby access points", "SSID", "BSSID", "RSSI dBm", "Frequency MHz",
                "Channel", "Width MHz", "Security", "WPS", "Age seconds");
        WifiManager wifi = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wifi == null) { report.note("Wi-Fi scanning is unsupported on this device."); return report; }
        if (!wifi.isWifiEnabled()) report.note("Wi-Fi is off. Android may return cached entries when scan-always-available is enabled.");
        if (context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            report.note("Nearby Wi-Fi scans require precise Location permission on Android. Grant it in the permission action and enable system Location, then refresh.");
            return report;
        }
        LocationManager location = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        if (location != null && !location.isProviderEnabled(LocationManager.GPS_PROVIDER) &&
                !location.isProviderEnabled(LocationManager.NETWORK_PROVIDER))
            report.note("System Location appears disabled; Android may block scans or return an empty cached list.");
        CountDownLatch update = new CountDownLatch(1);
        AtomicBoolean updated = new AtomicBoolean(false);
        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override public void onReceive(Context ignored, Intent intent) {
                updated.set(intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false));
                update.countDown();
            }
        };
        AtomicBoolean registered = new AtomicBoolean(false);
        Closeable cleanup = () -> {
            if (registered.compareAndSet(true, false)) {
                try { context.unregisterReceiver(receiver); } catch (IllegalArgumentException ignored) { }
            }
        };
        task.register(cleanup);
        try {
            IntentFilter filter = new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
            if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
            else context.registerReceiver(receiver, filter);
            registered.set(true);
            task.check();
            boolean accepted = wifi.startScan();
            report.note("Android throttles scan requests (typically four foreground scans per two minutes). Refresh never bypasses OS throttling.");
            if (accepted) {
                report.note("Scan requested. Waiting at most 10 seconds for Android's scan-result broadcast.");
                task.emit(report);
                long deadline = SystemClock.elapsedRealtime() + 10000;
                while (update.getCount() > 0 && SystemClock.elapsedRealtime() < deadline) {
                    task.check();
                    update.await(150, TimeUnit.MILLISECONDS);
                }
                report.note(updated.get() ? "Android reported updated scan results." :
                        "No new scan results were confirmed. Entries below are Android's cached observations; inspect their ages.");
            } else report.note("Android declined the scan request (throttling, disabled Location/Wi-Fi, or device policy). Showing permitted cached observations.");
            task.check();
            List<ScanResult> results = new ArrayList<>(wifi.getScanResults());
            Collections.sort(results, (a, b) -> Integer.compare(b.level, a.level));
            long elapsedMicros = SystemClock.elapsedRealtimeNanos() / 1000;
            for (ScanResult entry : results) {
                task.check();
                report.add(entry.SSID == null || entry.SSID.isEmpty() ? "(hidden SSID)" : entry.SSID,
                        value(entry.BSSID), Integer.toString(entry.level), Integer.toString(entry.frequency),
                        channel(entry.frequency) < 0 ? "Unknown" : Integer.toString(channel(entry.frequency)),
                        widthText(entry.channelWidth), value(entry.capabilities),
                        entry.capabilities != null && entry.capabilities.toUpperCase(Locale.US).contains("[WPS]") ? "Yes" : "No advertised WPS",
                        entry.timestamp > 0 ? String.format(Locale.US, "%.1f", Math.max(0, elapsedMicros - entry.timestamp) / 1000000.0) : "Unknown");
            }
            if (results.isEmpty()) report.note("No permitted scan results. Check precise Location permission, system Location, Wi-Fi, hardware support, and scan throttling.");
            report.note("Channel occupancy is estimated from advertised widths and RSSI. It is not measured RF airtime or a spectrum scan. 6 GHz visibility depends on Android and radio hardware.");
            task.emit(report);
            return report;
        } catch (SecurityException e) {
            report.note("Android denied Wi-Fi scanning. Precise Location and enabled Location services are required: " + message(e));
            return report;
        } finally {
            cleanup.close();
            task.unregister(cleanup);
        }
    }

    public static Report mdns(Context context, String serviceTypes, int seconds, Task task) throws Exception {
        if (seconds < 2 || seconds > 60) throw new IllegalArgumentException("Discovery duration must be 2–60 seconds.");
        String requested = serviceTypes == null || serviceTypes.trim().isEmpty() ? DEFAULT_SERVICE_TYPES : serviceTypes.trim();
        LinkedHashSet<String> types = new LinkedHashSet<>();
        for (String input : requested.split(",")) {
            String type = input.trim();
            if (!type.endsWith(".")) type += ".";
            if (!type.matches("_[A-Za-z0-9-]{1,63}\\._(?:tcp|udp)\\."))
                throw new IllegalArgumentException("Use comma-separated DNS-SD types, for example _http._tcp.,_ipp._tcp.");
            types.add(type);
        }
        if (types.size() > 12) throw new IllegalArgumentException("Discover at most 12 service types per run.");
        Report report = new Report("Bonjour / mDNS", requested, "Service", "Type", "Address", "Port", "TXT / status");
        report.note("Uses Android DNS-SD on the local link. Searches only the requested service types; this is not an inventory of every device. Client isolation, VPNs and multicast filtering may hide services.");
        NsdManager nsd = (NsdManager) context.getSystemService(Context.NSD_SERVICE);
        if (nsd == null) { report.note("Android network service discovery is unavailable."); return report; }
        Closeable multicast = multicast(context, report);
        List<NsdManager.DiscoveryListener> listeners = Collections.synchronizedList(new ArrayList<>());
        Map<String, NsdServiceInfo> discovered = Collections.synchronizedMap(new LinkedHashMap<>());
        AtomicBoolean finished = new AtomicBoolean(false);
        Closeable cleanup = () -> {
            if (finished.compareAndSet(false, true)) {
                synchronized (listeners) {
                    for (NsdManager.DiscoveryListener listener : listeners)
                        try { nsd.stopServiceDiscovery(listener); } catch (RuntimeException ignored) { }
                }
                multicast.close();
            }
        };
        task.register(cleanup);
        try {
            task.check();
            for (String type : types) {
                NsdManager.DiscoveryListener listener = new NsdManager.DiscoveryListener() {
                    @Override public void onDiscoveryStarted(String ignored) { }
                    @Override public void onDiscoveryStopped(String ignored) { }
                    @Override public void onStartDiscoveryFailed(String serviceType, int code) {
                        if (!finished.get()) report.note("Discovery could not start for " + serviceType + ": Android error " + code);
                        try { nsd.stopServiceDiscovery(this); } catch (RuntimeException ignored) { }
                    }
                    @Override public void onStopDiscoveryFailed(String serviceType, int code) { }
                    @Override public void onServiceFound(NsdServiceInfo info) {
                        if (!finished.get() && discovered.size() < 256) discovered.put(info.getServiceType() + ":" + info.getServiceName(), info);
                    }
                    @Override public void onServiceLost(NsdServiceInfo info) {
                        if (!finished.get()) discovered.remove(info.getServiceType() + ":" + info.getServiceName());
                    }
                };
                synchronized (listeners) {
                    task.check();
                    if (finished.get()) throw new InterruptedException("Discovery stopped");
                    listeners.add(listener);
                    try { nsd.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, listener); }
                    catch (RuntimeException e) { report.note(type + ": " + message(e)); }
                }
            }
            task.emit(report);
            long deadline = SystemClock.elapsedRealtime() + seconds * 1000L;
            while (SystemClock.elapsedRealtime() < deadline) {
                task.check();
                task.sleep(Math.min(200, Math.max(1, deadline - SystemClock.elapsedRealtime())));
            }
            List<NsdServiceInfo> pending;
            synchronized (discovered) { pending = new ArrayList<>(discovered.values()); }
            report.note("Discovered " + pending.size() + " service instances. Resolving them sequentially to respect Android's resolver limit.");
            task.emit(report);
            long resolutionDeadline = SystemClock.elapsedRealtime() + Math.min(30000L, Math.max(5000L, pending.size() * 2000L));
            boolean resolverAvailable = true;
            for (NsdServiceInfo info : pending) {
                task.check();
                if (!resolverAvailable || SystemClock.elapsedRealtime() >= resolutionDeadline) {
                    report.add(info.getServiceName(), info.getServiceType(), "Unresolved", "", "Resolution budget reached");
                    continue;
                }
                CountDownLatch resolved = new CountDownLatch(1);
                NsdServiceInfo[] answer = new NsdServiceInfo[1];
                int[] failure = {-1};
                NsdManager.ResolveListener listener = new NsdManager.ResolveListener() {
                    @Override public void onResolveFailed(NsdServiceInfo item, int errorCode) { failure[0] = errorCode; resolved.countDown(); }
                    @Override public void onServiceResolved(NsdServiceInfo item) { answer[0] = item; resolved.countDown(); }
                };
                try { nsd.resolveService(info, listener); }
                catch (RuntimeException e) { report.add(info.getServiceName(), info.getServiceType(), "Unresolved", "", message(e)); continue; }
                Closeable stopResolve = () -> {
                    if (Build.VERSION.SDK_INT >= 34 && resolved.getCount() > 0)
                        try { nsd.stopServiceResolution(listener); } catch (RuntimeException ignored) { }
                };
                task.register(stopResolve);
                try {
                    long until = Math.min(resolutionDeadline, SystemClock.elapsedRealtime() + 4000);
                    while (resolved.getCount() > 0 && SystemClock.elapsedRealtime() < until) {
                        task.check();
                        resolved.await(100, TimeUnit.MILLISECONDS);
                    }
                } finally { stopResolve.close(); task.unregister(stopResolve); }
                if (resolved.getCount() > 0) {
                    resolverAvailable = false;
                    report.add(info.getServiceName(), info.getServiceType(), "Unresolved", "", "Android resolver timed out; further resolves skipped to avoid concurrent resolve failures");
                } else if (answer[0] == null) {
                    report.add(info.getServiceName(), info.getServiceType(), "Unresolved", "", "Android resolution error " + failure[0]);
                } else {
                    NsdServiceInfo item = answer[0];
                    LinkedHashSet<String> addresses = new LinkedHashSet<>();
                    if (Build.VERSION.SDK_INT >= 34) for (InetAddress address : item.getHostAddresses()) addresses.add(address.getHostAddress());
                    if (item.getHost() != null) addresses.add(item.getHost().getHostAddress());
                    report.add(item.getServiceName(), item.getServiceType(), addresses.isEmpty() ? "Not supplied" : join(addresses, ", "),
                            Integer.toString(item.getPort()), txt(item));
                }
                task.emit(report);
            }
            if (pending.isEmpty()) report.note("No matching services were advertised during the discovery interval. This does not prove there are no devices on this network.");
            return report;
        } finally { cleanup.close(); task.unregister(cleanup); }
    }

    public static Report upnp(Context context, int seconds, Task task) throws Exception {
        if (seconds < 2 || seconds > 60) throw new IllegalArgumentException("Discovery duration must be 2–60 seconds.");
        Report report = new Report("UPnP / DLNA discovery", "Local SSDP", "Device / source", "Field", "Value", "Details");
        report.note("Sends SSDP M-SEARCH to local multicast and reads advertised local description XML. It does not invoke device-control actions. Multicast isolation or VPN routing can prevent discovery.");
        DatagramSocket socket = new DatagramSocket();
        Closeable multicast = multicast(context, report);
        task.register(socket);
        task.register(multicast);
        Map<String, Map<String, String>> advertisements = new LinkedHashMap<>();
        try {
            socket.setSoTimeout(350);
            byte[] query = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
            DatagramPacket search = new DatagramPacket(query, query.length, InetAddress.getByName("239.255.255.250"), 1900);
            socket.send(search);
            task.emit(report);
            long end = SystemClock.elapsedRealtime() + seconds * 1000L;
            long resend = SystemClock.elapsedRealtime() + 1500;
            byte[] buffer = new byte[32768];
            while (SystemClock.elapsedRealtime() < end && advertisements.size() < 256) {
                task.check();
                if (SystemClock.elapsedRealtime() >= resend) { socket.send(search); resend = Long.MAX_VALUE; }
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                try { socket.receive(packet); } catch (SocketTimeoutException ignored) { continue; }
                String text = new String(packet.getData(), packet.getOffset(), packet.getLength(), StandardCharsets.UTF_8);
                if (!text.toUpperCase(Locale.US).startsWith("HTTP/1.1 200")) continue;
                Map<String, String> headers = new LinkedHashMap<>();
                for (String line : text.split("\r?\n")) {
                    int colon = line.indexOf(':');
                    if (colon > 0) headers.put(line.substring(0, colon).trim().toLowerCase(Locale.US), line.substring(colon + 1).trim());
                }
                headers.put("source", packet.getAddress().getHostAddress());
                String key = headers.get("source") + "|" + headers.get("usn") + "|" + headers.get("st") + "|" + headers.get("location");
                if (advertisements.containsKey(key)) continue;
                advertisements.put(key, headers);
                report.add(headers.get("source"), "SSDP advertisement", value(headers.get("st")),
                        "USN " + value(headers.get("usn")) + " · server " + value(headers.get("server")));
                if (headers.get("location") != null) report.add(headers.get("source"), "Description URL", headers.get("location"), "Advertised by device");
                task.emit(report);
            }
        } finally { socket.close(); task.unregister(socket); multicast.close(); task.unregister(multicast); }
        Set<String> locations = new LinkedHashSet<>();
        for (Map<String, String> headers : advertisements.values()) if (headers.get("location") != null) locations.add(headers.get("location"));
        int fetched = 0;
        for (String location : locations) {
            task.check();
            if (++fetched > 32) { report.note("Description fetch limit reached (32). Other advertisements remain listed."); break; }
            try { appendDescription(location, report, task); }
            catch (Exception e) { task.check(); report.add(location, "Description unavailable", message(e), "SSDP advertisement remains valid discovery evidence"); }
            task.emit(report);
        }
        if (advertisements.isEmpty()) report.note("No SSDP responses received. Devices may not advertise UPnP or multicast may be blocked.");
        return report;
    }

    private static void appendDescription(String location, Report report, Task task) throws Exception {
        URL url = new URL(location);
        requireLocalUrl(url);
        byte[] xml = fetch(url, 1024 * 1024, task, false);
        Document document = descriptionXml(xml, task);
        URL base = url;
        NodeList bases = document.getElementsByTagNameNS("*", "URLBase");
        if (bases.getLength() > 0 && !bases.item(0).getTextContent().trim().isEmpty()) base = new URL(url, bases.item(0).getTextContent().trim());
        NodeList devices = document.getElementsByTagNameNS("*", "device");
        for (int i = 0; i < Math.min(64, devices.getLength()); i++) {
            task.check();
            Element device = (Element) devices.item(i);
            String name = child(device, "friendlyName");
            if (name.isEmpty()) name = url.getHost() + " device " + (i + 1);
            String[] fields = {"deviceType", "manufacturer", "manufacturerURL", "modelDescription", "modelName", "modelNumber", "UDN", "serialNumber"};
            for (String field : fields) {
                String fieldValue = child(device, field);
                if (!fieldValue.isEmpty()) report.add(name, field, fieldValue, "Description XML · " + location);
            }
            String presentation = child(device, "presentationURL");
            if (!presentation.isEmpty()) report.add(name, "Presentation URL", new URL(base, presentation).toString(), "Advertised management page; not opened automatically");
            Element list = childElement(device, "serviceList");
            if (list != null) for (Node node = list.getFirstChild(); node != null; node = node.getNextSibling()) {
                if (!(node instanceof Element) || !"service".equals(localName(node))) continue;
                Element service = (Element) node;
                String type = child(service, "serviceType");
                report.add(name, "Service", type, child(service, "serviceId"));
                for (String field : new String[]{"SCPDURL", "controlURL", "eventSubURL"}) {
                    String endpoint = child(service, field);
                    if (!endpoint.isEmpty()) report.add(name, field, new URL(base, endpoint).toString(), type + " · information only");
                }
            }
        }
        if (devices.getLength() == 0) report.add(location, "Description XML", "No UPnP device elements", "Response was parsed without external entity access");
    }

    /** Build a small DOM from Android's pull parser. Never ask a DOM parser to load untrusted XML. */
    private static Document descriptionXml(byte[] bytes, Task task) throws Exception {
        XmlPullParser parser = Xml.newPullParser();
        parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
        parser.setFeature(XmlPullParser.FEATURE_PROCESS_DOCDECL, false);
        parser.setInput(new ByteArrayInputStream(bytes), null);
        Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        Element current = null;
        int nodes = 0;
        for (int event = parser.getEventType(); event != XmlPullParser.END_DOCUMENT; event = parser.nextToken()) {
            task.check();
            if (parser.getDepth() > 48 || ++nodes > 100000) throw new IOException("Description XML exceeds complexity limit");
            if (event == XmlPullParser.DOCDECL) throw new IOException("DOCTYPE declarations are not allowed in description XML");
            if (event == XmlPullParser.START_TAG) {
                Element next = document.createElementNS(parser.getNamespace(), parser.getName());
                if (current == null) document.appendChild(next); else current.appendChild(next);
                current = next;
            } else if (event == XmlPullParser.END_TAG) {
                Node parent = current == null ? null : current.getParentNode();
                current = parent instanceof Element ? (Element) parent : null;
            } else if (event == XmlPullParser.TEXT || event == XmlPullParser.CDSECT || event == XmlPullParser.ENTITY_REF) {
                String text = parser.getText();
                if (event == XmlPullParser.ENTITY_REF && text == null) throw new IOException("Unresolved entity in description XML");
                if (current != null && text != null) current.appendChild(document.createTextNode(text));
            }
        }
        return document;
    }

    public static Report publicInfo(Context context, Task task) throws Exception {
        Report report = new Report("Public IP lookup", "ipify / ipwho.is", "Parameter", "Value", "Source / details");
        report.note("This explicit action contacts api.ipify.org, api6.ipify.org and ipwho.is over HTTPS. These services see your public IP. Geolocation is approximate and can reflect a VPN exit or provider gateway.");
        task.emit(report);
        String ipv4 = null, ipv6 = null;
        try {
            JSONObject response = new JSONObject(new String(fetch(new URL("https://api.ipify.org?format=json"), 16384, task, true), StandardCharsets.UTF_8));
            String candidate = response.getString("ip");
            InetAddress parsed = InetAddress.getByName(candidate);
            if (!(parsed instanceof Inet4Address)) throw new IOException("Service did not return an IPv4 address");
            ipv4 = parsed.getHostAddress();
            report.add("Public IPv4", ipv4, "api.ipify.org · network egress address");
        } catch (Exception e) { task.check(); report.add("Public IPv4", "Unavailable", message(e)); }
        task.emit(report);
        try {
            JSONObject response = new JSONObject(new String(fetch(new URL("https://api6.ipify.org?format=json"), 16384, task, true), StandardCharsets.UTF_8));
            String candidate = response.getString("ip");
            InetAddress parsed = InetAddress.getByName(candidate);
            if (!(parsed instanceof Inet6Address)) throw new IOException("Service did not return an IPv6 address");
            ipv6 = parsed.getHostAddress();
            report.add("Public IPv6", ipv6, "api6.ipify.org · IPv6 reachability required");
        } catch (Exception e) { task.check(); report.add("Public IPv6", "Unavailable", "IPv6 may be unsupported on the active network: " + message(e)); }
        task.emit(report);
        String lookup = ipv4 != null ? ipv4 : ipv6;
        if (lookup != null) {
            try {
                JSONObject response = new JSONObject(new String(fetch(new URL("https://ipwho.is/" + lookup), 65536, task, true), StandardCharsets.UTF_8));
                if (!response.optBoolean("success", false)) throw new IOException(response.optString("message", "Lookup unavailable"));
                report.add("Approximate location", response.optString("city") + ", " + response.optString("region") + ", " + response.optString("country"), "ipwho.is · estimate for " + lookup);
                report.add("Approximate coordinates", response.optString("latitude") + ", " + response.optString("longitude"), "IP-derived estimate; not GPS position");
                JSONObject connection = response.optJSONObject("connection");
                if (connection != null) {
                    report.add("ASN", connection.optString("asn", "Unavailable"), "ipwho.is");
                    report.add("Organization", connection.optString("org", "Unavailable"), "ipwho.is");
                    report.add("Provider", connection.optString("isp", "Unavailable"), "ipwho.is");
                }
            } catch (Exception e) { task.check(); report.note("Estimated location/provider lookup unavailable: " + message(e)); }
        }
        task.emit(report);
        return report;
    }

    private static byte[] fetch(URL url, int limit, Task task, boolean secureOnly) throws Exception {
        task.check();
        if (secureOnly && !"https".equalsIgnoreCase(url.getProtocol())) throw new IOException("HTTPS required");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("User-Agent", "FieldKit-NetworkAnalyzer/1.0");
        connection.setRequestProperty("Accept", "application/json, application/xml, text/xml, */*");
        Closeable close = connection::disconnect;
        task.register(close);
        try {
            int status = connection.getResponseCode();
            if (status < 200 || status >= 300) throw new IOException("HTTP " + status + " from " + url.getHost());
            if (connection.getContentLengthLong() > limit) throw new IOException("Response exceeds " + limit + " bytes");
            long until = SystemClock.elapsedRealtime() + 12000;
            try (InputStream input = connection.getInputStream(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    task.check();
                    if (SystemClock.elapsedRealtime() > until) throw new SocketTimeoutException("Response time limit exceeded");
                    if (output.size() + count > limit) throw new IOException("Response exceeds " + limit + " bytes");
                    output.write(buffer, 0, count);
                }
                return output.toByteArray();
            }
        } finally { connection.disconnect(); task.unregister(close); }
    }

    private static void requireLocalUrl(URL url) throws Exception {
        if (!"http".equalsIgnoreCase(url.getProtocol()) && !"https".equalsIgnoreCase(url.getProtocol()))
            throw new IOException("Only HTTP(S) description URLs are supported");
        if (url.getUserInfo() != null) throw new IOException("Description URL may not contain credentials");
        InetAddress[] addresses = InetAddress.getAllByName(url.getHost());
        if (addresses.length == 0) throw new IOException("Description hostname did not resolve");
        for (InetAddress address : addresses) {
            byte[] bytes = address.getAddress();
            boolean uniqueLocal = bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc;
            if (address.isLoopbackAddress() || address.isAnyLocalAddress() || address.isMulticastAddress() ||
                    !(address.isSiteLocalAddress() || address.isLinkLocalAddress() || uniqueLocal))
                throw new IOException("Only local-network advertised description addresses are fetched");
        }
    }

    private static Closeable multicast(Context context, Report report) {
        WifiManager wifi = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wifi == null) return () -> { };
        WifiManager.MulticastLock lock = wifi.createMulticastLock("fieldkit-discovery");
        lock.setReferenceCounted(false);
        try { lock.acquire(); }
        catch (RuntimeException e) { report.note("Could not acquire Wi-Fi multicast reception: " + message(e)); }
        return () -> { try { if (lock.isHeld()) lock.release(); } catch (RuntimeException ignored) { } };
    }

    public static String defaultRange(Context context) {
        NetworkInventory.Connection connection = NetworkInventory.preferredForLan(context);
        return connection == null ? "" : connection.recommendedRange();
    }
    public static String self(Context context) {
        NetworkInventory.Connection connection = NetworkInventory.preferredForLan(context);
        return connection == null ? "" : connection.firstIpv4();
    }
    public static String gateway(Context context) {
        NetworkInventory.Connection connection = NetworkInventory.preferredForLan(context);
        return connection == null ? "" : connection.gateway();
    }
    public static String dnsServer(Context context) {
        LinkProperties properties = activeProperties(context);
        if (properties != null && !properties.getDnsServers().isEmpty()) return properties.getDnsServers().get(0).getHostAddress();
        return "";
    }
    private static LinkProperties activeProperties(Context context) {
        ConnectivityManager manager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) return null;
        Network network = manager.getActiveNetwork();
        return network == null ? null : manager.getLinkProperties(network);
    }
    public static int channel(int frequency) {
        if (frequency == 2484) return 14;
        if (frequency >= 2412 && frequency <= 2472) return (frequency - 2407) / 5;
        if (frequency == 5935) return 2;
        if (frequency >= 5955 && frequency <= 7115) return (frequency - 5950) / 5;
        if (frequency >= 4910 && frequency <= 4980) return (frequency - 4000) / 5;
        if (frequency >= 5000 && frequency <= 5895) return (frequency - 5000) / 5;
        if (frequency >= 58320 && frequency <= 70200) return (frequency - 56160) / 2160;
        return -1;
    }
    public static int width(int code) {
        switch (code) { case 0: return 20; case 1: return 40; case 2: return 80; case 3: return 160; case 4: return 160; case 5: return 320; default: return 0; }
    }
    private static String widthText(int code) { return code == 4 ? "80+80" : width(code) == 0 ? "Unknown" : Integer.toString(width(code)); }
    private static String band(int frequency) { return frequency >= 5925 && frequency <= 7125 ? "6 GHz" : frequency >= 4900 && frequency < 5925 ? "5 GHz" : frequency >= 2400 && frequency < 2500 ? "2.4 GHz" : frequency >= 57000 ? "60 GHz" : "unknown band"; }
    private static String signal(int rssi) { return rssi >= -55 ? "Excellent" : rssi >= -67 ? "Good" : rssi >= -75 ? "Fair" : rssi >= -85 ? "Weak" : "Very weak"; }
    private static String scope(InetAddress address) {
        if (address.isLoopbackAddress()) return "Loopback";
        if (address.isLinkLocalAddress()) return "Link-local";
        byte[] bytes = address.getAddress();
        if (bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc) return "Unique local";
        if (address.isSiteLocalAddress()) return "Private / site-local";
        if (address.isMulticastAddress()) return "Multicast";
        return "Global unicast";
    }
    private static String transports(NetworkCapabilities capabilities) {
        if (capabilities == null) return "Unknown";
        List<String> result = new ArrayList<>();
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) result.add("Wi-Fi");
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) result.add("Cellular");
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) result.add("Ethernet");
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) result.add("VPN");
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) result.add("Bluetooth");
        return result.isEmpty() ? "Other" : join(result, ", ");
    }
    private static String technology(int type) {
        switch (type) {
            case TelephonyManager.NETWORK_TYPE_NR: return "5G NR";
            case TelephonyManager.NETWORK_TYPE_LTE: return "LTE";
            case TelephonyManager.NETWORK_TYPE_HSPAP: return "HSPA+";
            case TelephonyManager.NETWORK_TYPE_HSPA: return "HSPA";
            case TelephonyManager.NETWORK_TYPE_HSDPA: return "HSDPA";
            case TelephonyManager.NETWORK_TYPE_HSUPA: return "HSUPA";
            case TelephonyManager.NETWORK_TYPE_UMTS: return "UMTS";
            case TelephonyManager.NETWORK_TYPE_EDGE: return "EDGE";
            case TelephonyManager.NETWORK_TYPE_GPRS: return "GPRS";
            case TelephonyManager.NETWORK_TYPE_GSM: return "GSM";
            case TelephonyManager.NETWORK_TYPE_CDMA: return "CDMA";
            case TelephonyManager.NETWORK_TYPE_EVDO_0:
            case TelephonyManager.NETWORK_TYPE_EVDO_A:
            case TelephonyManager.NETWORK_TYPE_EVDO_B: return "EVDO";
            case TelephonyManager.NETWORK_TYPE_UNKNOWN: return "Unknown / not registered";
            default: return "Android technology code " + type;
        }
    }
    private static String txt(NsdServiceInfo info) {
        List<String> values = new ArrayList<>();
        for (Map.Entry<String, byte[]> attribute : info.getAttributes().entrySet()) {
            byte[] bytes = attribute.getValue();
            values.add(attribute.getKey() + "=" + (bytes == null ? "" : new String(bytes, StandardCharsets.UTF_8)));
        }
        return values.isEmpty() ? "No TXT attributes supplied" : join(values, "; ");
    }
    private static Element childElement(Element element, String name) {
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element && name.equals(localName(node))) return (Element) node;
        return null;
    }
    private static String child(Element element, String name) { Element found = childElement(element, name); return found == null ? "" : found.getTextContent().trim(); }
    private static String localName(Node node) { return node.getLocalName() == null ? node.getNodeName() : node.getLocalName(); }
    private static long ipv4(InetAddress address) { byte[] b = address.getAddress(); return ((long)(b[0] & 255) << 24) | ((long)(b[1] & 255) << 16) | ((long)(b[2] & 255) << 8) | (b[3] & 255); }
    private static long mask(int prefix) { return prefix == 0 ? 0 : (0xffffffffL << (32 - prefix)) & 0xffffffffL; }
    private static String ip(long address) { return ((address >>> 24) & 255) + "." + ((address >>> 16) & 255) + "." + ((address >>> 8) & 255) + "." + (address & 255); }
    private static String bytes(long amount) { return amount == TrafficStats.UNSUPPORTED ? "Unsupported" : String.format(Locale.US, "%,d bytes", amount); }
    private static String value(String text) { return text == null || text.isEmpty() ? "Not reported" : text; }
    private static String message(Throwable e) { return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(); }
    private static String join(Iterable<String> strings, String separator) { StringBuilder result = new StringBuilder(); for (String item : strings) { if (result.length() > 0) result.append(separator); result.append(item); } return result.toString(); }
}
