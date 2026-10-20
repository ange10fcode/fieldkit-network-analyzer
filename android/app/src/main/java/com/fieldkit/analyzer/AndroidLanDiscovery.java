package com.fieldkit.analyzer;

import android.content.Context;
import android.net.wifi.WifiManager;
import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Optional bounded local naming. Advertisements and connected TCP evidence remain distinct. */
public final class AndroidLanDiscovery {
    private AndroidLanDiscovery() {}

    public static Report enrich(Context context, Report lan, Task parent) throws Exception {
        parent.check();
        if (parent.hasRoute() && parent.route().description().startsWith("VPN")) {
            lan.note("Local naming skipped for an explicitly selected VPN. Local multicast advertisements do not identify tailnet peers.");
            return lan;
        }
        parent.emit(lan);
        Task discovery = new Task(null);discovery.route(parent.route());
        Closeable cancel = discovery::cancel;
        parent.register(cancel);
        ExecutorService workers=Executors.newFixedThreadPool(3);
        WifiManager.MulticastLock multicast=null;
        try {
            try {
                WifiManager wifi=(WifiManager)context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                if(wifi!=null){multicast=wifi.createMulticastLock("fieldkit-lan-names");multicast.setReferenceCounted(false);multicast.acquire();}
            }catch(RuntimeException restricted){lan.note("Android restricted the multicast receive lock; service discovery may be incomplete.");}
            final List<String> resolvers=localResolvers(context,lan,parent);
            Future<Report> hostnames=workers.submit(()->LanNameDiscovery.discover(lan,resolvers,discovery));
            Future<Report> devices=workers.submit(()->SsdpNames.discover(lan.target,discovery));
            Future<Report> bonjour=workers.submit(()->AndroidNetwork.mdns(context,AndroidNetwork.DEFAULT_SERVICE_TYPES,3,discovery));
            // Unicast host names take priority; existing reverse-DNS and user labels are retained.
            mergeFuture(hostnames,lan,parent,false,"Local names");
            mergeFuture(devices,lan,parent,false,"UPnP names");
            mergeFuture(bonjour,lan,parent,true,"Bonjour names");
            lan.note("Name sources: local DNS PTR, NetBIOS workstation responses, Bonjour service names and UPnP friendlyName. Missing names mean that no supported name response was received. Advertised labels are device-provided and not verified identities. Android DNS-SD chooses local discovery links independently of probe routing; unicast DNS, NetBIOS and SSDP retain the current probe route.");
            if(resolvers.isEmpty())lan.note("No DNS resolver was exposed for a Wi-Fi/Ethernet subnet containing this scan. Public DNS was not substituted; NetBIOS and local advertisements were still checked.");
            else lan.note("Local reverse-name resolver(s): "+String.join(", ",resolvers)+". Queries keep the current Android/VPN socket routing; no underlying-network binding is added.");
            synchronized(lan) {
                long unknown=0;for(List<String> row:lan.rows)if(row.size()>1&&(row.get(1).isEmpty()||row.get(1).equals("—")))unknown++;
                if(unknown>0)lan.note(unknown+" device(s) did not supply a supported name. Assign a label in device details to recognize them next time.");
            }
            parent.emit(lan);
            return lan;
        } catch (Exception failure) {
            parent.check();
            lan.note("Local names unavailable; probe results retained. " +
                    (failure.getMessage() == null ? "Android service discovery could not finish." : failure.getMessage()));
            return lan;
        } finally {
            discovery.cancel(); parent.unregister(cancel);workers.shutdownNow();
            if(multicast!=null&&multicast.isHeld())multicast.release();
        }
    }

    private static void mergeFuture(Future<Report> future,Report lan,Task parent,boolean dnsSd,String phase)throws Exception {
        try {
            while(!future.isDone()){parent.check();parent.sleep(100);}
            Report result=future.get();parent.check();
            if(dnsSd){int count=LanServiceMerge.merge(lan,result);lan.note("Bonjour: "+count+" advertised endpoints matched this IPv4 range. IPv6 is listed only when the same resolved service instance supplied both address families; IPv6 reachability was not tested.");}
            else LanServiceMerge.mergeNames(lan,result);
            synchronized(result){for(String note:result.notes)if(!dnsSd||note.contains("failed")||note.contains("could not")||note.contains("No matching"))lan.note(note);}
            parent.emit(lan);
        }catch(java.util.concurrent.ExecutionException unavailable){parent.check();lan.note(phase+" unavailable; probe results retained.");}
    }

    private static List<String> localResolvers(Context context,Report lan,Task parent) {
        List<String> result=new ArrayList<>();
        if(parent.hasRoute()) {
            String dns=parent.route().dnsServer();if(dns!=null&&!dns.isEmpty())result.add(dns);return result;
        }
        long[] bounds=Ip.range(lan.target);
        for(NetworkInventory.Connection connection:NetworkInventory.snapshot(context)) {
            if(!connection.kind.equals("Wi-Fi")&&!connection.kind.equals("Ethernet"))continue;
            boolean matches=false;
            for(String cidr:connection.ipv4Cidrs)try {
                String[] parts=cidr.split("/");long mask=Ip.mask(Integer.parseInt(parts[1])),network=Ip.parse(parts[0])&mask,end=network|(0xffffffffL^mask);
                if(bounds[0]>=network&&bounds[1]<=end)matches=true;
            }catch(IllegalArgumentException malformed){ }
            if(matches&&connection.properties!=null)for(java.net.InetAddress dns:connection.properties.getDnsServers()) {
                String address=dns.getHostAddress();if(!result.contains(address))result.add(address);
            }
        }
        return result;
    }
}
