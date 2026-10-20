package com.fieldkit.analyzer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashSet;
import java.net.Inet6Address;
import java.net.InetAddress;

/** Joins actual DNS-SD advertisements to the requested scan range without claiming open ports. */
public final class LanServiceMerge {
    private LanServiceMerge() {}

    public static int merge(Report lan, Report services) {
        if (lan.columns.length < 9) return 0;
        long[] bounds = Ip.range(lan.target);
        List<List<String>> advertised = new ArrayList<>();
        synchronized (services) {
            for (List<String> row : services.rows) advertised.add(new ArrayList<>(row));
        }
        int added = 0;
        synchronized (lan) {
            Map<String,List<String>> devices = new LinkedHashMap<>();
            for (int i=0;i<lan.rows.size();i++) {
                List<String> row=mutable(lan,lan.rows.get(i));lan.rows.set(i,row);
                if (!row.isEmpty()) devices.put(row.get(0), row);
            }
            for (List<String> service : advertised) {
                if (service.size() < 4) continue;
                String name = clean(service.get(0)), type = clean(service.get(1));
                String port = clean(service.get(3));
                try { int number = Integer.parseInt(port); if (number < 1 || number > 65535) continue; }
                catch (NumberFormatException invalid) { continue; }
                String transport = type.contains("._udp") ? "UDP" : "TCP";
                String endpoint = name + " · " + type + " · " + transport + " " + port + " (advertised)";
                LinkedHashSet<String> v6=new LinkedHashSet<>();
                for(String address:service.get(2).split("[,\\s]+")) {
                    if(!address.contains(":"))continue;
                    String literal=address.contains("%")?address.substring(0,address.indexOf('%')):address;
                    try { if(InetAddress.getByName(literal) instanceof Inet6Address)v6.add(address); }
                    catch(Exception invalid) { }
                }
                for (String address : service.get(2).split("[,\\s]+")) {
                    long numeric;
                    try { numeric = Ip.parse(address); } catch (IllegalArgumentException invalid) { continue; }
                    if (numeric < bounds[0] || numeric > bounds[1]) continue;
                    String ip = Ip.format(numeric);
                    List<String> device = devices.get(ip);
                    if (device == null) {
                        device = new ArrayList<>(Arrays.asList(ip,"—","A","—",
                                "mDNS advertisement; TCP reachability not established","—","—","—","—"));
                        device=mutable(lan,device);lan.rows.add(device); devices.put(ip, device);
                    }
                    if (device.size() < 9) continue;
                    String previous = device.get(8);
                    appendIpv6(lan,device,v6);
                    if (!previous.equals("—") && Arrays.asList(previous.split("\\n")).contains(endpoint)) continue;
                    device.set(8, previous.equals("—") || previous.isEmpty() ? endpoint : previous + "\n" + endpoint);
                    if ((device.get(1).equals("—") || device.get(1).isEmpty()) && !name.isEmpty())
                        device.set(1, name + " (mDNS)");
                    if (!device.get(2).contains("A")) device.set(2, device.get(2) + "A");
                    added++;
                }
            }
        }
        return added;
    }

    /** Names contain IP, name, source and details. SSDP names are advertisements, never open ports. */
    public static int mergeNames(Report lan,Report names) {
        if(lan.columns.length<9)return 0;
        long[] bounds=Ip.range(lan.target);int count=0;
        synchronized(lan) {
            Map<String,List<String>> devices=new LinkedHashMap<>();
            for(int i=0;i<lan.rows.size();i++){List<String> row=mutable(lan,lan.rows.get(i));lan.rows.set(i,row);if(!row.isEmpty())devices.put(row.get(0),row);}
            List<List<String>> rows=new ArrayList<>();synchronized(names){for(List<String> row:names.rows)rows.add(new ArrayList<>(row));}
            for(List<String> name:rows) {
                if(name.size()<4)continue;String ip=name.get(0),label=clean(name.get(1)),source=clean(name.get(2)),details=clean(name.get(3));
                long numeric;try{numeric=Ip.parse(ip);}catch(IllegalArgumentException invalid){continue;}
                if(numeric<bounds[0]||numeric>bounds[1]||label.isEmpty()||label.equals("—"))continue;
                boolean ssdp=source.equals("UPnP");List<String> device=devices.get(ip);
                if(device==null) {
                    if(!ssdp)continue;
                    device=mutable(lan,new ArrayList<>(Arrays.asList(ip,"—","A","—","SSDP advertisement; TCP reachability not established","—","—","—","—")));
                    lan.rows.add(device);devices.put(ip,device);
                }
                String evidence=source+" name: "+label+(details.isEmpty()?"":" · "+details);
                if(!containsLine(device.get(4),evidence))device.set(4,unknown(device.get(4))?evidence:device.get(4)+"\n"+evidence);
                if(unknown(device.get(1))){device.set(1,label+(source.equals("Local DNS PTR")?"":" ("+source+")"));count++;}
                if(ssdp) {
                    String endpoint=label+" · UPnP device advertisement";
                    if(!containsLine(device.get(8),endpoint))device.set(8,unknown(device.get(8))?endpoint:device.get(8)+"\n"+endpoint);
                    if(!device.get(2).contains("A"))device.set(2,device.get(2)+"A");
                }
            }
        }
        return count;
    }

    private static void appendIpv6(Report lan,List<String> device,LinkedHashSet<String> addresses) {
        if(addresses.isEmpty())return;int index=-1;for(int i=0;i<lan.columns.length;i++)if("IPv6 advertised".equals(lan.columns[i]))index=i;
        if(index<0||device.size()<=index)return;LinkedHashSet<String> all=new LinkedHashSet<>();
        if(!unknown(device.get(index)))all.addAll(Arrays.asList(device.get(index).split("\\n")));
        all.addAll(addresses);device.set(index,String.join("\n",all));
    }
    private static List<String> mutable(Report lan,List<String> row) { List<String> copy=new ArrayList<>(row);while(copy.size()<lan.columns.length)copy.add("—");return copy; }
    private static boolean unknown(String value) { return value==null||value.isEmpty()||value.equals("—"); }
    private static boolean containsLine(String value,String line) { return Arrays.asList(value.split("\\n")).contains(line); }

    private static String clean(String value) {
        if (value == null) return "";
        String text = value.replaceAll("[\\p{Cntrl}]", " ").trim();
        return text.length() > 180 ? text.substring(0,180) : text;
    }
}
