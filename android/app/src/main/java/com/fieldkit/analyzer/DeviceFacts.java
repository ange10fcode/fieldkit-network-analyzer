package com.fieldkit.analyzer;

import java.util.ArrayList;
import java.util.List;

/** Evidence-backed labels. An IP address or open port cannot reveal Bluetooth support or device class. */
public final class DeviceFacts {
    private DeviceFacts() { }
    public static final class Tag {
        public final String label, kind, evidence;
        Tag(String label,String kind,String evidence) { this.label=label;this.kind=kind;this.evidence=evidence; }
    }
    public static List<Tag> tags(List<String> row,String[] columns) {
        List<Tag> result=new ArrayList<>();
        String ip=cell(row,0),flags=cell(row,2),ports=cell(row,6),advertised=cell(row,8);
        try { Ip.parse(ip);result.add(new Tag("IPv4","ipv4","IPv4 address observed in this scan: "+ip)); }
        catch(IllegalArgumentException ignored) { }
        int ipv6=-1;for(int i=0;i<columns.length;i++)if("IPv6 advertised".equals(columns[i]))ipv6=i;
        if(ipv6>=0&&known(cell(row,ipv6)))result.add(new Tag("IPv6 advertised","ipv6","The same DNS-SD service advertised this IPv4 address and: "+cell(row,ipv6)+". IPv6 connectivity was not tested."));
        if(flags.contains("G"))result.add(new Tag("Gateway","gateway","Matches the configured IPv4 gateway for the selected network."));
        if(flags.contains("S"))result.add(new Tag("This phone","self","Matches this phone's IPv4 address on the selected network."));
        if(ports.matches("\\d+(?:\\s*,\\s*\\d+)*"))result.add(new Tag("TCP open","tcp","Accepted TCP connections on ports "+ports+" during this scan."));
        if(known(advertised))result.add(new Tag("Service advertised","advertised","Local service or device advertisements were received. Advertised ports are separate from confirmed open TCP ports."));
        return result;
    }
    private static String cell(List<String> row,int index) { return index>=0&&index<row.size()&&row.get(index)!=null?row.get(index):""; }
    private static boolean known(String text) { return !text.isEmpty()&&!text.equals("—")&&!text.equalsIgnoreCase("unknown"); }
}
