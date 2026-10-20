package com.fieldkit.analyzer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class DeviceFactsTests {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    public static void main(String[] args) {
        String[] columns={"IP address","Name","Flags","Probe response ms","Evidence","Web endpoint","Open TCP ports","Common service labels","Advertised services","IPv6 advertised"};
        List<String> row=Arrays.asList("192.168.7.1","router.example","GSA","2","TCP 80 accepted","http://192.168.7.1","80, 443","HTTP; HTTPS","Printer · _ipp._tcp · TCP 631 (advertised)","fe80::1");
        List<DeviceFacts.Tag> tags=DeviceFacts.tags(row,columns);List<String> labels=new ArrayList<>();
        for(DeviceFacts.Tag tag:tags){labels.add(tag.label);check(!tag.evidence.isEmpty(),"each badge has inspectable provenance");}
        check(labels.containsAll(Arrays.asList("IPv4","IPv6 advertised","Gateway","This phone","TCP open","Service advertised")),"all actual evidence represented");
        check(!labels.contains("Bluetooth")&&!labels.contains("Printer"),"IP and conventional ports do not invent radio capabilities or device type");
        check(tags.get(1).evidence.contains("not tested"),"IPv6 advertisement does not claim successful IPv6 probe");
        List<String> unknown=Arrays.asList("192.168.7.2","—","","—","—","—","None found in 4 tested","—","—","—");
        check(DeviceFacts.tags(unknown,columns).size()==1,"missing evidence leaves only IPv4 badge");
        check(DeviceFacts.tags(Arrays.asList(""),columns).isEmpty(),"short and older reports remain safe");

        Report lan=new Report("LAN scan","192.168.7.1-192.168.7.5",columns);
        lan.add("192.168.7.1","router.example","G","2","TCP 80 accepted","http://192.168.7.1","80","HTTP","—","—");
        Report services=new Report("Bonjour","","Service","Type","Address","Port","TXT / status");
        services.add("Office Printer","_ipp._tcp.","192.168.7.2, fe80::42%wlan0, 2001:db8::42","631","");
        services.add("IPv6-only device","_http._tcp.","2001:db8::99","80","");
        services.add("Other device","_http._tcp.","192.168.8.3,2001:db8::100","80","");
        check(LanServiceMerge.merge(lan,services)==1,"only actual in-range IPv4 service joined");
        check(lan.rows.size()==2,"IPv6-only or out-of-range instance not falsely joined");
        check(lan.rows.get(1).get(9).contains("2001:db8::42")&&lan.rows.get(1).get(9).contains("fe80::42%wlan0"),"same-instance IPv6 address recorded alongside IPv4");
        check(lan.rows.get(0).get(9).equals("—"),"no unrelated host IPv6 association");
        check(LanServiceMerge.merge(lan,services)==0,"repeat service merge deduplicates");
        Report names=new Report("Local device names","","IP address","Name","Source","Details");
        names.add("192.168.7.1","Overwrite attempt","UPnP","Device-provided");
        names.add("192.168.7.2","PRINTER-PC","NetBIOS","Unique workstation");
        names.add("192.168.7.3","Living Room TV","UPnP","Device-provided friendlyName");
        names.add("192.168.7.4","Not-discovered","NetBIOS","Unsolicited unicast name");
        names.add("192.168.8.1","Out of range","UPnP","");
        check(LanServiceMerge.mergeNames(lan,names)==1,"only unknown in-range device gains name");
        check(lan.rows.get(0).get(1).equals("router.example"),"existing PTR name retained");
        check(lan.rows.get(1).get(1).equals("Office Printer (mDNS)"),"advertised service name retained over later name source");
        List<String> tv=lan.rows.get(2);check(tv.get(1).equals("Living Room TV (UPnP)")&&tv.get(6).equals("—"),"UPnP friendly name is actual advertisement, not invented open TCP evidence");
        check(tv.size()==columns.length&&tv.get(9).equals("—"),"new advertisement row keeps ten-column contract");
        check(lan.rows.size()==3,"unicast name cannot add an unprobed host and out-of-range name omitted");
        check(LanServiceMerge.mergeNames(lan,names)==0,"repeated name merging does not overwrite labels");
        System.out.println("DeviceFactsTests: "+checks+" checks passed (badge provenance, linked dual-stack service evidence and name merging).");
    }
}
