package com.fieldkit.analyzer;

import java.util.List;

public final class LanServiceMergeTests {
    private static int checks;
    private static void check(boolean condition,String message){checks++;if(!condition)throw new AssertionError(message);}
    public static void main(String[] args) {
        Report lan = new Report("LAN scan","192.168.7.1-192.168.7.10","IP address","Name (PTR / advertised)","Flags","Probe response ms","Evidence","Web endpoint","Open TCP ports","Common service labels","Advertised services");
        lan.add("192.168.7.2","printer.example","W","2","TCP 80 accepted","http://192.168.7.2","80","HTTP","—");
        Report services = new Report("Bonjour / mDNS","","Service","Type","Address","Port","TXT / status");
        services.add("Office Printer","_ipp._tcp.","192.168.7.2","631","");
        services.add("Office Printer","_ipp._tcp.","192.168.7.2","631","");
        services.add("Desk PC","_ssh._tcp.","192.168.7.3, fe80::1","22","");
        services.add("Out of scope","_http._tcp.","192.168.8.1","80","");
        services.add("Unresolved","_http._tcp.","Unresolved","80","");
        services.add("Invalid port","_http._tcp.","192.168.7.4","0","");
        check(LanServiceMerge.merge(lan,services)==2,"only unique in-range IPv4 endpoints merged");
        check(lan.rows.size()==2,"one service-only host added");
        List<String> printer=lan.rows.get(0),pc=lan.rows.get(1);
        check(printer.get(1).equals("printer.example"),"PTR hostname preserved");
        check(printer.get(6).equals("80"),"advertised 631 not claimed as open TCP");
        check(printer.get(8).contains("631 (advertised)"),"advertised endpoint labeled");
        check(printer.get(2).equals("WA"),"advertisement evidence marked");
        check(pc.get(1).equals("Desk PC (mDNS)"),"service name provenance visible");
        check(pc.get(6).equals("—")&&pc.get(3).equals("—"),"service-only device has no fabricated open port or RTT");
        check(pc.get(4).contains("not established"),"service-only TCP evidence honest");
        check(LanServiceMerge.merge(lan,services)==0,"repeat merge deduplicates");
        Report singleton=new Report("LAN scan","192.168.7.3",lan.columns);
        check(LanServiceMerge.merge(singleton,services)==1&&singleton.rows.size()==1,"single-host scope obeyed");
        Report old=new Report("LAN scan","192.168.7.3","IP","Name");
        check(LanServiceMerge.merge(old,services)==0,"older report column shape safe");
        System.out.println("LanServiceMergeTests: "+checks+" checks passed (range, deduplication and evidence provenance).");
    }
}
