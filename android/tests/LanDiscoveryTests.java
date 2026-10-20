package com.fieldkit.analyzer;

import java.net.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.*;

/** Real loopback listeners establish what the LAN device's open-port columns mean. */
public final class LanDiscoveryTests {
    static int checks;
    static void check(boolean condition,String message){checks++;if(!condition)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception {
        InetAddress loop=InetAddress.getByName("127.0.0.1");
        AtomicInteger accepted=new AtomicInteger();
        try(ServerSocket first=new ServerSocket(0,8,loop);ServerSocket second=new ServerSocket(0,8,loop)) {
            first.setSoTimeout(2000);second.setSoTimeout(2000);
            AtomicReference<Throwable> failure=new AtomicReference<>();
            Thread a=accept(first,accepted,failure),b=accept(second,accepted,failure);
            int closed;try(ServerSocket reserve=new ServerSocket(0,1,loop)){closed=reserve.getLocalPort();}
            String requested=first.getLocalPort()+","+second.getLocalPort()+","+closed;
            Report report=NetworkTools.lan("127.0.0.1",100,1,false,"","",requested,new Task(null));
            a.join(2500);b.join(2500);
            check(failure.get()==null&&accepted.get()==2,"Every requested open listener really accepted a connection");
            check(report.rows.size()==1,"One actual local device discovered");
            List<String> row=report.rows.get(0);
            check(row.size()==10&&report.columns[9].equals("IPv6 advertised")&&row.get(9).equals("—"),"LAN inventory retains port/advertisement columns and leaves unobserved IPv6 unknown");
            check(row.get(0).equals("127.0.0.1")&&row.get(1).equals("—"),"IP is observed and disabled name lookup does not invent a name");
            Set<String> opened=new HashSet<>(Arrays.asList(row.get(6).split(", ")));
            check(opened.equals(new HashSet<>(Arrays.asList(String.valueOf(first.getLocalPort()),String.valueOf(second.getLocalPort())))),"Both actual listeners are open and refused port is excluded");
            check(row.get(7).contains(String.valueOf(first.getLocalPort()))&&row.get(7).contains(String.valueOf(second.getLocalPort())),"Every open port has its own conventional label");
            check(row.get(8).equals("—"),"TCP connections do not fabricate advertised services");
            check(report.text().contains("do not verify the running protocol"),"Port labels are explicitly not protocol identification");
            Report refused=NetworkTools.lan("127.0.0.1",100,1,false,"","",String.valueOf(closed),new Task(null));
            check(refused.rows.size()==1&&refused.rows.get(0).get(6).equals("None found in 1 tested"),"A refused response proves host presence but no open service");
            check(refused.rows.get(0).get(7).equals("—"),"Closed ports never become service labels");
            boolean bounded=false;try{NetworkTools.lan("127.0.0.1",100,1,false,"","","1-65",new Task(null));}catch(IllegalArgumentException expected){bounded=expected.getMessage().contains("64 TCP ports");}
            check(bounded,"LAN service work is bounded; full scans belong to Ports");
        }
        check(Ip.ports(NetworkTools.LAN_COMMON_PORTS).length==18,"Common preset includes engineering, camera and printer ports");
        RouteTests.Route unresponsive=new RouteTests.Route();unresponsive.closeTcp=true;Task quick=new Task(null);quick.route(unresponsive);
        Report missing=NetworkTools.lan("127.0.0.1",100,1,false,"","",NetworkTools.LAN_COMMON_PORTS,true,quick);
        check(unresponsive.tcp.get()==4&&missing.rows.isEmpty(),"Common mode does not inspect 18 services on every silent address");
        RouteTests.Route known=new RouteTests.Route();known.closeTcp=true;Task responsive=new Task(null);responsive.route(known);
        Report self=NetworkTools.lan("127.0.0.1",100,1,false,"127.0.0.1","",NetworkTools.LAN_COMMON_PORTS,true,responsive);
        check(known.tcp.get()==18&&self.rows.size()==1,"Known responsive device receives all common port checks");
        RouteTests.Route custom=new RouteTests.Route();custom.closeTcp=true;Task explicit=new Task(null);explicit.route(custom);
        NetworkTools.lan("127.0.0.1",100,1,false,"","",NetworkTools.LAN_COMMON_PORTS,false,explicit);
        check(custom.tcp.get()==18,"Explicit Custom mode checks every requested port even on silent addresses");
        System.out.println("LanDiscoveryTests: "+checks+" checks passed (real open/closed TCP inventory, names, labels, bounds).");
    }
    private static Thread accept(ServerSocket server,AtomicInteger count,AtomicReference<Throwable> failure){
        Thread thread=new Thread(()->{try{server.accept().close();count.incrementAndGet();}catch(Throwable error){failure.set(error);}},"LAN listener fixture");thread.setDaemon(true);thread.start();return thread;
    }
}
