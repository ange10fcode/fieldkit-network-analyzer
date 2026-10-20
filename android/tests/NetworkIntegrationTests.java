package com.fieldkit.analyzer;

import java.net.*;
import java.util.concurrent.atomic.*;
import java.util.*;

/** Actual loopback socket integration, not mocked probe results. */
public final class NetworkIntegrationTests {
    static int assertions;
    static void check(boolean c,String m){assertions++;if(!c)throw new AssertionError(m);}
    public static void main(String[] args)throws Exception {
        InetAddress loop=InetAddress.getByName("127.0.0.1");
        AtomicBoolean active=new AtomicBoolean(true);
        try(ServerSocket server=new ServerSocket(0,20,loop)) {
            Thread accept=new Thread(()->{while(active.get())try{server.accept().close();}catch(Exception e){if(active.get())throw new RuntimeException(e);}});accept.setDaemon(true);accept.start();
            int open=server.getLocalPort(),closed;
            try(ServerSocket reserve=new ServerSocket(0,1,loop)){closed=reserve.getLocalPort();}
            Report scan=NetworkTools.ports("127.0.0.1",open+","+closed,500,2,new Task(null));
            Map<Integer,String> statuses=new HashMap<>();for(List<String> row:scan.rows)statuses.put(Integer.parseInt(row.get(0)),row.get(2));
            check("Open".equals(statuses.get(open)),"live listening TCP port is open");check("Closed".equals(statuses.get(closed)),"live refused TCP port is closed");
            check(scan.detail.contains("100.00%"),"completed scan progress");
            Report ping=NetworkTools.ping("127.0.0.1","TCP",3,100,500,56,open,"IPv4",false,new Task(null));
            check(ping.rows.size()==3,"three actual TCP probes");for(List<String> row:ping.rows){check("Connected".equals(row.get(2)),"TCP connection evidence");check(Double.parseDouble(row.get(3))>=0,"nonnegative measured RTT");}
            check(ping.detail.contains("loss 0.00%"),"accurate measured loss");
            AtomicInteger emitted=new AtomicInteger();AtomicReference<Task> ref=new AtomicReference<>();Task cancel=new Task(r->{if(emitted.incrementAndGet()>=3)ref.get().cancel();});ref.set(cancel);
            boolean cancelled=false;long start=System.nanoTime();try{NetworkTools.ping("127.0.0.1","TCP",0,100,500,56,open,"IPv4",false,cancel);}catch(InterruptedException e){cancelled=true;}
            check(cancelled,"continuous probe can stop");check((System.nanoTime()-start)/1e9<3,"stop is prompt");
            Report lan=NetworkTools.lan("127.0.0.1",100,1,false,"127.0.0.1","",new Task(null));
            check(lan.rows.size()==1&&lan.rows.get(0).get(2).contains("S"),"LAN recognizes current device with evidence");
            active.set(false);
        }
        try(DatagramSocket receiver=new DatagramSocket(0,loop)) {
            receiver.setSoTimeout(2000);Report wol=NetworkTools.wol("01:23:45:67:89:AB","127.0.0.1",receiver.getLocalPort(),new Task(null));
            byte[] buffer=new byte[200];DatagramPacket packet=new DatagramPacket(buffer,buffer.length);receiver.receive(packet);
            check(packet.getLength()==102,"actual WOL datagram length");byte[] expected=Ip.magicPacket("01:23:45:67:89:AB");
            check(Arrays.equals(expected,Arrays.copyOf(buffer,packet.getLength())),"actual WOL bytes match magic packet");check(wol.text().contains("does not confirm"),"transmission does not claim wake success");
        }
        System.out.println("NetworkIntegrationTests: "+assertions+" assertions passed");
    }
}
