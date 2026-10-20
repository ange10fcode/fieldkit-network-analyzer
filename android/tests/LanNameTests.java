package com.fieldkit.analyzer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class LanNameTests {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception {
        int id=0x47a2;byte[] request=LanNameDiscovery.nodeStatusRequest(id);
        check(request.length==50,"RFC1002 wildcard node-status request length");
        check(new String(request,13,32,StandardCharsets.US_ASCII).equals("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),"wildcard name encoded without a broadcast scan");
        byte[] reply=nodeStatus(id,"OFFICE-PC");
        check(LanNameDiscovery.parseNodeStatus(reply,id).equals("OFFICE-PC"),"unique workstation selected; group and server suffix names ignored");
        check(LanNameDiscovery.parseNodeStatus(nodeStatus(id,""),id).isEmpty(),"no unique workstation name means unknown");
        rejects(()->LanNameDiscovery.parseNodeStatus(reply,id+1),"wrong transaction rejected");
        rejects(()->LanNameDiscovery.parseNodeStatus(Arrays.copyOf(reply,reply.length-48),id),"truncated name table rejected");
        byte[] badCount=reply.clone();badCount[6]=127;rejects(()->LanNameDiscovery.parseNodeStatus(badCount,id),"invalid answer count rejected");

        AtomicReference<Throwable> failure=new AtomicReference<>();
        try(DatagramSocket server=new DatagramSocket(0,InetAddress.getLoopbackAddress())) {
            Thread fixture=new Thread(()->{
                try {
                    byte[] bytes=new byte[1024];DatagramPacket packet=new DatagramPacket(bytes,bytes.length);server.receive(packet);
                    check(packet.getLength()==50&&bytes[47]==0x21,"actual UDP request uses NBSTAT question type");
                    int actual=((bytes[0]&255)<<8)|(bytes[1]&255);byte[] response=nodeStatus(actual,"LAB-LAPTOP");
                    server.send(new DatagramPacket(response,response.length,packet.getSocketAddress()));
                }catch(Throwable error){failure.set(error);}
            },"nbstat-local-fixture");fixture.start();
            String found=LanNameDiscovery.netbios("127.0.0.1",server.getLocalPort(),1000,new Task(null));fixture.join(2000);
            check(found.equals("LAB-LAPTOP"),"real localhost UDP fixture produces computer name");
            if(failure.get()!=null)throw new AssertionError(failure.get());
        }
        try(DatagramSocket server=new DatagramSocket(0,InetAddress.getLoopbackAddress())) {
            Thread fixture=new Thread(()->{
                try {
                    byte[] bytes=new byte[4096];DatagramPacket packet=new DatagramPacket(bytes,bytes.length);server.receive(packet);
                    byte[] response=ptrReply(Arrays.copyOf(bytes,packet.getLength()),"printer.office.example");
                    server.send(new DatagramPacket(response,response.length,packet.getSocketAddress()));
                }catch(Throwable error){failure.set(error);}
            },"ptr-local-fixture");fixture.start();
            check(LanNameDiscovery.ptr("192.168.7.2","127.0.0.1",server.getLocalPort(),1000,new Task(null)).equals("printer.office.example"),"real local resolver fixture supplies PTR hostname");
            fixture.join(2000);if(failure.get()!=null)throw new AssertionError(failure.get());
        }
        try(DatagramSocket quiet=new DatagramSocket(0,InetAddress.getLoopbackAddress())) {
            long start=System.nanoTime();check(LanNameDiscovery.netbios("127.0.0.1",quiet.getLocalPort(),120,new Task(null)).isEmpty(),"quiet responder leaves name unknown");
            check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start)<700,"node-status timeout is bounded");
            Task task=new Task(null);Thread stop=new Thread(()->{try{Thread.sleep(80);task.cancel();}catch(InterruptedException ignored){}});stop.start();
            boolean cancelled=false;try{LanNameDiscovery.netbios("127.0.0.1",quiet.getLocalPort(),1500,task);}catch(Exception expected){cancelled=task.isCancelled();}
            check(cancelled,"cancellation closes an in-flight naming socket");stop.join();
        }
        System.out.println("LanNameTests: "+checks+" checks passed (RFC1002 parsing, actual UDP names/PTR, bounded timeout and cancellation).");
    }

    private static byte[] nodeStatus(int id,String computer)throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.writeShort(id);out.writeShort(0x8400);out.writeShort(0);out.writeShort(1);out.writeInt(0);
        byte[] request=LanNameDiscovery.nodeStatusRequest(id);out.write(request,12,34);out.writeShort(0x21);out.writeShort(1);out.writeInt(0);out.writeShort(1+3*18+46);out.writeByte(3);
        entry(out,"WORKGROUP",0,0x8400);entry(out,"PRINT-SERVER",0x20,0x0400);entry(out,computer,0,0x0400);out.write(new byte[46]);return bytes.toByteArray();
    }
    private static void entry(DataOutputStream out,String name,int suffix,int flags)throws IOException {
        byte[] padded=new byte[15];Arrays.fill(padded,(byte)' ');byte[] bytes=name.getBytes(StandardCharsets.US_ASCII);System.arraycopy(bytes,0,padded,0,Math.min(bytes.length,padded.length));out.write(padded);out.writeByte(suffix);out.writeShort(flags);
    }
    private static byte[] ptrReply(byte[] query,String hostname)throws IOException {
        int end=12;while(query[end]!=0)end+=1+(query[end]&255);end+=5;
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.write(query,0,2);out.writeShort(0x8180);out.writeShort(1);out.writeShort(1);out.writeInt(0);out.write(query,12,end-12);
        out.writeShort(0xc00c);out.writeShort(12);out.writeShort(1);out.writeInt(60);
        ByteArrayOutputStream name=new ByteArrayOutputStream();for(String part:hostname.split("\\.")){name.write(part.length());name.write(part.getBytes(StandardCharsets.US_ASCII));}name.write(0);
        out.writeShort(name.size());out.write(name.toByteArray());return bytes.toByteArray();
    }
    private interface Throwing { void run()throws Exception; }
    private static void rejects(Throwing action,String message)throws Exception { boolean rejected=false;try{action.run();}catch(IOException expected){rejected=true;}check(rejected,message); }
}
