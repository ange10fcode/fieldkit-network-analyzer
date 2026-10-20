package com.fieldkit.analyzer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Root-free, bounded local naming. Queries retain the caller's Android/VPN routing policy. */
public final class LanNameDiscovery {
    private static final SecureRandom RANDOM=new SecureRandom();
    private LanNameDiscovery() { }

    public static Report discover(Report lan,List<String> resolvers,Task task)throws Exception {
        Report result=new Report("Local device names",lan.target,"IP address","Name","Source","Details");
        List<String> addresses=new ArrayList<>();
        synchronized(lan) { for(List<String> row:lan.rows)if(row.size()>1&&(row.get(1).isEmpty()||row.get(1).equals("—"))) {
            try{Ip.parse(row.get(0));addresses.add(row.get(0));}catch(IllegalArgumentException invalid){ }
            if(addresses.size()>=128)break;
        } }
        ExecutorService workers=Executors.newFixedThreadPool(6);CompletionService<String[]> queue=new ExecutorCompletionService<>(workers);
        Task child=new Task(null);child.route(task.route());java.io.Closeable stop=child::cancel;task.register(stop);
        int submitted=0,done=0;long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);
        try {
            while(submitted<Math.min(6,addresses.size())){String ip=addresses.get(submitted++);queue.submit(()->name(ip,resolvers,child,deadline));}
            while(done<addresses.size()&&System.nanoTime()<deadline) {
                task.check();Future<String[]> answer=queue.poll(100,TimeUnit.MILLISECONDS);if(answer==null)continue;done++;
                try { String[] row=answer.get();if(row!=null)result.add(row); }
                catch(java.util.concurrent.ExecutionException failed) { task.check(); }
                if(submitted<addresses.size()){String ip=addresses.get(submitted++);queue.submit(()->name(ip,resolvers,child,deadline));}
            }
            result.note("Local naming checked "+done+" of "+addresses.size()+" unnamed responding devices within an 8-second budget. Local DNS PTR and unicast NetBIOS node-status responses are used; a missing response leaves the name unknown. No name is inferred from an IP address or an open port.");
            return result;
        } finally { child.cancel();task.unregister(stop);workers.shutdownNow(); }
    }

    private static String[] name(String ip,List<String> resolvers,Task task,long deadline)throws Exception {
        for(int i=0;i<Math.min(2,resolvers.size());i++) {
            task.check();if(System.nanoTime()>=deadline)return null;
            try { String name=ptr(ip,resolvers.get(i),53,Math.min(400,remaining(deadline)),task);
                if(!name.isEmpty())return new String[]{ip,name,"Local DNS PTR","Resolver "+resolvers.get(i)+"; current probe routing policy"};
            } catch(IOException unavailable) { task.check(); }
        }
        if(System.nanoTime()>=deadline)return null;
        try { String name=netbios(ip,137,Math.min(700,remaining(deadline)),task);
            if(!name.isEmpty())return new String[]{ip,name,"NetBIOS","Unique workstation name returned by UDP node status"};
        } catch(IOException unavailable) { task.check(); }
        return null;
    }

    static String ptr(String ip,String server,int port,int timeout,Task task)throws Exception {
        int id=RANDOM.nextInt(65536);String expected=DnsClient.reverse(ip);
        byte[] reply=exchange(DnsClient.queryPacket(expected,12,true,id),server,port,timeout,task,id);
        if(reply==null)return "";DnsClient.Response response=DnsClient.parse(reply,id);
        if(response.rcode!=0||(response.flags&0x0200)!=0)return "";
        for(DnsClient.Record record:response.records)if(record.type==12&&record.recordClass==1&&record.section.equals("Answer")&&record.name.equalsIgnoreCase(expected)) {
            String value=record.value.trim();if(value.length()>253||value.isEmpty()||value.matches(".*[\\p{Cntrl}].*"))return "";
            return value.endsWith(".")?value.substring(0,value.length()-1):value;
        }
        return "";
    }

    static String netbios(String ip,int port,int timeout,Task task)throws Exception {
        int id=RANDOM.nextInt(65536);byte[] reply=exchange(nodeStatusRequest(id),ip,port,timeout,task,id);
        return reply==null?"":parseNodeStatus(reply,id);
    }

    private static byte[] exchange(byte[] query,String address,int port,int timeout,Task task,int id)throws Exception {
        task.check();if(timeout<1)return null;
        // Literal addresses only: local naming never bootstraps a resolver through another DNS service.
        if(!address.contains(":"))Ip.parse(address);
        InetAddress endpoint=InetAddress.getByName(address);DatagramSocket socket=new DatagramSocket();task.register(socket);
        long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeout);
        try {
            task.bind(socket);socket.connect(endpoint,port);socket.send(new DatagramPacket(query,query.length));
            while(System.nanoTime()<deadline) {
                task.check();socket.setSoTimeout(Math.min(100,remaining(deadline)));
                byte[] buffer=new byte[8192];DatagramPacket packet=new DatagramPacket(buffer,buffer.length);
                try { socket.receive(packet);if(packet.getLength()>=12&&u16(buffer,0)==id)return Arrays.copyOf(buffer,packet.getLength()); }
                catch(SocketTimeoutException ignored){ }
            }
            return null;
        } finally {task.unregister(socket);socket.close();}
    }

    static byte[] nodeStatusRequest(int id)throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.writeShort(id);out.writeShort(0);out.writeShort(1);out.writeShort(0);out.writeShort(0);out.writeShort(0);
        byte[] wildcard=new byte[16];wildcard[0]='*';out.writeByte(32);
        for(byte b:wildcard){out.writeByte('A'+((b&255)>>>4));out.writeByte('A'+(b&15));}
        out.writeByte(0);out.writeShort(0x21);out.writeShort(1);return bytes.toByteArray();
    }

    /** RFC1002 NBSTAT. Group/domain entries and non-workstation suffixes never become a device name. */
    static String parseNodeStatus(byte[] packet,int id)throws IOException {
        if(packet==null||packet.length<12||u16(packet,0)!=(id&65535)||(u16(packet,2)&0x800f)!=0x8000||(u16(packet,2)&0x7800)!=0)throw new IOException("Invalid NetBIOS response header");
        int questions=u16(packet,4),answers=u16(packet,6),position=12;
        if(questions>1||answers<1||answers>16)throw new IOException("Invalid NetBIOS record count");
        for(int i=0;i<questions;i++){position=skipName(packet,position);need(packet,position,4);if(u16(packet,position)!=0x21||u16(packet,position+2)!=1)throw new IOException("Wrong NetBIOS question");position+=4;}
        for(int i=0;i<answers;i++) {
            position=skipName(packet,position);need(packet,position,10);int type=u16(packet,position),cls=u16(packet,position+2),length=u16(packet,position+8);position+=10;need(packet,position,length);
            if(type==0x21&&cls==1&&length>0) {
                int count=packet[position]&255;if(1+count*18>length)throw new IOException("Truncated NetBIOS name table");
                for(int j=0;j<count;j++) {
                    int start=position+1+j*18,suffix=packet[start+15]&255,flags=u16(packet,start+16);
                    if(suffix!=0||(flags&0x8000)!=0)continue;
                    String name=new String(packet,start,15,StandardCharsets.US_ASCII).trim();
                    if(!name.isEmpty()&&!name.equals("*")&&name.matches("[A-Za-z0-9][A-Za-z0-9 _.-]{0,14}"))return name;
                }
            }
            position+=length;
        }
        return "";
    }
    private static int skipName(byte[] packet,int position)throws IOException {
        for(int labels=0;labels<128;labels++) {
            need(packet,position,1);int length=packet[position++]&255;if(length==0)return position;
            if((length&0xc0)==0xc0){need(packet,position,1);int pointer=((length&63)<<8)|(packet[position]&255);if(pointer>=packet.length)throw new IOException("Invalid NetBIOS name pointer");return position+1;}
            if(length>63)throw new IOException("Invalid NetBIOS name label");need(packet,position,length);position+=length;
        }
        throw new IOException("NetBIOS name too long");
    }
    private static int remaining(long deadline) { return (int)Math.max(1,TimeUnit.NANOSECONDS.toMillis(Math.max(0,deadline-System.nanoTime()))); }
    private static int u16(byte[] bytes,int position) { return ((bytes[position]&255)<<8)|(bytes[position+1]&255); }
    private static void need(byte[] bytes,int position,int length)throws IOException { if(position<0||length<0||position>bytes.length-length)throw new IOException("Truncated NetBIOS packet"); }
}
