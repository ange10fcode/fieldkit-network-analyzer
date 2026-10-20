package com.fieldkit.analyzer;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

/** Direct DNS client, with bounded RFC 1035 compression parsing and TCP retry on TC. */
public final class DnsClient {
    private static final Map<String,Integer> TYPES = new LinkedHashMap<>();
    static {
        String[] names = {"A","NS","CNAME","SOA","PTR","HINFO","MX","TXT","AAAA","SRV","DS","SSHFP","RRSIG","NSEC","DNSKEY","NSEC3","SVCB","HTTPS","CAA"};
        int[] nums = {1,2,5,6,12,13,15,16,28,33,43,44,46,47,48,50,64,65,257};
        for (int i=0;i<names.length;i++) TYPES.put(names[i],nums[i]);
    }
    private DnsClient() {}
    public static int type(String name) {
        Integer t = TYPES.get(name == null ? "" : name.trim().toUpperCase(Locale.US));
        if (t == null) throw new IllegalArgumentException("Unsupported DNS record type.");
        return t;
    }
    public static String typeName(int type) {
        for (Map.Entry<String,Integer> t : TYPES.entrySet()) if (t.getValue() == type) return t.getKey();
        return type == 41 ? "OPT" : "TYPE" + type;
    }
    public static final class Record {
        public final String section, name, value;
        public final int type, recordClass;
        public final long ttl;
        Record(String section, String name, int type, int recordClass, long ttl, String value) {
            this.section=section; this.name=name; this.type=type; this.recordClass=recordClass; this.ttl=ttl; this.value=value;
        }
    }
    public static final class Response {
        public int id, flags, rcode;
        public long durationMs;
        public String server, transport="UDP";
        public final List<Record> records = new ArrayList<>();
        public String status() {
            String[] s={"NOERROR","FORMERR","SERVFAIL","NXDOMAIN","NOTIMP","REFUSED"};
            return rcode < s.length ? s[rcode] : "RCODE " + rcode;
        }
    }
    public static String reverse(String target) throws UnknownHostException {
        try {
            long v=Ip.parse(target);
            return (v&255)+"."+((v>>>8)&255)+"."+((v>>>16)&255)+"."+((v>>>24)&255)+".in-addr.arpa";
        } catch (IllegalArgumentException ignored) {}
        if (!target.contains(":")) return target;
        byte[] bytes=InetAddress.getByName(target).getAddress();
        if (bytes.length != 16) throw new IllegalArgumentException("Invalid IPv6 address for reverse lookup.");
        StringBuilder s=new StringBuilder();
        for (int i=bytes.length-1;i>=0;i--) { int n=bytes[i]&255; s.append(Integer.toHexString(n&15)).append('.').append(Integer.toHexString(n>>>4)).append('.'); }
        return s.append("ip6.arpa").toString();
    }
    public static byte[] queryPacket(String domain, int type, boolean recursive, int id) throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        DataOutputStream out=new DataOutputStream(bytes);
        out.writeShort(id); out.writeShort(recursive ? 0x0100 : 0); out.writeShort(1); out.writeShort(0); out.writeShort(0); out.writeShort(1);
        String s=domain.trim();
        if (s.endsWith(".")) s=s.substring(0,s.length()-1);
        if (!s.isEmpty()) {
            int length=1;
            for (String label:s.split("\\.",-1)) {
                if (label.isEmpty()) throw new IllegalArgumentException("DNS names may not have empty labels.");
                String ascii=IDN.toASCII(label);
                byte[] b=ascii.getBytes(StandardCharsets.US_ASCII);
                if (b.length>63 || b.length==0) throw new IllegalArgumentException("DNS label exceeds 63 bytes.");
                length += 1+b.length;
                if (length>255) throw new IllegalArgumentException("DNS name exceeds 255 bytes.");
                out.writeByte(b.length); out.write(b);
            }
        }
        out.writeByte(0); out.writeShort(type); out.writeShort(1);
        // EDNS0 with a conservative UDP size; DO requests DNSSEC material without claiming validation.
        out.writeByte(0); out.writeShort(41); out.writeShort(1232); out.writeInt(0x8000); out.writeShort(0);
        return bytes.toByteArray();
    }
    public static Response query(String name,String requestedType,String server,boolean recursive,Task task) throws Exception {
        return query(name,requestedType,server,53,recursive,task);
    }
    /** Test seam for a local authoritative fixture; production uses standard port 53. */
    static Response query(String name,String requestedType,String server,int port,boolean recursive,Task task) throws Exception {
        if(port<1||port>65535)throw new IllegalArgumentException("DNS port must be 1–65535.");
        task.check();
        int type=type(requestedType), id=new SecureRandom().nextInt(65536);
        String qname=type==12 ? reverse(name.trim()) : name.trim();
        if (server==null || server.trim().isEmpty()) throw new IllegalArgumentException("No DNS server is configured for this network. Enter a server IP address.");
        InetAddress[] servers=task.resolve(server.trim());
        if(servers.length==0)throw new UnknownHostException("The selected network returned no address for the DNS server.");
        InetAddress endpoint=servers[0];
        byte[] query=queryPacket(qname,type,recursive,id), result=null;
        long start=System.nanoTime(), deadline=System.nanoTime()+6000000000L;
        DatagramSocket socket=new DatagramSocket(); task.register(socket);
        try {
            task.bind(socket);task.check();socket.connect(endpoint,port); socket.setSoTimeout(500);
            socket.send(new DatagramPacket(query,query.length));
            while (result==null) {
                task.check();
                if (System.nanoTime()>deadline) throw new SocketTimeoutException("DNS server did not respond within 6 seconds.");
                byte[] buffer=new byte[65535]; DatagramPacket packet=new DatagramPacket(buffer,buffer.length);
                try {
                    socket.receive(packet);
                    if (packet.getLength()<12 || u16(buffer,0)!=id || (u16(buffer,2)&0x8000)==0) continue;
                    result=Arrays.copyOf(buffer,packet.getLength());
                } catch(SocketTimeoutException ignored) {}
            }
        } finally { task.unregister(socket); socket.close(); }
        boolean tcp=(u16(result,2)&0x0200)!=0;
        if (tcp) {
            Socket stream=task.newSocket();
            ScheduledExecutorService deadlineCloser=Executors.newSingleThreadScheduledExecutor();
            long tcpDeadline=System.nanoTime()+6000000000L;
            deadlineCloser.schedule(()->{try{stream.close();}catch(IOException ignored){}},6,TimeUnit.SECONDS);
            try {
                task.check();stream.connect(new InetSocketAddress(endpoint,port),6000); stream.setSoTimeout(6000);
                DataOutputStream out=new DataOutputStream(stream.getOutputStream()); out.writeShort(query.length); out.write(query); out.flush();
                DataInputStream in=new DataInputStream(stream.getInputStream()); int length=in.readUnsignedShort();
                if (length<12) throw new IOException("Truncated DNS-over-TCP response.");
                result=new byte[length]; in.readFully(result); task.check();
            } catch(IOException error) {
                if(System.nanoTime()>=tcpDeadline)throw new SocketTimeoutException("DNS TCP transaction exceeded 6 seconds.");
                throw error;
            } finally { deadlineCloser.shutdownNow();task.unregister(stream); stream.close(); }
        }
        Response response=parse(result,id);
        // A connected UDP socket binds the sender; validate echoed question as well as ID.
        Cursor cursor=new Cursor(result,12); String echoed=cursor.name(); int echoedType=cursor.u16(), echoedClass=cursor.u16();
        Cursor original=new Cursor(query,12);
        if (!echoed.equalsIgnoreCase(original.name()) || echoedType!=type || echoedClass!=1) throw new IOException("DNS server returned a mismatched question.");
        response.server=endpoint.getHostAddress(); response.durationMs=(System.nanoTime()-start)/1000000;
        response.transport=tcp ? "TCP (UDP response truncated)" : "UDP";
        return response;
    }
    public static Response parse(byte[] packet,int expectedId) throws IOException {
        if (packet==null || packet.length<12) throw new IOException("DNS packet is shorter than its header.");
        Cursor c=new Cursor(packet,0); Response r=new Response();
        r.id=c.u16(); r.flags=c.u16(); r.rcode=r.flags&15;
        if (r.id!=(expectedId&65535) || (r.flags&0x8000)==0 || (r.flags&0x7800)!=0) throw new IOException("Invalid DNS transaction ID or response header.");
        int questions=c.u16(), answers=c.u16(), authority=c.u16(), additional=c.u16();
        if (questions!=1) throw new IOException("DNS response must echo exactly one question.");
        if ((long) answers+authority+additional > packet.length/11L) throw new IOException("DNS record count exceeds packet length.");
        for (int i=0;i<questions;i++) { c.name(); c.skip(4); }
        int[] counts={answers,authority,additional}; String[] sections={"Answer","Authority","Additional"};
        for(int section=0;section<3;section++) for(int i=0;i<counts[section];i++) {
            String name=c.name(); int type=c.u16(), cls=c.u16(); long ttl=c.u32(); int length=c.u16();
            c.need(length); int end=c.pos+length; String value;
            try { value=decode(type,new Cursor(packet,c.pos),end); }
            catch (IOException | IllegalArgumentException malformed) { value="Malformed RDATA ("+malformed.getMessage()+"); raw hex: "+hex(packet,c.pos,end); }
            if (type==41) { r.rcode |= (int)((ttl>>>24)&255)<<4; value="EDNS version "+((ttl>>>16)&255)+"; UDP payload "+cls+"; DO="+((ttl&0x8000)!=0)+"; options="+hex(packet,c.pos,end); }
            r.records.add(new Record(sections[section],name,type,cls,ttl,value)); c.pos=end;
        }
        return r;
    }
    private static String decode(int t,Cursor c,int end) throws IOException {
        int start=c.pos; String out;
        switch(t) {
            case 1: if(end-c.pos!=4) throw new IOException("A length"); return InetAddress.getByAddress(c.bytes(4)).getHostAddress();
            case 28: if(end-c.pos!=16) throw new IOException("AAAA length"); return InetAddress.getByAddress(c.bytes(16)).getHostAddress();
            case 2: case 5: case 12: out=c.name(); break;
            case 15: out="preference="+c.u16()+" exchange="+c.name(); break;
            case 6: out="primary="+c.name()+" mailbox="+c.name()+" serial="+c.u32()+" refresh="+c.u32()+" retry="+c.u32()+" expire="+c.u32()+" minimum="+c.u32(); break;
            case 13: out="CPU="+c.text(end)+" OS="+c.text(end); break;
            case 16: {
                StringBuilder b=new StringBuilder(), flat=new StringBuilder();
                while(c.pos<end) { String text=c.text(end); if(b.length()>0)b.append(' '); b.append('"').append(text.replace("\"","\\\"")).append('"'); flat.append(text); }
                if(flat.toString().toLowerCase(Locale.US).startsWith("v=spf1"))b.append(" [SPF policy; mechanisms are published policy, not an authentication result]");
                out=b.toString(); break;
            }
            case 33: out="priority="+c.u16()+" weight="+c.u16()+" port="+c.u16()+" target="+c.name(); break;
            case 257: { int flags=c.u8(); int length=c.u8(); out="flags="+flags+" tag="+new String(c.bytes(length),StandardCharsets.US_ASCII)+" value="+new String(c.bytes(end-c.pos),StandardCharsets.UTF_8); break; }
            case 44: out="algorithm="+c.u8()+" fingerprint-type="+c.u8()+" fingerprint="+hex(c.data,c.pos,end); c.pos=end; break;
            case 43: out="key-tag="+c.u16()+" algorithm="+c.u8()+" digest-type="+c.u8()+" digest="+hex(c.data,c.pos,end); c.pos=end; break;
            case 48: { int flags=c.u16(), protocol=c.u8(), algorithm=c.u8(); out="flags="+flags+" protocol="+protocol+" algorithm="+algorithm+" public-key="+Base64.getEncoder().encodeToString(c.bytes(end-c.pos)); break; }
            case 46: {
                out="covered="+typeName(c.u16())+" algorithm="+c.u8()+" labels="+c.u8()+" original-ttl="+c.u32()+" expiration(epoch)="+c.u32()+" inception(epoch)="+c.u32()+" key-tag="+c.u16()+" signer="+c.name();
                out+=" signature="+Base64.getEncoder().encodeToString(c.bytes(end-c.pos)); break;
            }
            case 47: out="next="+c.name()+" types="+bitmap(c,end); break;
            case 50: {
                int algorithm=c.u8(), flags=c.u8(), iterations=c.u16(); byte[] salt=c.bytes(c.u8()), hash=c.bytes(c.u8());
                out="hash-algorithm="+algorithm+" flags="+flags+" iterations="+iterations+" salt="+hex(salt,0,salt.length)+" next-hash(hex)="+hex(hash,0,hash.length)+" types="+bitmap(c,end); break;
            }
            case 64: case 65: {
                StringBuilder b=new StringBuilder("priority="+c.u16()+" target="+c.name());
                int lastKey=-1;
                while(c.pos<end) {
                    int key=c.u16(), length=c.u16();
                    if(key<=lastKey || length>end-c.pos)throw new IOException("Invalid SVCB parameter order or length");
                    lastKey=key; byte[] value=c.bytes(length);
                    b.append("; ").append(svcParam(key,value));
                }
                out=b.toString(); break;
            }
            default: out="raw hex: "+hex(c.data,start,end); c.pos=end;
        }
        if (c.pos!=end) throw new IOException("RDATA length mismatch");
        return out;
    }
    private static String svcParam(int key,byte[] bytes) throws IOException {
        Cursor c=new Cursor(bytes,0); StringBuilder v=new StringBuilder();
        if(key==0) { while(c.pos<bytes.length){ if(v.length()>0)v.append(','); v.append(c.u16()); } return "mandatory="+v; }
        if(key==1) { while(c.pos<bytes.length){ if(v.length()>0)v.append(','); v.append(c.text(bytes.length)); } return "alpn="+v; }
        if(key==2)return "no-default-alpn="+hex(bytes,0,bytes.length);
        if(key==3) { if(bytes.length!=2)throw new IOException("Invalid SVCB port length"); return "port="+c.u16(); }
        if(key==4 || key==6) { int length=key==4?4:16; if(bytes.length%length!=0)throw new IOException("Invalid address hints"); while(c.pos<bytes.length){ if(v.length()>0)v.append(','); v.append(InetAddress.getByAddress(c.bytes(length)).getHostAddress()); } return (key==4?"ipv4hint=":"ipv6hint=")+v; }
        if(key==5)return "ech="+Base64.getEncoder().encodeToString(bytes);
        if(key==7)return "dohpath="+new String(bytes,StandardCharsets.UTF_8);
        return "key"+key+"="+hex(bytes,0,bytes.length);
    }
    private static String bitmap(Cursor c,int end) throws IOException {
        StringBuilder out=new StringBuilder(); int previous=-1;
        while(c.pos<end) {
            int window=c.u8(), length=c.u8();
            if(window<=previous || length==0 || length>32 || length>end-c.pos)throw new IOException("Invalid DNSSEC type bitmap");
            previous=window;
            for(int i=0;i<length;i++) { int b=c.u8(); for(int bit=0;bit<8;bit++)if((b&(0x80>>>bit))!=0){ if(out.length()>0)out.append(' '); out.append(typeName(window*256+i*8+bit)); } }
        }
        return out.toString();
    }
    static String hex(byte[] data,int start,int end) throws IOException {
        if(start<0 || end<start || end>data.length)throw new IOException("RDATA exceeds DNS packet");
        StringBuilder out=new StringBuilder((end-start)*2);
        for(int i=start;i<end;i++) { int n=data[i]&255; out.append(Character.forDigit(n>>>4,16)).append(Character.forDigit(n&15,16)); }
        return out.toString();
    }
    private static int u16(byte[] p,int at) { return ((p[at]&255)<<8)|(p[at+1]&255); }
    private static final class Cursor {
        final byte[] data; int pos;
        Cursor(byte[] data,int pos){this.data=data;this.pos=pos;}
        void need(int length)throws IOException{if(length<0 || pos<0 || length>data.length-pos)throw new IOException("Unexpected end of DNS packet");}
        int u8()throws IOException{need(1);return data[pos++]&255;}
        int u16()throws IOException{need(2);int v=DnsClient.u16(data,pos);pos+=2;return v;}
        long u32()throws IOException{return ((long)u16()<<16)|u16();}
        void skip(int n)throws IOException{need(n);pos+=n;}
        byte[] bytes(int n)throws IOException{need(n);byte[] b=Arrays.copyOfRange(data,pos,pos+n);pos+=n;return b;}
        String text(int end)throws IOException{int length=u8();if(length>end-pos)throw new IOException("Character string exceeds RDATA");return new String(bytes(length),StandardCharsets.UTF_8);}
        String name()throws IOException{
            int p=pos, next=-1, jumps=0, wireLength=1; StringBuilder out=new StringBuilder();
            while(true) {
                if(p<0 || p>=data.length)throw new IOException("DNS name outside packet");
                int length=data[p++]&255;
                if((length&0xc0)==0xc0) {
                    if(p>=data.length)throw new IOException("Truncated compression pointer");
                    int pointer=((length&63)<<8)|(data[p++]&255);
                    if(pointer>=p-2 || ++jumps>128)throw new IOException("Invalid or cyclic compression pointer");
                    if(next==-1)next=p;
                    p=pointer;continue;
                }
                if((length&0xc0)!=0)throw new IOException("Unsupported DNS label encoding");
                if(length==0) { pos=next==-1?p:next; return out.length()==0?".":out.toString(); }
                if(length>63 || length>data.length-p || (wireLength+=length+1)>255)throw new IOException("Invalid DNS name length");
                if(out.length()>0)out.append('.');
                for(int i=0;i<length;i++) { int value=data[p++]&255; if(value<=32 || value>=127 || value=='.' || value=='\\')out.append('\\').append(String.format(Locale.US,"%03d",value));else out.append((char)value); }
            }
        }
    }
}
