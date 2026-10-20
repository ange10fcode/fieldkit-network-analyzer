package com.fieldkit.analyzer;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Plain JVM checks: javac + java com.fieldkit.analyzer.CoreTests (no Android runtime). */
public final class CoreTests {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private interface Action {void run()throws Exception;}
    private static void rejects(Action test,String message)throws Exception{boolean rejected=false;try{test.run();}catch(IllegalArgumentException|IOException expected){rejected=true;}check(rejected,message);}
    private static byte[] bytes(int... values){byte[] b=new byte[values.length];for(int i=0;i<b.length;i++)b[i]=(byte)values[i];return b;}
    private static byte[] join(byte[]... data)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();for(byte[] b:data)out.write(b);return out.toByteArray();}
    private static byte[] reply(int type,byte[] data)throws IOException {
        byte[] query=DnsClient.queryPacket("example.test",type,true,0x1234);
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.writeShort(0x1234);out.writeShort(0x8180);out.writeShort(1);out.writeShort(1);out.writeShort(0);out.writeShort(0);
        out.write(query,12,query.length-12-11);out.writeShort(0xc00c);out.writeShort(type);out.writeShort(1);out.writeInt(-1);out.writeShort(data.length);out.write(data);
        return bytes.toByteArray();
    }
    private static String decode(int type,byte[] value)throws Exception{return DnsClient.parse(reply(type,value),0x1234).records.get(0).value;}
    public static void main(String[] args)throws Exception {
        check(Ip.parse("0.0.0.0")==0,"IPv4 zero");check(Ip.parse("255.255.255.255")==0xffffffffL,"IPv4 unsigned max");
        check(Ip.format(Ip.parse("192.168.1.20")).equals("192.168.1.20"),"IPv4 round trip");
        rejects(()->Ip.parse("256.1.1.1"),"Reject octet overflow");rejects(()->Ip.parse("1.2.3"),"Reject truncated IPv4");rejects(()->Ip.parse("1.2.3.-1"),"Reject negative IPv4");rejects(()->Ip.parse("example.com"),"No implicit DNS in IPv4 parser");
        check(Ip.mask(0)==0,"Prefix zero");check(Ip.mask(24)==0xffffff00L,"Prefix 24");check(Ip.mask(32)==0xffffffffL,"Prefix 32");rejects(()->Ip.mask(33),"Reject prefix33");
        check(Ip.network("192.168.1.20",24).equals("192.168.1.0"),"Network calculation");
        long[] range=Ip.range("192.168.1.20/24");check(range[0]==Ip.parse("192.168.1.1")&&range[1]==Ip.parse("192.168.1.254"),"CIDR host bounds");
        range=Ip.range("192.168.1.20/31");check(range[1]-range[0]+1==2,"Point-to-point prefix");range=Ip.range("192.168.1.20/32");check(range[0]==range[1],"Single host prefix");
        check(Ip.range("10.0.0.0 - 10.0.15.255")[1]-Ip.range("10.0.0.0 - 10.0.15.255")[0]+1==4096,"Maximum scan range");
        rejects(()->Ip.range("10.0.0.0/8"),"Block oversized scan");rejects(()->Ip.range("10.0.0.2-10.0.0.1"),"Block backwards scan");rejects(()->Ip.range("10.0.0.1/"),"Missing CIDR");
        int[] ports=Ip.ports("22,80,443,80, 100-102");check(Arrays.equals(ports,new int[]{22,80,100,101,102,443}),"Deduplicated sorted ports");check(Ip.ports("1-65535").length==65535,"Full TCP range");rejects(()->Ip.ports("0"),"Reject zero port");rejects(()->Ip.ports("80-22"),"Reject reversed port range");rejects(()->Ip.ports("65536"),"Reject port overflow");
        byte[] magic=Ip.magicPacket("01:23:45:67:89:AB");check(magic.length==102,"Magic packet length");for(int i=0;i<6;i++)check((magic[i]&255)==255,"Magic packet prefix");for(int i=0;i<16;i++)check(Arrays.equals(Arrays.copyOfRange(magic,6+i*6,12+i*6),bytes(1,35,69,103,137,171)),"Sixteen MAC copies");rejects(()->Ip.magicPacket("AA:BB:CC:DD:EE"),"Reject short MAC");
        check(DnsClient.reverse("192.0.2.10").equals("10.2.0.192.in-addr.arpa"),"IPv4 PTR conversion");check(DnsClient.reverse("2001:db8::1").equals("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"),"IPv6 nibble reversal");
        for(String type:new String[]{"A","AAAA","CNAME","MX","NS","PTR","SOA","TXT","SRV","CAA","HINFO","SSHFP","SVCB","HTTPS","DNSKEY","RRSIG","DS","NSEC","NSEC3"})check(DnsClient.typeName(DnsClient.type(type)).equals(type),"DNS type "+type);
        check((DnsClient.queryPacket("_http._tcp.example.test",33,false,10)[2]&1)==0,"Nonrecursive query");check((DnsClient.queryPacket("example.test",1,true,10)[2]&1)==1,"Recursion flag");
        rejects(()->DnsClient.queryPacket("bad..test",1,true,10),"Reject empty label");rejects(()->DnsClient.queryPacket(String.join("",Collections.nCopies(64,"a"))+".test",1,true,10),"Reject long label");
        DnsClient.Response response=DnsClient.parse(reply(1,bytes(192,0,2,1)),0x1234);check(response.status().equals("NOERROR"),"DNS success code");check(response.records.get(0).ttl==4294967295L,"Unsigned TTL");check(response.records.get(0).name.equals("example.test"),"Compressed owner name");check(response.records.get(0).section.equals("Answer"),"Answer section");
        check(decode(1,bytes(192,0,2,1)).equals("192.0.2.1"),"A decoding");check(decode(28,bytes(0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1)).contains("2001:db8"),"AAAA decoding");
        for(int type:new int[]{2,5,12})check(decode(type,bytes(0xc0,0x0c)).equals("example.test"),"Compressed domain RDATA "+type);
        check(decode(15,bytes(0,10,0xc0,0x0c)).equals("preference=10 exchange=example.test"),"MX decoding");
        check(decode(33,bytes(0,1,0,2,1,0xbb,0xc0,0x0c)).contains("port=443"),"SRV decoding");
        ByteArrayOutputStream soaBytes=new ByteArrayOutputStream();DataOutputStream soa=new DataOutputStream(soaBytes);soa.writeShort(0xc00c);soa.writeShort(0xc00c);for(int i=1;i<=5;i++)soa.writeInt(i);
        check(decode(6,soaBytes.toByteArray()).contains("serial=1 refresh=2 retry=3 expire=4 minimum=5"),"SOA decoding");
        check(decode(16,bytes(3,'f','o','o',3,'b','a','r')).equals("\"foo\" \"bar\""),"Multiple TXT segments");
        byte[] spf="v=spf1 -all".getBytes(StandardCharsets.US_ASCII);check(decode(16,join(bytes(spf.length),spf)).contains("SPF policy"),"SPF policy inspection");
        check(decode(13,bytes(3,'x','6','4',5,'L','i','n','u','x')).equals("CPU=x64 OS=Linux"),"HINFO decoding");
        check(decode(257,join(bytes(0,5),"issue".getBytes(StandardCharsets.US_ASCII),"ca.test".getBytes(StandardCharsets.US_ASCII))).contains("tag=issue value=ca.test"),"CAA decoding");
        check(decode(43,bytes(0x12,0x34,8,2,0xaa,0xbb)).contains("key-tag=4660 algorithm=8 digest-type=2 digest=aabb"),"DS decoding");
        check(decode(44,bytes(4,2,0xab,0xcd)).contains("fingerprint=abcd"),"SSHFP decoding");check(decode(48,bytes(1,1,3,8,1,2,3)).contains("public-key=AQID"),"DNSKEY decoding");
        ByteArrayOutputStream signatureBytes=new ByteArrayOutputStream();DataOutputStream signature=new DataOutputStream(signatureBytes);signature.writeShort(1);signature.writeByte(8);signature.writeByte(2);signature.writeInt(300);signature.writeInt(1700000000);signature.writeInt(1600000000);signature.writeShort(1234);signature.writeShort(0xc00c);signature.write(bytes(1,2,3));
        check(decode(46,signatureBytes.toByteArray()).contains("key-tag=1234 signer=example.test signature=AQID"),"RRSIG decoding");
        check(decode(47,bytes(0xc0,0x0c,0,1,0x40)).contains("types=A"),"NSEC bitmap");check(decode(50,bytes(1,0,0,5,0,2,0xaa,0xbb,0,1,0x40)).contains("iterations=5 salt= next-hash(hex)=aabb types=A"),"NSEC3 decoding");
        check(decode(64,bytes(0,1,0xc0,0x0c,0,3,0,2,1,0xbb,0,4,0,4,192,0,2,10)).contains("port=443; ipv4hint=192.0.2.10"),"SVCB parameters");check(decode(65,bytes(0,0,0xc0,0x0c)).contains("priority=0 target=example.test"),"HTTPS alias binding");
        check(decode(1,bytes(1,2,3)).startsWith("Malformed RDATA"),"Malformed known type retained as raw hex");
        rejects(()->DnsClient.parse(new byte[11],1),"Reject truncated header");rejects(()->DnsClient.parse(reply(1,bytes(1,2,3,4)),0x7777),"Reject transaction mismatch");
        byte[] corrupt=reply(1,bytes(1,2,3,4));corrupt[12]=(byte)0xc0;corrupt[13]=12;rejects(()->DnsClient.parse(corrupt,0x1234),"Reject self-referencing compression");
        byte[] truncated=Arrays.copyOf(reply(1,bytes(1,2,3,4)),20);rejects(()->DnsClient.parse(truncated,0x1234),"Reject truncated name/question");
        Random random=new Random(20261016);
        for(int i=0;i<2000;i++){byte[] fuzz=new byte[random.nextInt(200)];random.nextBytes(fuzz);try{DnsClient.parse(fuzz,0x1234);}catch(IOException expected){}checks++;}
        check("192.168.1.1".equals(NetworkTools.traceRouter("From 192.168.1.1 icmp_seq=1 Time to live exceeded")),"IPv4 hop parsing");
        check("192.168.1.1".equals(NetworkTools.traceRouter("From router (192.168.1.1): icmp_seq=1 Time to live exceeded")),"Named IPv4 hop parsing");
        check("fe80::1%wlan0".equals(NetworkTools.traceRouter("From fe80::1%wlan0 icmp_seq=1 Time exceeded: Hop limit")),"IPv6 zone parsing");
        check("2001:db8::".equals(NetworkTools.traceRouter("From 2001:db8:: icmp_seq=1 Time exceeded")),"IPv6 double colon preserved");
        check(NetworkTools.traceRouter("From router.invalid icmp_seq=1 bad result")==null,"Invalid router is not fabricated");
        System.out.println("CoreTests: "+checks+" checks passed (IP, ports, WOL, 19 DNS types, hostile DNS packets).");
    }
}
