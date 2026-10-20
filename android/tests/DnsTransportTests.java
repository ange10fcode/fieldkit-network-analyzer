package com.fieldkit.analyzer;

import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;

/** Real local UDP + DNS-over-TCP fixtures, including TC retry and slow-read timeout. */
public final class DnsTransportTests {
    static int checks;
    static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    /** Reserve the same explicit loopback port for both transports, outside Windows' ephemeral range. */
    static final class Endpoints implements Closeable {
        ServerSocket tcp;DatagramSocket udp;
        Endpoints(InetAddress loop)throws IOException {
            IOException last=null;
            for(int attempt=0;attempt<128;attempt++) {
                int port=ThreadLocalRandom.current().nextInt(20000,45001);
                ServerSocket candidateTcp=null;DatagramSocket candidateUdp=null;
                try {
                    candidateTcp=new ServerSocket();candidateTcp.setReuseAddress(false);candidateTcp.bind(new InetSocketAddress(loop,port),1);
                    candidateUdp=new DatagramSocket(null);candidateUdp.setReuseAddress(false);candidateUdp.bind(new InetSocketAddress(loop,port));
                    tcp=candidateTcp;udp=candidateUdp;return;
                } catch(IOException unavailable) {
                    last=unavailable;
                    if(candidateUdp!=null)candidateUdp.close();
                    if(candidateTcp!=null)try{candidateTcp.close();}catch(IOException ignored){}
                }
            }
            throw new IOException("Could not reserve matching TCP/UDP loopback fixture ports in 20000–45000 after 128 attempts.",last);
        }
        public void close()throws IOException {if(udp!=null)udp.close();if(tcp!=null)tcp.close();}
    }
    static byte[] response(byte[] query,boolean tc,boolean mismatch)throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.write(query,0,2);out.writeShort(tc?0x8380:0x8180);out.writeShort(1);out.writeShort(tc?0:1);out.writeShort(0);out.writeShort(0);
        byte[] question=Arrays.copyOfRange(query,12,query.length-11);if(mismatch)question[1]='z';out.write(question);
        if(!tc){out.writeShort(0xc00c);out.writeShort(1);out.writeShort(1);out.writeInt(600);out.writeShort(4);out.write(new byte[]{(byte)192,0,2,7});}
        return bytes.toByteArray();
    }
    static Thread fixture(DatagramSocket udp,ServerSocket tcp,boolean truncate,boolean mismatch,boolean slow,AtomicReference<Throwable> failure) {
        Thread thread=new Thread(()->{
            try {
                udp.setSoTimeout(4000);byte[] buffer=new byte[2048];DatagramPacket request=new DatagramPacket(buffer,buffer.length);udp.receive(request);
                byte[] query=Arrays.copyOf(buffer,request.getLength());byte[] answer=response(query,truncate,mismatch);
                udp.send(new DatagramPacket(answer,answer.length,request.getSocketAddress()));
                if(truncate)try(Socket connection=tcp.accept()) {
                    connection.setSoTimeout(4000);DataInputStream in=new DataInputStream(connection.getInputStream());int length=in.readUnsignedShort();byte[] tcpQuery=new byte[length];in.readFully(tcpQuery);
                    byte[] full=response(tcpQuery,false,mismatch);DataOutputStream out=new DataOutputStream(connection.getOutputStream());
                    if(slow) {out.writeShort(1000);out.flush();try{for(int i=0;i<30;i++){out.writeByte(i);out.flush();Thread.sleep(500);}}catch(IOException expected){}}
                    else {out.writeShort(full.length);out.write(full);out.flush();}
                }
            }catch(Throwable error){failure.set(error);}
        },"DNS-fixture");thread.setDaemon(true);thread.start();return thread;
    }
    static void exchange(boolean truncate,boolean mismatch,boolean slow)throws Exception {
        InetAddress loop=InetAddress.getByName("127.0.0.1");AtomicReference<Throwable> failure=new AtomicReference<>();
        try(Endpoints endpoints=new Endpoints(loop)) {
            ServerSocket tcp=endpoints.tcp;DatagramSocket udp=endpoints.udp;
            tcp.setSoTimeout(4000);Thread fixture=fixture(udp,tcp,truncate,mismatch,slow,failure);long start=System.nanoTime();
            if(mismatch) {
                boolean rejected=false;try{DnsClient.query("example.test","A","127.0.0.1",tcp.getLocalPort(),true,new Task(null));}catch(IOException expected){rejected=expected.getMessage().contains("mismatched question");}
                check(rejected,"Reject echoed question mismatch");
            }else if(slow) {
                boolean timedOut=false;try{DnsClient.query("example.test","A","127.0.0.1",tcp.getLocalPort(),true,new Task(null));}catch(SocketTimeoutException expected){timedOut=true;}
                check(timedOut,"TCP slow-drip response observes absolute deadline");check((System.nanoTime()-start)/1e9<8,"DNS total TCP read bounded by 6s despite active stream");
            }else {
                DnsClient.Response result=DnsClient.query("example.test","A","127.0.0.1",tcp.getLocalPort(),true,new Task(null));
                check(result.records.size()==1,"One actual DNS answer");check(result.records.get(0).value.equals("192.0.2.7"),"Real wire A response parsed");check(result.records.get(0).ttl==600,"Wire TTL preserved");
                check(result.transport.equals(truncate?"TCP (UDP response truncated)":"UDP"),"Expected DNS transport used");check(result.status().equals("NOERROR"),"Wire status interpreted");
            }
            fixture.join(2000);check(failure.get()==null,"Fixture completed without unexpected error: "+failure.get());
        }
    }
    public static void main(String[] args)throws Exception {
        exchange(false,false,false);exchange(true,false,false);exchange(false,true,false);exchange(true,false,true);
        System.out.println("DnsTransportTests: "+checks+" checks passed (live loopback UDP, TCP fallback, question validation, absolute slow-read deadline).");
    }
}
