package com.fieldkit.analyzer;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Selected-network operations use an operation-owned route even on worker threads. */
public final class RouteTests {
    static int checks;
    static synchronized void check(boolean value,String text){checks++;if(!value)throw new AssertionError(text);}
    static final InetAddress LOOP;
    static {try{LOOP=InetAddress.getByAddress(new byte[]{127,0,0,1});}catch(Exception e){throw new ExceptionInInitializerError(e);}}
    static class Route implements Task.Route {
        final AtomicInteger tcp=new AtomicInteger(),udp=new AtomicInteger(),lookups=new AtomicInteger(),http=new AtomicInteger(),created=new AtomicInteger();
        final Set<String> threads=Collections.synchronizedSet(new HashSet<>());
        final List<Socket> sockets=Collections.synchronizedList(new ArrayList<>());
        final List<DatagramSocket> datagrams=Collections.synchronizedList(new ArrayList<>());
        boolean failTcp,failUdp,closeTcp;
        public InetAddress[] resolve(String host){lookups.incrementAndGet();return new InetAddress[]{LOOP};}
        public void bind(Socket s)throws IOException {check(!s.isConnected(),"TCP bound before connect");tcp.incrementAndGet();threads.add(Thread.currentThread().getName());sockets.add(s);if(failTcp)throw new IOException("Fixture network disconnected");if(closeTcp)s.close();}
        public Socket createSocket()throws IOException{created.incrementAndGet();return Task.Route.super.createSocket();}
        public void bind(DatagramSocket s)throws IOException {check(!s.isConnected(),"UDP bound before connect/send");udp.incrementAndGet();datagrams.add(s);if(failUdp)throw new IOException("Fixture network disconnected");}
        public HttpURLConnection open(URL url)throws IOException {http.incrementAndGet();return new FixtureHttp(url);}
        public String description(){return "Fixture Wi-Fi";}
        public String dnsServer(){return "";}
    }
    static final class FixtureHttp extends HttpURLConnection {
        final ByteArrayOutputStream uploaded=new ByteArrayOutputStream();
        FixtureHttp(URL u){super(u);}
        public void disconnect(){}
        public boolean usingProxy(){return false;}
        public void connect(){}
        public int getResponseCode(){return 200;}
        public String getContentType(){return "application/json";}
        public OutputStream getOutputStream(){return uploaded;}
        public InputStream getInputStream(){
            String q=url.getQuery();int size=-1;
            if(q!=null)for(String part:q.split("&"))if(part.startsWith("bytes="))size=Integer.parseInt(part.substring(6));
            return new ByteArrayInputStream(size>=0?new byte[size]:"{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }
    static Task task(Route route){Task task=new Task(null);task.route(route);return task;}
    static void tcpAndWorkers()throws Exception {
        Route route=new Route();Task task=task(route);
        check(task.hasRoute()&&task.route()==route,"Route attached to Task");
        try(ServerSocket server=new ServerSocket(0,20,LOOP)) {
            server.setSoTimeout(3000);
            Thread accept=new Thread(()->{try{for(int i=0;i<4;i++)server.accept().close();}catch(IOException e){throw new RuntimeException(e);}},"Route fixture");accept.setDaemon(true);accept.start();
            int closed;try(ServerSocket reserve=new ServerSocket(0,1,LOOP)){closed=reserve.getLocalPort();}
            Report scan=NetworkTools.ports("test.invalid",server.getLocalPort()+","+closed,500,2,task);
            check(scan.rows.size()==2,"Two selected-network scan results");
            check(route.tcp.get()==2,"Every port scan worker bound its TCP socket");
            check(route.created.get()==2,"Port workers create sockets through route factory");
            check(route.threads.stream().allMatch(n->n.startsWith("pool-")),"Task route used on executor threads");
            check(route.lookups.get()==1,"Hostname resolved by selected route");
            Report ping=NetworkTools.ping("test.invalid","ICMP",3,100,500,56,server.getLocalPort(),"Auto",false,task);
            check(route.tcp.get()==5,"Every selected-network ping uses bound TCP");
            check(route.created.get()==5,"Ping also uses route socket factory without double binding");
            for(List<String> row:ping.rows)check(row.get(1).startsWith("TCP")&&row.get(2).equals("Connected"),"ICMP fallback has real TCP evidence and label");
            check(ping.text().contains("Selected-network ICMP is unavailable"),"Selected-network ICMP limitation shown");
            check(route.sockets.stream().allMatch(Socket::isClosed),"TCP resources closed after probes");
            accept.join(1000);
        }
    }
    static void failClosed()throws Exception {
        Route route=new Route();route.failTcp=true;Task task=task(route);
        try(ServerSocket listening=new ServerSocket(0,5,LOOP)) {
            listening.setSoTimeout(150);
            boolean failed=false;
            try{NetworkTools.ping("test.invalid","ICMP",1,100,100,56,listening.getLocalPort(),"Auto",false,task);}catch(IOException e){Task.RouteException useful=Task.routeFailure(e);failed=useful!=null&&useful.canUseSystem&&useful.getMessage().contains("Android routing");}
            check(failed,"Selected-route bind failure surfaced");
            boolean connected=false;try{listening.accept().close();connected=true;}catch(SocketTimeoutException expected){}
            check(!connected,"Failed binding never attempts unbound connection");
        }
        check(route.sockets.stream().allMatch(Socket::isClosed),"Bind failures close TCP sockets");
        Route lanRoute=new Route();lanRoute.closeTcp=true;Report lan=NetworkTools.lan("127.0.0.1",100,1,true,"","",task(lanRoute));
        check(lanRoute.tcp.get()==4,"Selected LAN uses four bound TCP probes");
        check(lan.rows.isEmpty(),"Selected LAN does not fall back to default native ping/reachability of loopback");
        check(lan.text().contains("Only network-bound TCP"),"LAN route probe scope stated");
        check(lan.text().contains("Reverse names skipped"),"Missing selected-network DNS noted");
        int before=lanRoute.lookups.get();Report trace=NetworkTools.trace("test.invalid",3,1,100,0,task(lanRoute));
        check(trace.rows.isEmpty()&&trace.text().contains("Traceroute unavailable for selected network"),"Selected-network traceroute refuses native process");
        check(lanRoute.lookups.get()==before,"Refused traceroute does not resolve on another network");
        Route deniedLan=new Route();deniedLan.failTcp=true;boolean workerFailure=false;
        try{NetworkTools.lan("127.0.0.1",100,1,false,"","",task(deniedLan));}catch(ExecutionException error){workerFailure=Task.routeFailure(error)!=null;}
        check(workerFailure,"Worker failure exposes typed routing error without java exception prefixes");
        check(Task.routeFailure(new IOException("unrelated"))==null,"Unrelated error does not offer route retry");
    }
    static void dnsBindings(boolean truncate)throws Exception {
        Route route=new Route();Task task=task(route);AtomicReference<Throwable> failure=new AtomicReference<>();
        try(DnsTransportTests.Endpoints endpoints=new DnsTransportTests.Endpoints(LOOP)) {
            ServerSocket tcp=endpoints.tcp;DatagramSocket udp=endpoints.udp;
            tcp.setSoTimeout(3000);udp.setSoTimeout(3000);
            Thread fixture=DnsTransportTests.fixture(udp,tcp,truncate,false,false,failure);
            DnsClient.Response response=DnsClient.query("test.invalid","A","dns.invalid",tcp.getLocalPort(),true,task);
            fixture.join(1000);
            check(failure.get()==null,"DNS route fixture completed");
            check(response.records.size()==1,"Selected DNS has wire answer");
            check(route.udp.get()==1,"DNS UDP bound to selected network");
            check(route.tcp.get()==(truncate?1:0),"DNS TCP fallback bound to selected network");
            check(route.created.get()==(truncate?1:0),"DNS TCP uses route socket factory");
            check(route.lookups.get()==1,"DNS server hostname uses selected resolver");
            check(route.datagrams.stream().allMatch(DatagramSocket::isClosed),"DNS datagram cleaned up");
            check(route.sockets.stream().allMatch(Socket::isClosed),"DNS TCP cleaned up");
        }
        Route failed=new Route();failed.failUdp=true;boolean rejected=false;
        try{DnsClient.query("test.invalid","A","dns.invalid",65000,true,task(failed));}catch(IOException expected){rejected=expected.getMessage().contains("disconnected");}
        check(rejected,"DNS binding failure propagated without default retry");
        check(failed.datagrams.get(0).isClosed(),"DNS failed binding closes socket");
    }
    static void httpAndWol()throws Exception {
        Route route=new Route();Task task=task(route);
        NetworkTools.HttpResult response=NetworkTools.httpGet("https://test.invalid/query",100,task);
        check(response.body.equals("{}")&&route.http.get()==1,"HTTPS calls selected route opener");
        Report rdap=NetworkTools.registration("example.test",false,task);
        check(route.http.get()==2&&rdap.text().contains("HTTP status"),"RDAP uses selected route opener");
        Report speed=NetworkTools.speed("https://test.invalid",100000,task);
        check(route.http.get()==9,"Five latency and two transfer requests all use selected route");
        check(speed.text().contains("100000 bytes"),"Selected-route transfer fixture completed");
        try(DatagramSocket receiver=new DatagramSocket(0,LOOP)) {
            receiver.setSoTimeout(1000);NetworkTools.wol("01:23:45:67:89:AB","test.invalid",receiver.getLocalPort(),task);
            byte[] bytes=new byte[200];DatagramPacket p=new DatagramPacket(bytes,bytes.length);receiver.receive(p);
            check(p.getLength()==102&&route.udp.get()==1,"WOL transmits bound datagram");
        }
        check(route.datagrams.get(0).isClosed(),"WOL closes bound datagram");
        Route failedWhois=new Route();failedWhois.failTcp=true;boolean failed=false;
        try{NetworkTools.registration("example.test",true,task(failedWhois));}catch(IOException expected){failed=true;}
        check(failed&&failedWhois.tcp.get()==1&&failedWhois.sockets.get(0).isClosed(),"WHOIS binds and closes on failure");
        check(failedWhois.created.get()==1,"WHOIS uses route socket factory");
        Route cancelledRoute=new Route();Task cancelled=task(cancelledRoute);cancelled.cancel();boolean stopped=false;
        try{NetworkTools.ping("test.invalid","TCP",1,100,100,56,80,"Auto",false,cancelled);}catch(InterruptedException expected){stopped=true;}
        check(stopped&&cancelledRoute.tcp.get()==0,"Cancelled routed task starts no connection");
    }
    static void dnsTcpFailure()throws Exception {
        Route route=new Route();route.failTcp=true;AtomicReference<Throwable> fixtureError=new AtomicReference<>();
        try(DnsTransportTests.Endpoints endpoints=new DnsTransportTests.Endpoints(LOOP)) {
            ServerSocket tcp=endpoints.tcp;DatagramSocket udp=endpoints.udp;
            tcp.setSoTimeout(150);udp.setSoTimeout(2000);
            Thread fixture=new Thread(()->{try{
                byte[] data=new byte[2048];DatagramPacket request=new DatagramPacket(data,data.length);udp.receive(request);
                byte[] answer=DnsTransportTests.response(Arrays.copyOf(data,request.getLength()),true,false);
                udp.send(new DatagramPacket(answer,answer.length,request.getSocketAddress()));
            }catch(Throwable e){fixtureError.set(e);}},"DNS failure fixture");fixture.setDaemon(true);fixture.start();
            boolean failed=false;try{DnsClient.query("test.invalid","A","dns.invalid",tcp.getLocalPort(),true,task(route));}catch(IOException expected){failed=expected.getMessage().contains("disconnected");}
            check(failed&&route.tcp.get()==1&&route.udp.get()==1,"DNS TCP bind failure propagates after bound UDP truncation");
            boolean accepted=false;try{tcp.accept().close();accepted=true;}catch(SocketTimeoutException expected){}
            check(!accepted,"DNS TCP bind failure never opens default connection");
            check(route.sockets.get(0).isClosed()&&route.datagrams.get(0).isClosed(),"Failed DNS TCP fallback closes both transports");
            fixture.join(1000);check(fixtureError.get()==null,"DNS failure fixture completes");
        }
    }
    static void failedWorkerClosesPeers()throws Exception {
        CountDownLatch connected=new CountDownLatch(1),closed=new CountDownLatch(1);AtomicInteger creations=new AtomicInteger();
        Socket waiting=new Socket(){
            @Override public void connect(SocketAddress endpoint,int timeout)throws IOException {
                connected.countDown();
                try{if(!closed.await(3,TimeUnit.SECONDS))throw new SocketTimeoutException("Fixture peer was not closed promptly");}catch(InterruptedException ignored){try{closed.await(3,TimeUnit.SECONDS);}catch(InterruptedException stop){Thread.currentThread().interrupt();}}
                throw new SocketException("Fixture peer closed");
            }
            @Override public synchronized void close()throws IOException{closed.countDown();super.close();}
        };
        Route route=new Route(){
            @Override public Socket createSocket()throws IOException {
                if(creations.incrementAndGet()==1)return waiting;
                try{if(!connected.await(1,TimeUnit.SECONDS))throw new IOException("Fixture never started");}catch(InterruptedException error){Thread.currentThread().interrupt();throw new IOException(error);}
                throw new Task.RouteException("Blocked","Fixture route blocked","Fixture",true,null);
            }
        };
        Task task=task(route);long started=System.nanoTime();boolean failed=false;
        try{NetworkTools.ports("test.invalid","80,443",5000,2,task);}catch(ExecutionException error){failed=Task.routeFailure(error)!=null;}
        check(failed,"One worker's route error is preserved");
        check(closed.getCount()==0&&waiting.isClosed(),"Route failure promptly closes another worker's in-flight socket");
        check((System.nanoTime()-started)/1e9<2,"Worker error cleanup does not wait for connect timeout");
        check(!task.isCancelled(),"Network failure remains a failure, not user cancellation");
    }
    public static void main(String[] args)throws Exception {
        tcpAndWorkers();failClosed();dnsBindings(false);dnsBindings(true);dnsTcpFailure();httpAndWol();failedWorkerClosesPeers();
        System.out.println("RouteTests: "+checks+" checks passed (operation routes, worker TCP, DNS UDP/TCP, HTTPS, fail-closed cleanup, WOL and cancellation).");
    }
}
