package com.fieldkit.analyzer;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import org.json.*;

/** Rootless diagnostic engines. Every displayed result comes from an actual operation. */
public final class NetworkTools {
    private NetworkTools() {}
    private static final Pattern RTT=Pattern.compile("time([=<])\\s*([0-9]+(?:\\.[0-9]+)?)\\s*ms",Pattern.CASE_INSENSITIVE);
    private static final Pattern FROM=Pattern.compile("(?im)^From\\s+([^\\r\\n]+)");
    private static final int[] LAN_PORTS={80,443,22,445};
    public static final String LAN_COMMON_PORTS="21,22,23,53,80,139,443,445,554,631,1883,3389,5357,5900,8000,8080,8443,9100";
    private static String number(double n){return String.format(Locale.US,"%.2f",n);}
    private static int bounded(int n,int min,int max,String label){if(n<min||n>max)throw new IllegalArgumentException(label+" must be "+min+"–"+max+".");return n;}
    private static String target(String s){
        if(s==null||s.trim().isEmpty()||s.trim().length()>253)throw new IllegalArgumentException("Enter a hostname or IP address without a URL or spaces.");
        String host=s.trim();for(int i=0;i<host.length();i++){char c=host.charAt(i);if(Character.isWhitespace(c)||Character.isISOControl(c)||c=='/'||c=='\\')throw new IllegalArgumentException("Enter a hostname or IP address without a URL or spaces.");}
        return host;
    }
    private static InetAddress address(String host,String family,Task task)throws IOException{
        for(InetAddress a:task.resolve(target(host)))if("Auto".equalsIgnoreCase(family)||family==null||("IPv4".equalsIgnoreCase(family)&&a instanceof Inet4Address)||("IPv6".equalsIgnoreCase(family)&&a instanceof Inet6Address))return a;
        throw new UnknownHostException("Target has no address for "+family+".");
    }
    private static final class Command {
        int exit; boolean timedOut; String output;
    }
    private static Command command(List<String> args,int timeout,Task task)throws Exception {
        task.check(); Process p=new ProcessBuilder(args).redirectErrorStream(true).start(); task.own(p);
        final ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        Thread reader=new Thread(()->{
            try(InputStream in=p.getInputStream()) {byte[] b=new byte[1024];int n;while((n=in.read(b))>=0) {if(bytes.size()<131072)bytes.write(b,0,Math.min(n,131072-bytes.size()));} }catch(IOException ignored){}
        },"native-probe-output");reader.setDaemon(true);reader.start();
        Command c=new Command();
        try {
            long end=System.nanoTime()+timeout*1000000L;
            while(!p.waitFor(100,TimeUnit.MILLISECONDS)) { task.check(); if(System.nanoTime()>=end){c.timedOut=true;p.destroy();break;} }
            if(p.isAlive()) {p.destroyForcibly();p.waitFor(500,TimeUnit.MILLISECONDS);}
            reader.join(750); task.check();
            c.exit=p.isAlive()?-1:p.exitValue(); c.output=new String(bytes.toByteArray(),StandardCharsets.UTF_8); return c;
        } finally { if(p.isAlive())p.destroyForcibly();try{p.getInputStream().close();}catch(IOException ignored){} }
    }
    private static List<String> pingCommand(InetAddress a,int timeout,int payload,Integer ttl,boolean df) {
        List<String> args=new ArrayList<>(); boolean v6=a instanceof Inet6Address;
        String executable=new File("/system/bin/ping").exists()?"/system/bin/ping":"ping";
        if(v6&&new File("/system/bin/ping6").exists())executable="/system/bin/ping6";
        args.add(executable);if(v6&&!executable.endsWith("ping6"))args.add("-6");
        Collections.addAll(args,"-n","-c","1","-W",String.valueOf(Math.max(1,(timeout+999)/1000)),"-s",String.valueOf(payload));
        if(ttl!=null)Collections.addAll(args,"-t",String.valueOf(ttl));
        if(df&&!v6)Collections.addAll(args,"-M","do");
        args.add(a.getHostAddress());return args;
    }
    private static boolean unsupported(Command c) {
        String o=c.output.toLowerCase(Locale.US);
        return o.contains("permission denied")||o.contains("operation not permitted")||o.contains("unknown option")||o.contains("invalid option")||o.contains("unrecognized option")||o.contains("usage:")||o.contains("not found");
    }
    private static String nativeFailure(String output) {
        for(String line:output.split("\\r?\\n")) {
            String lower=line.toLowerCase(Locale.US);
            if(lower.contains("message too long")||lower.contains("packet too large")||lower.contains("local error")||lower.contains("network is unreachable")||lower.contains("destination unreachable")||lower.startsWith("ping:"))return line.length()>512?line.substring(0,512):line;
        }
        return null;
    }
    static String traceRouter(String output) {
        Matcher from=FROM.matcher(output);if(!from.find())return null;String text=from.group(1).trim(),candidate;
        int opening=text.indexOf('('),closing=opening<0?-1:text.indexOf(')',opening+1);
        candidate=opening>=0&&closing>opening?text.substring(opening+1,closing):text.split("\\s+",2)[0];
        for(int attempt=0;attempt<2;attempt++) {
            try{Ip.parse(candidate);return candidate;}catch(IllegalArgumentException ignored){}
            if(candidate.contains(":")&&candidate.matches("[0-9a-fA-F:.]+(?:%[A-Za-z0-9_.-]+)?")) {
                int zone=candidate.indexOf('%');String literal=zone<0?candidate:candidate.substring(0,zone);
                try{if(InetAddress.getByName(literal) instanceof Inet6Address)return candidate;}catch(UnknownHostException ignored){}
            }
            if(candidate.endsWith(":"))candidate=candidate.substring(0,candidate.length()-1);else break;
        }
        return null;
    }
    public static Report ping(String target,String mode,int count,int interval,int timeout,int payload,int port,String family,boolean df,Task task)throws Exception {
        bounded(count,0,100000,"Probe count (0 means continuous)");bounded(interval,100,60000,"Interval in milliseconds");bounded(timeout,100,30000,"Timeout in milliseconds");bounded(payload,0,65000,"ICMP payload size");bounded(port,1,65535,"TCP port");
        InetAddress a=address(target,family,task);task.check();
        Report r=new Report("Ping",target,"Probe","Method","Result","RTT ms");
        r.note("Resolved target: "+a.getHostAddress()+". Interval "+interval+" ms; timeout "+timeout+" ms. Native timeout termination can incur up to 100 ms scheduling overhead; replies whose RTT exceeds the configured timeout are excluded. TCP timing includes connection establishment.");
        if(count==0)r.note("Continuous mode retains the latest 10,000 probe rows and 3,600 chart samples. Summary statistics include every probe in this run.");
        boolean tcp="TCP".equalsIgnoreCase(mode),fallback=false,upperBound=false;
        if(task.hasRoute()) {
            r.note("Selected network: "+task.route().description()+". TCP sockets and hostname resolution use this network.");
            if(!tcp){tcp=true;fallback=true;r.note("Selected-network ICMP is unavailable: native ping cannot use the Android per-socket network selection. Using TCP connect probes on port "+port+"; ICMP payload and DF do not apply.");}
        }
        if(df&&a instanceof Inet6Address)r.note("IPv6 routers never fragment transit packets; native IPv4 Don't Fragment option does not apply.");
        if(!tcp)r.note("ICMP payload: "+payload+" bytes"+(df?"; Don't Fragment requested where native ping supports it.":"."));
        int sent=0,received=0;double min=Double.POSITIVE_INFINITY,max=0,sum=0,sumSquares=0,variation=0,previous=Double.NaN;
        Set<String> nativeErrors=new HashSet<>();
        long started=System.nanoTime();
        while(count==0||sent<count) {
            task.check();long iteration=System.nanoTime();double ms=Double.NaN;String result="No ICMP echo response before timeout",method=tcp?"TCP :"+port:"ICMP";
            if(!tcp) {
                try {
                    Command c=command(pingCommand(a,timeout,payload,null,df),timeout,task);
                    if(unsupported(c)) {
                        // Unsupported optional DF is surfaced and retried without that option first.
                        if(df&&c.output.toLowerCase(Locale.US).matches("(?s).*(option|usage).*")) {
                            r.note("Native ping does not support the requested DF option. Retrying ICMP without DF.");df=false;
                            c=command(pingCommand(a,timeout,payload,null,false),timeout,task);
                        }
                        if(unsupported(c))throw new IOException(c.output.trim());
                    }
                    Matcher m=RTT.matcher(c.output);
                    if(m.find()&&Double.parseDouble(m.group(2))<=timeout) {ms=Double.parseDouble(m.group(2));upperBound|="<".equals(m.group(1));result="Echo reply"+("<".equals(m.group(1))?" (RTT upper bound)":"");}
                    else {String failure=nativeFailure(c.output);if(failure!=null){result=failure;if(nativeErrors.add(failure))r.note("Native ICMP error: "+failure);}}
                } catch(IOException unavailable) {
                    tcp=true;fallback=true;method="TCP :"+port;
                    r.note("Native ICMP unavailable: "+unavailable.getMessage()+". Continuing with explicitly labeled TCP connect probes; ICMP payload/DF do not apply.");
                }
            }
            if(tcp) {
                Probe p=connect(a,port,timeout,task);method="TCP :"+port;result=p.status;
                if("Open".equals(p.status)){ms=p.ms;result="Connected";}
            }
            sent++;
            if(!Double.isNaN(ms)){received++;min=Math.min(min,ms);max=Math.max(max,ms);sum+=ms;sumSquares+=ms*ms;if(!Double.isNaN(previous))variation+=Math.abs(ms-previous);previous=ms;}
            r.add(String.valueOf(sent),method,result,Double.isNaN(ms)?"—":number(ms));
            if(count==0)synchronized(r){if(r.rows.size()>10000)r.rows.remove(0);}
            r.series("Elapsed seconds",(System.nanoTime()-started)/1e9);r.series("RTT ms",ms);r.series("Failed probe",Double.isNaN(ms)?1:Double.NaN);
            r.detail="Sent "+sent+"; successful "+received+"; failed "+(sent-received)+"; loss "+number(100.0*(sent-received)/sent)+"%.\n"+(received>0?"RTT min / avg / max: "+number(min)+" / "+number(sum/received)+" / "+number(max)+" ms; standard deviation "+number(Math.sqrt(Math.max(0,sumSquares/received-(sum/received)*(sum/received))))+" ms; mean adjacent successful RTT change "+number(received>1?variation/(received-1):0)+" ms.":"No successful probes.")+"\nElapsed "+number((System.nanoTime()-started)/1e9)+" s.";
            task.emit(r);
            if(count==0||sent<count)task.sleep(Math.max(0,interval-(System.nanoTime()-iteration)/1000000));
        }
        if(upperBound)r.note("Native ping returned one or more time< values. Their upper bounds are used in summary statistics.");
        if(fallback)r.note("Results use TCP fallback and are not ICMP echo measurements.");
        return r;
    }
    public static Report trace(String target,int hops,int probes,int timeout,int interval,Task task)throws Exception {
        bounded(hops,1,64,"Maximum hops");bounded(probes,1,5,"Probes per hop");bounded(timeout,100,10000,"Timeout in milliseconds");bounded(interval,0,10000,"Interval in milliseconds");
        if(task.hasRoute()){task.check();Report unavailable=new Report("Traceroute",target,"Hop","Probe","Address","Hostname","RTT ms","Result");unavailable.note("Traceroute unavailable for selected network "+task.route().description()+": the native ICMP process cannot bind to an Android Network. Select Automatic routing to run traceroute using the system route.");task.emit(unavailable);return unavailable;}
        InetAddress a=address(target,"Auto",task);Report r=new Report("Traceroute",target,"Hop","Probe","Address","Hostname","RTT ms","Result");
        r.note("ICMP echo probes with increasing IP TTL / IPv6 hop limit to "+a.getHostAddress()+". Native ping often exposes hop addresses without Time Exceeded RTT; unavailable timings remain blank. UDP traceroute needs unavailable raw ICMP reception on many unrooted Android devices.");
        boolean reached=false;
        for(int ttl=1;ttl<=hops&&!reached;ttl++) {
            int responses=0;
            for(int probe=1;probe<=probes;probe++) {
                task.check();Command c;
                try{c=command(pingCommand(a,timeout,32,ttl,false),timeout,task);}catch(IOException error){r.note("Traceroute unavailable: native ICMP executable cannot run: "+error.getMessage());task.emit(r);return r;}
                if(unsupported(c)){r.note("Traceroute unavailable on this device: "+c.output.trim());task.emit(r);return r;}
                Matcher timing=RTT.matcher(c.output);String router=traceRouter(c.output),host="—",ms="—",name="—",status="Timeout / no exposed router reply";
                if(timing.find()&&Double.parseDouble(timing.group(2))<=timeout) { host=a.getHostAddress();ms=("<".equals(timing.group(1))?"<":"")+timing.group(2);reached=true;responses++;status="Destination replied"; }
                else if(router!=null) {host=router;responses++;status=c.output.toLowerCase(Locale.US).contains("unreachable")?"ICMP unreachable":"ICMP Time Exceeded / router response";}
                if(!"—".equals(host)) {
                    // Do not add blocking reverse resolution to every probe; direct DNS is available in the target menu.
                    name="Reverse lookup available in DNS tool";
                }
                r.add(String.valueOf(ttl),String.valueOf(probe),host,name,ms,status);r.detail="Hop "+ttl+" of "+hops+"; probe "+probe+" of "+probes;task.emit(r);
                if(interval>0)task.sleep(interval);
            }
            r.note("Hop "+ttl+": "+responses+"/"+probes+" probes exposed an ICMP response. Missing replies do not prove routing failure.");
        }
        r.note(reached?"Destination reached.":"Maximum hop count reached without an exposed destination reply. Routers or destination may suppress ICMP.");
        r.detail="Native ICMP traceroute completed. ASN and geographic hop data are not inferred; no fabricated hop locations are shown.";
        return r;
    }
    private static final class Probe {
        int port; double ms; String status,detail;
        Probe(int port,String status,double ms,String detail){this.port=port;this.status=status;this.ms=ms;this.detail=detail;}
    }
    private static Probe connect(InetAddress address,int port,int timeout,Task task)throws InterruptedException,IOException {
        task.check();Socket socket=null;long start=System.nanoTime();
        try {socket=task.newSocket();task.check();socket.connect(new InetSocketAddress(address,port),timeout);task.check();return new Probe(port,"Open",(System.nanoTime()-start)/1e6,"");}
        catch(SocketTimeoutException e){return new Probe(port,"Timed out",(System.nanoTime()-start)/1e6,"No reply; filtering and packet loss cannot be distinguished.");}
        catch(NoRouteToHostException e){return new Probe(port,"Unreachable",(System.nanoTime()-start)/1e6,message(e));}
        catch(ConnectException e){String text=message(e).toLowerCase(Locale.US);return new Probe(port,text.contains("refused")?"Closed":text.contains("unreach")?"Unreachable":"Indeterminate",(System.nanoTime()-start)/1e6,message(e));}
        catch(Task.RouteException error){throw error;}
        catch(IOException e){return new Probe(port,"Indeterminate",(System.nanoTime()-start)/1e6,message(e));}
        finally {if(socket!=null){task.unregister(socket);try{socket.close();}catch(IOException ignored){}} }
    }
    private static String message(Throwable e){return e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
    private static String service(int p) {
        switch(p){case 20:return "FTP data";case 21:return "FTP";case 22:return "SSH";case 23:return "Telnet";case 25:return "SMTP";case 53:return "DNS";case 80:return "HTTP";case 110:return "POP3";case 123:return "NTP (usually UDP)";case 135:return "MS RPC";case 139:return "NetBIOS";case 143:return "IMAP";case 389:return "LDAP";case 443:return "HTTPS";case 445:return "SMB";case 465:return "SMTPS";case 554:return "RTSP";case 587:return "SMTP submission";case 631:return "IPP";case 636:return "LDAPS";case 853:return "DNS over TLS";case 993:return "IMAPS";case 995:return "POP3S";case 1433:return "MS SQL";case 1883:return "MQTT";case 2049:return "NFS";case 3306:return "MySQL";case 3389:return "RDP";case 5357:return "Web Services for Devices";case 5432:return "PostgreSQL";case 5900:return "VNC";case 6379:return "Redis";case 8000:return "HTTP alternate / other";case 8080:return "HTTP alternate";case 8443:return "HTTPS alternate";case 9100:return "Printing";default:return "Unassigned / other";}
    }
    public static Report ports(String target,String ports,int timeout,int concurrency,Task task)throws Exception {
        int[] requested=Ip.ports(ports);bounded(timeout,100,30000,"Timeout in milliseconds");bounded(concurrency,1,64,"Concurrency");
        InetAddress a=address(target,"Auto",task);task.check();Report r=new Report("TCP port scan",target,"Port","Common service label","Status","Connect attempt ms","Details");
        r.note("TCP connect scan of "+a.getHostAddress()+"; "+requested.length+" ports, concurrency "+concurrency+", timeout "+timeout+" ms. Common service labels do not identify the actual running protocol. A timeout does not prove filtering.");
        ExecutorService workers=Executors.newFixedThreadPool(concurrency);CompletionService<Probe> queue=new ExecutorCompletionService<>(workers);
        int submitted=0,done=0,open=0,closed=0,timedOut=0,other=0;long start=System.nanoTime(),last=0;
        try {
            while(submitted<Math.min(concurrency,requested.length)){final int p=requested[submitted++];queue.submit(()->connect(a,p,timeout,task));}
            while(done<requested.length) {
                task.check();Future<Probe> future=queue.poll(150,TimeUnit.MILLISECONDS);if(future==null)continue;Probe p=future.get();done++;
                if("Open".equals(p.status))open++;else if("Closed".equals(p.status))closed++;else if("Timed out".equals(p.status))timedOut++;else other++;
                r.add(String.valueOf(p.port),service(p.port),p.status,number(p.ms),p.detail);
                r.detail="Examined "+done+" / "+requested.length+" ("+number(done*100.0/requested.length)+"%); open "+open+", closed "+closed+", timed out "+timedOut+", other "+other+". Elapsed "+number((System.nanoTime()-start)/1e9)+" s.";
                if(System.nanoTime()-last>150000000L){task.emit(r);last=System.nanoTime();}
                if(submitted<requested.length){final int next=requested[submitted++];queue.submit(()->connect(a,next,timeout,task));}
            }
        } finally {workers.shutdownNow();task.closeActiveResources();}
        task.emit(r);return r;
    }
    private static final class Device {
        String ip,name="—",flags="",methods="",web="—",openPorts="—",services="—";double ms=Double.NaN;boolean reachable;
    }
    private static void devicePorts(Device d,InetAddress address,int timeout,int[] ports,int start,int end,List<String> methods,List<String> web,List<String> open,List<String> services,Task task)throws Exception {
        for(int index=start;index<end;index++) {
            int port=ports[index];Probe p=connect(address,port,timeout,task);
            if("Open".equals(p.status)||"Closed".equals(p.status)) {
                if(!d.reachable)d.ms=p.ms;d.reachable=true;
                methods.add("TCP "+port+" "+("Open".equals(p.status)?"accepted":"refused (host response)"));
                if("Open".equals(p.status)) {open.add(String.valueOf(port));services.add(port+" "+service(port));if(port==80||port==443)web.add((port==443?"https://":"http://")+d.ip);}
            }
        }
    }
    private static Device discover(long value,int timeout,boolean resolve,String self,String gateway,int[] ports,boolean responsiveOnly,Task task)throws Exception {
        task.check();Device d=new Device();d.ip=Ip.format(value);InetAddress address=InetAddress.getByAddress(new byte[]{(byte)(value>>>24),(byte)(value>>>16),(byte)(value>>>8),(byte)value});List<String> methods=new ArrayList<>();
        if(d.ip.equals(self)){d.reachable=true;d.flags+="S";methods.add("Current device");d.ms=0;}
        if(d.ip.equals(gateway))d.flags+="G";
        List<String> web=new ArrayList<>(),open=new ArrayList<>(),services=new ArrayList<>();
        int initial=responsiveOnly?LAN_PORTS.length:ports.length;
        devicePorts(d,address,timeout,ports,0,initial,methods,web,open,services,task);
        if(!d.reachable&&!task.hasRoute()) {
            try {
                Command c=command(pingCommand(address,timeout,16,null,false),timeout,task);Matcher m=RTT.matcher(c.output);
                if(m.find()&&Double.parseDouble(m.group(2))<=timeout){d.reachable=true;d.flags+="P";d.ms=Double.parseDouble(m.group(2));methods.add("ICMP echo reply");}
            }catch(IOException ignored){}
        }
        // Common mode keeps subnet discovery practical: inspect extra services on
        // responsive devices. Custom mode probes every requested port on each IP.
        if(responsiveOnly&&d.reachable)devicePorts(d,address,timeout,ports,initial,ports.length,methods,web,open,services,task);
        d.openPorts=open.isEmpty()?"None found in "+ports.length+" tested":String.join(", ",open);d.services=services.isEmpty()?"—":String.join("; ",services);
        if(!d.reachable&&!task.hasRoute()) {
            task.check();long began=System.nanoTime();
            try{if(address.isReachable(timeout)){d.reachable=true;d.ms=(System.nanoTime()-began)/1e6;methods.add("Java reachability (ICMP or TCP echo)");}}catch(IOException unavailable){task.check();}
        }
        if(!web.isEmpty()){d.flags+="W";d.web=String.join(" ",web);}
        d.methods=String.join("; ",methods);
        if(d.reachable&&resolve){
            task.check();
            if(task.hasRoute()) {
                String dns=task.route().dnsServer();
                if(dns!=null&&!dns.trim().isEmpty())try {
                    DnsClient.Response response=DnsClient.query(d.ip,"PTR",dns,true,task);
                    for(DnsClient.Record record:response.records)if(record.type==12&&"Answer".equals(record.section)){d.name=record.value;break;}
                }catch(IOException ignored){task.check();}
            } else {String host=address.getCanonicalHostName();if(!host.equals(d.ip))d.name=host;}
        }
        return d;
    }
    public static Report lan(String range,int timeout,int concurrency,boolean resolve,String self,String gateway,Task task)throws Exception {
        return lan(range,timeout,concurrency,resolve,self,gateway,"",task);
    }
    /** Device discovery and a bounded TCP service inventory; use Ports for larger scans. */
    public static Report lan(String range,int timeout,int concurrency,boolean resolve,String self,String gateway,String ports,Task task)throws Exception {
        return lan(range,timeout,concurrency,resolve,self,gateway,ports,false,task);
    }
    public static Report lan(String range,int timeout,int concurrency,boolean resolve,String self,String gateway,String ports,boolean commonMode,Task task)throws Exception {
        long[] bounds=Ip.range(range);bounded(timeout,100,5000,"Timeout in milliseconds");bounded(concurrency,1,64,"Concurrency");int total=(int)(bounds[1]-bounds[0]+1);
        boolean responsiveOnly=commonMode;
        if(commonMode)ports=LAN_COMMON_PORTS;
        int[] inspected=ports==null||ports.trim().isEmpty()?LAN_PORTS.clone():Ip.ports(ports);if(inspected.length>64)throw new IllegalArgumentException("Device discovery supports up to 64 TCP ports per address. Use the Ports tool for a larger port scan.");
        if(responsiveOnly){LinkedHashSet<Integer> ordered=new LinkedHashSet<>();for(int p:LAN_PORTS)ordered.add(p);for(int p:inspected)ordered.add(p);int index=0;for(int p:ordered)inspected[index++]=p;}
        Report r=new Report("LAN scan",range,"IP address","Name (PTR / advertised)","Flags","Probe response ms","Evidence","Web endpoint","Open TCP ports","Common service labels","Advertised services","IPv6 advertised");
        r.note("Range "+Ip.format(bounds[0])+" – "+Ip.format(bounds[1])+"; "+total+" addresses; "+inspected.length+" TCP ports per address; timeout "+timeout+" ms; concurrency "+concurrency+"; reverse names "+resolve+". "+(task.hasRoute()?"Selected network: "+task.route().description()+". Only network-bound TCP responses are used; native ICMP and Java reachability cannot honor this selection.":"Android routing (including an active VPN) is used. TCP responses, native ICMP and Java reachability are used.")+" Firewalls, sleep and client isolation can hide devices. Remote MAC addresses are not assumed accessible.");
        r.note("Open TCP ports accepted a real connection during this scan. Common service labels describe conventional port usage and do not verify the running protocol. Names come from reverse DNS when available; missing names remain unknown. Ports not tested and UDP services are not evaluated.");
        if(responsiveOnly)r.note("Common mode first probes TCP 80, 443, 22 and 445 on each IP, then checks the remaining common ports only on responsive devices. A device that ignores those probes and ICMP may be missed. Choose Custom to probe every specified port on every address.");
        if(task.hasRoute()&&resolve&&(task.route().dnsServer()==null||task.route().dnsServer().trim().isEmpty()))r.note("Reverse names skipped: the selected network has no DNS server. Default-network DNS is not used.");
        r.note("Flags: G configured gateway; S this device; W TCP 80/443 accepted (web protocol not verified); P native ICMP echo reply. Bonjour / UPnP advertisements are available in Service Discovery.");
        ExecutorService workers=Executors.newFixedThreadPool(concurrency);CompletionService<Device> queue=new ExecutorCompletionService<>(workers);int submitted=0,done=0,found=0;long started=System.nanoTime(),last=0;
        try {
            while(submitted<Math.min(concurrency,total)){final long ip=bounds[0]+submitted++;queue.submit(()->discover(ip,timeout,resolve,self,gateway,inspected,responsiveOnly,task));}
            while(done<total) {
                task.check();Future<Device> result=queue.poll(150,TimeUnit.MILLISECONDS);if(result==null)continue;Device d=result.get();done++;
                if(d.reachable){found++;r.add(d.ip,d.name,d.flags,Double.isNaN(d.ms)?"—":number(d.ms),d.methods,d.web,d.openPorts,d.services,"—","—");}
                r.detail="Examined "+done+" / "+total+" addresses ("+number(done*100.0/total)+"%); discovered "+found+"; elapsed "+number((System.nanoTime()-started)/1e9)+" s.";
                if(System.nanoTime()-last>150000000L){task.emit(r);last=System.nanoTime();}
                if(submitted<total){final long ip=bounds[0]+submitted++;queue.submit(()->discover(ip,timeout,resolve,self,gateway,inspected,responsiveOnly,task));}
            }
        } finally {workers.shutdownNow();task.closeActiveResources();}
        task.emit(r);return r;
    }
    public static Report dns(String target,String type,String server,boolean recursive,Task task)throws Exception {
        Report r=new Report("DNS lookup",target,"Section","Name","Type","TTL seconds","Value");
        r.note("Requested "+type+" from "+server+"; recursion desired: "+recursive+". DNS queries are sent directly, unencrypted; Private DNS policy may prevent direct DNS.");task.emit(r);
        DnsClient.Response response=DnsClient.query(target,type,server,recursive,task);
        for(DnsClient.Record record:response.records)r.add(record.section,record.name,DnsClient.typeName(record.type),record.type==41?"—":String.valueOf(record.ttl),record.value);
        r.note("Status: "+response.status()+"; server "+response.server+"; "+response.durationMs+" ms; "+response.transport+"; AA="+((response.flags&0x400)!=0)+"; RA="+((response.flags&0x80)!=0)+"; AD="+((response.flags&0x20)!=0)+"; CD="+((response.flags&0x10)!=0)+".");
        r.note("DNSSEC material is displayed when returned. This client does not validate DNSSEC signatures; the AD bit is the upstream resolver's assertion, not local cryptographic proof.");
        if(response.records.isEmpty())r.note("No records returned for this query.");return r;
    }
    public static Report registration(String target,boolean whois,Task task)throws Exception {
        String host=target(target);Report r=new Report(whois?"WHOIS lookup":"RDAP lookup",host,"Field","Value");
        boolean asn=host.toUpperCase(Locale.US).startsWith("AS")&&host.substring(2).matches("[0-9]+");
        if(asn){long number;try{number=Long.parseLong(host.substring(2));}catch(NumberFormatException e){throw new IllegalArgumentException("AS number must be 1–4294967295.");}if(number<1||number>4294967295L)throw new IllegalArgumentException("AS number must be 1–4294967295.");}
        if(whois) {
            r.note("WHOIS sends the requested name/address to public registry servers over unencrypted TCP port 43. Availability and redaction depend on registry policy.");task.emit(r);
            boolean isAddress=host.contains(":");try{Ip.parse(host);isAddress=true;}catch(IllegalArgumentException ignored){}
            String bootstrapQuery=isAddress||asn?host:IDN.toASCII(host.substring(host.lastIndexOf('.')+1));
            String bootstrap=whois("whois.iana.org",bootstrapQuery,task),server=referral(bootstrap);r.add("Bootstrap server","whois.iana.org");
            String body=bootstrap;
            if(server!=null&&!server.equalsIgnoreCase("whois.iana.org")){task.check();r.add("Referral server",server);body=whois(server,host,task);}
            r.detail=body;for(String line:body.split("\\r?\\n")){int colon=line.indexOf(':');if(colon>0&&!line.startsWith("%")&&!line.startsWith("#"))r.add(line.substring(0,colon).trim(),line.substring(colon+1).trim());}
            if(body.trim().isEmpty())r.note("Registry returned no WHOIS data.");
        } else {
            String kind;
            try{Ip.parse(host);kind="ip";}catch(IllegalArgumentException e){kind=asn?"autnum":host.contains(":")?"ip":"domain";}
            if(asn)host=String.valueOf(Long.parseLong(host.substring(2)));
            if("domain".equals(kind))host=IDN.toASCII(host);
            String url="https://rdap.org/"+kind+"/"+URLEncoder.encode(host,"UTF-8");
            r.note("Sends this public registration query to rdap.org over HTTPS; redirects lead to the responsible public registry. Registration data may be redacted.");task.emit(r);
            HttpResult response=httpGet(url,2097152,task);r.add("HTTP status",String.valueOf(response.status));r.add("Registry endpoint",response.url);r.add("Content type",response.contentType);
            r.detail=response.body;
            try {rdapFields(new JSONObject(response.body),r);}
            catch(JSONException malformed){r.note("The registry response is not valid RDAP JSON; its original body is retained.");}
            if(response.status<200||response.status>=300)r.note("Registry returned HTTP "+response.status+". Its response body is retained below.");
        }
        return r;
    }
    private static void rdapFields(JSONObject object,Report r) {
        for(String field:new String[]{"objectClassName","name","handle","ldhName","unicodeName","startAddress","endAddress","ipVersion","country","type","port43"}) {
            String value=object.optString(field,"");if(!value.isEmpty())r.add(field,value);
        }
        JSONArray status=object.optJSONArray("status");if(status!=null)r.add("Status",status.toString());
        JSONArray events=object.optJSONArray("events");if(events!=null)for(int i=0;i<events.length();i++){JSONObject event=events.optJSONObject(i);if(event!=null)r.add(event.optString("eventAction","Event"),event.optString("eventDate","Date unavailable"));}
        JSONArray servers=object.optJSONArray("nameservers");if(servers!=null)for(int i=0;i<servers.length();i++){JSONObject ns=servers.optJSONObject(i);if(ns!=null)r.add("Nameserver",ns.optString("ldhName",ns.optString("unicodeName","Unavailable")));}
        JSONArray entities=object.optJSONArray("entities");if(entities!=null)for(int i=0;i<entities.length();i++) {
            JSONObject entity=entities.optJSONObject(i);if(entity==null)continue;
            JSONArray roles=entity.optJSONArray("roles");String label=roles==null?"Entity":roles.toString();String handle=entity.optString("handle","");if(!handle.isEmpty())r.add(label+" handle",handle);
            JSONArray vcard=entity.optJSONArray("vcardArray");JSONArray properties=vcard==null?null:vcard.optJSONArray(1);
            if(properties!=null)for(int j=0;j<properties.length();j++){JSONArray property=properties.optJSONArray(j);if(property==null||property.length()<4)continue;String field=property.optString(0);if(Arrays.asList("fn","org","email","tel","adr","url").contains(field))r.add(label+" "+field,String.valueOf(property.opt(3)));}
            JSONArray entityEvents=entity.optJSONArray("events");if(entityEvents!=null)for(int j=0;j<entityEvents.length();j++){JSONObject e=entityEvents.optJSONObject(j);if(e!=null)r.add(label+" "+e.optString("eventAction","event"),e.optString("eventDate"));}
        }
    }
    private static String referral(String body) {
        Matcher m=Pattern.compile("(?im)^(?:refer|whois):\\s*([a-z0-9.-]+)\\s*$").matcher(body);
        return m.find()?m.group(1):null;
    }
    private static String whois(String server,String query,Task task)throws Exception {
        task.check();Socket socket=task.newSocket();
        try {task.check();socket.connect(new InetSocketAddress(address(server,"Auto",task),43),6000);socket.setSoTimeout(6000);
            OutputStream out=socket.getOutputStream();out.write((query+"\r\n").getBytes(StandardCharsets.UTF_8));out.flush();
            return new String(readLimited(socket.getInputStream(),2097152,task),StandardCharsets.UTF_8);
        }finally{task.unregister(socket);socket.close();}
    }
    public static final class HttpResult { public int status;public String body,url,contentType; }
    /** Secure bounded GET shared with optional public IP information. */
    public static HttpResult httpGet(String url,int limit,Task task)throws Exception {
        if(limit<1||limit>4194304)throw new IllegalArgumentException("HTTP response limit must be 1–4 MiB.");
        String current=url;
        for(int redirects=0;redirects<=5;redirects++) {
            task.check();URL endpoint=new URL(current);if(!"https".equalsIgnoreCase(endpoint.getProtocol()))throw new IOException("Only HTTPS lookup URLs are accepted.");
            HttpURLConnection c=task.open(endpoint);Closeable cancel=()->c.disconnect();task.register(cancel);
            try {c.setConnectTimeout(6000);c.setReadTimeout(6000);c.setInstanceFollowRedirects(false);c.setRequestProperty("Accept","application/rdap+json, application/json, text/plain;q=0.9");c.setRequestProperty("User-Agent","FieldKitNetworkAnalyzer/1.0");
                int status=c.getResponseCode();
                if(status==301||status==302||status==303||status==307||status==308){String location=c.getHeaderField("Location");if(location==null)throw new IOException("Registry redirect had no destination.");current=new URL(endpoint,location).toString();continue;}
                InputStream in=status>=400?c.getErrorStream():c.getInputStream();HttpResult result=new HttpResult();result.status=status;result.url=current;result.contentType=String.valueOf(c.getContentType());
                result.body=in==null?"":new String(readLimited(in,limit,task),StandardCharsets.UTF_8);return result;
            }finally{task.unregister(cancel);c.disconnect();}
        }
        throw new IOException("Too many HTTPS redirects.");
    }
    private static byte[] readLimited(InputStream input,int max,Task task)throws Exception {
        long deadline=System.nanoTime()+30000000000L;
        try(InputStream in=input;ByteArrayOutputStream out=new ByteArrayOutputStream()) {byte[] b=new byte[8192];int n;while((n=in.read(b))!=-1){task.check();if(System.nanoTime()>deadline)throw new SocketTimeoutException("Lookup exceeded 30 seconds.");if(out.size()+n>max)throw new IOException("Response exceeded "+max+" bytes.");out.write(b,0,n);}return out.toByteArray();}
    }
    public static Report speed(String base,int bytes,Task task)throws Exception {
        bounded(bytes,100000,50000000,"Transfer bytes per direction");URL endpoint=new URL(base.trim());
        if(!"https".equalsIgnoreCase(endpoint.getProtocol())||endpoint.getHost().isEmpty())throw new IllegalArgumentException("Speed endpoint must be an HTTPS origin supporting /__down and /__up.");
        String root=base.trim().replaceAll("/+$","");Report r=new Report("Internet speed test",root,"Measurement","Value","Details");
        r.note("Actual single-stream HTTPS transfer test; approximately "+number(bytes/1000000.0)+" MB each for download and upload, plus latency probes and protocol overhead. The server sees your public IP. This measures this internet path, not local Wi-Fi capacity. Results can be limited by test size, TLS, device and server.");task.emit(r);
        List<Double> latency=new ArrayList<>();
        for(int i=0;i<5;i++) {
            task.check();long start=System.nanoTime();HttpResult response=httpGet(root+"/__down?bytes=0&cachebust="+System.nanoTime(),4096,task);
            if(response.status<200||response.status>=300)throw new IOException("Latency endpoint returned HTTP "+response.status+".");
            double ms=(System.nanoTime()-start)/1e6;latency.add(ms);r.series("HTTP request latency ms",ms);r.add("Latency request "+(i+1),number(ms)+" ms","HTTPS request duration including any connection setup; not ICMP RTT");task.emit(r);
        }
        double sum=0,jitter=0;for(int i=0;i<latency.size();i++){sum+=latency.get(i);if(i>0)jitter+=Math.abs(latency.get(i)-latency.get(i-1));}
        r.add("HTTP latency mean",number(sum/latency.size())+" ms","Five real HTTPS requests");r.add("HTTP latency variation",number(jitter/(latency.size()-1))+" ms","Mean absolute difference between adjacent request durations");
        transfer(root,bytes,false,r,task);transfer(root,bytes,true,r,task);
        r.note("Completed. Upload rate includes upload and waiting for the server response; a client write alone is not treated as server-confirmed delivery. Test is a finite single connection estimate, not an ISP line-rate certification.");return r;
    }
    private static void transfer(String base,int size,boolean upload,Report r,Task task)throws Exception {
        task.check();String direction=upload?"Upload":"Download";
        URL url=new URL(base+(upload?"/__up":"/__down?bytes="+size+"&cachebust="+System.nanoTime()));HttpURLConnection c=task.open(url);Closeable cancel=()->c.disconnect();task.register(cancel);
        byte[] buffer=new byte[32768];int total=0;long began=System.nanoTime(),last=began;
        ScheduledExecutorService deadline=Executors.newSingleThreadScheduledExecutor();
        deadline.schedule(()->c.disconnect(),90,TimeUnit.SECONDS);
        try {
            c.setConnectTimeout(10000);c.setReadTimeout(20000);c.setUseCaches(false);c.setInstanceFollowRedirects(false);c.setRequestProperty("Accept-Encoding","identity");c.setRequestProperty("Cache-Control","no-cache, no-store");c.setRequestProperty("User-Agent","FieldKitNetworkAnalyzer/1.0");
            if(upload) {
                c.setRequestMethod("POST");c.setDoOutput(true);c.setFixedLengthStreamingMode(size);c.setRequestProperty("Content-Type","application/octet-stream");new SecureRandom().nextBytes(buffer);
                try(OutputStream out=c.getOutputStream()) {
                    while(total<size){task.check();int n=Math.min(buffer.length,size-total);out.write(buffer,0,n);total+=n;if(System.nanoTime()-last>150000000L){double mbps=total*8.0/(System.nanoTime()-began)*1000;r.series("Upload client-write Mbps (unconfirmed)",mbps);r.detail="Upload written "+total+" / "+size+" bytes; waiting for server confirmation at end.";task.emit(r);last=System.nanoTime();}}
                    out.flush();
                }
            }
            int status=c.getResponseCode();if(status<200||status>=300)throw new IOException(direction+" endpoint returned HTTP "+status+".");
            try(InputStream in=c.getInputStream()) {
                int n,responseBytes=0;
                while((n=in.read(buffer))!=-1) {
                    task.check();
                    if(upload){responseBytes+=n;if(responseBytes>1048576)throw new IOException("Unexpectedly large upload acknowledgement.");}
                    else {total+=n;if(total>size+65536)throw new IOException("Download endpoint returned more data than requested.");}
                    if(!upload&&System.nanoTime()-last>150000000L){double mbps=total*8.0/(System.nanoTime()-began)*1000;r.series("Download Mbps",mbps);r.detail="Download received "+total+" / "+size+" bytes.";task.emit(r);last=System.nanoTime();}
                    if(System.nanoTime()-began>90000000000L)throw new SocketTimeoutException(direction+" exceeded 90 seconds.");
                }
            }
            if(!upload&&total!=size)throw new IOException("Download incomplete: requested "+size+" bytes, received "+total+".");
            double seconds=(System.nanoTime()-began)/1e9,mbps=total*8.0/seconds/1e6;
            r.series(direction+" Mbps",mbps);r.add(direction,number(mbps)+" Mbps",total+" bytes / "+number(seconds)+" s; HTTP "+status+"; includes request setup and completion");r.detail=direction+" complete.";task.emit(r);
        } finally {deadline.shutdownNow();task.unregister(cancel);c.disconnect();}
    }
    public static Report wol(String mac,String dest,int port,Task task)throws Exception {
        bounded(port,1,65535,"UDP destination port");byte[] packet=Ip.magicPacket(mac);InetAddress destination=address(dest,"IPv4",task);
        if(!(destination instanceof Inet4Address))throw new IllegalArgumentException("Wake-on-LAN broadcast destination must be IPv4.");
        Report r=new Report("Wake-on-LAN",mac,"Field","Value");DatagramSocket socket=new DatagramSocket();task.register(socket);
        try {task.check();task.bind(socket);task.check();socket.setBroadcast(true);socket.send(new DatagramPacket(packet,packet.length,destination,port));task.check();r.add("Destination",destination.getHostAddress()+":"+port);r.add("Magic packet",packet.length+" bytes sent");r.note("UDP packet transmission succeeded. This does not confirm the device powered on. Target firmware, Ethernet adapter and router/VPN must support waking.");}
        finally{task.unregister(socket);socket.close();}return r;
    }
}
