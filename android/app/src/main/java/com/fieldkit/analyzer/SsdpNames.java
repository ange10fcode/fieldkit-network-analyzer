package com.fieldkit.analyzer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/** A bounded read-only SSDP friendly-name pass; only fetch the responding device's own description. */
public final class SsdpNames {
    private SsdpNames() { }
    public static Report discover(String range,Task task)throws Exception {
        Report result=new Report("UPnP device names",range,"IP address","Name","Source","Details");
        long[] bounds=Ip.range(range);Map<String,String[]> descriptions=new LinkedHashMap<>();
        DatagramSocket socket=new DatagramSocket();task.register(socket);
        try {
            task.bind(socket);socket.setSoTimeout(150);
            byte[] bytes=("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
            DatagramPacket query=new DatagramPacket(bytes,bytes.length,InetAddress.getByName("239.255.255.250"),1900);socket.send(query);
            long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(1800);
            while(System.nanoTime()<deadline&&descriptions.size()<16) {
                task.check();byte[] buffer=new byte[16384];DatagramPacket packet=new DatagramPacket(buffer,buffer.length);
                try { socket.receive(packet); }catch(SocketTimeoutException quiet){continue;}
                String ip=packet.getAddress().getHostAddress();long numeric;
                try{numeric=Ip.parse(ip);}catch(IllegalArgumentException invalid){continue;}
                if(numeric<bounds[0]||numeric>bounds[1])continue;
                String text=new String(buffer,0,packet.getLength(),StandardCharsets.ISO_8859_1);
                if(!text.toUpperCase(Locale.US).startsWith("HTTP/1.1 200"))continue;
                String location="";for(String line:text.split("\r?\n")){int colon=line.indexOf(':');if(colon>0&&line.substring(0,colon).trim().equalsIgnoreCase("location"))location=line.substring(colon+1).trim();}
                try { URL url=new URL(location);if(!safeDescription(url,ip))continue; }
                catch(Exception malformed){continue;}
                descriptions.put(ip+"|"+location,new String[]{ip,location});
            }
        } finally {task.unregister(socket);socket.close();}
        ExecutorService workers=Executors.newFixedThreadPool(4);CompletionService<String[]> queue=new ExecutorCompletionService<>(workers);
        Task child=new Task(null);child.route(task.route());Closeable stop=child::cancel;task.register(stop);
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);int submitted=0,finished=0;
        List<String[]> requests=new ArrayList<>(descriptions.values());
        try {
            while(submitted<Math.min(4,requests.size())){String[] item=requests.get(submitted++);queue.submit(()->description(item[0],item[1],child,deadline));}
            while(finished<requests.size()&&System.nanoTime()<deadline) {
                task.check();Future<String[]> reply=queue.poll(100,TimeUnit.MILLISECONDS);if(reply==null)continue;finished++;
                try{String[] row=reply.get();if(row!=null)result.add(row);}catch(java.util.concurrent.ExecutionException unavailable){task.check();}
                if(submitted<requests.size()){String[] item=requests.get(submitted++);queue.submit(()->description(item[0],item[1],child,deadline));}
            }
            result.note("SSDP received "+descriptions.size()+" in-range description endpoints; "+result.rows.size()+" device friendly names were read. Names are device advertisements, not verified identities. No control actions were sent.");
            return result;
        } finally {child.cancel();task.unregister(stop);workers.shutdownNow();}
    }

    static String[] description(String ip,String location,Task task,long deadline)throws Exception {
        URL url=new URL(location);if(!safeDescription(url,ip))return null;task.check();
        HttpURLConnection connection=task.open(url);Closeable close=connection::disconnect;task.register(close);
        try {
            connection.setInstanceFollowRedirects(false);connection.setConnectTimeout(700);connection.setReadTimeout(500);
            connection.setRequestProperty("Accept","text/xml, application/xml");
            if(connection.getResponseCode()!=200)return null;
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();
            try(InputStream input=connection.getInputStream()) {
                byte[] buffer=new byte[4096];int count;
                while((count=input.read(buffer))>=0) {
                    task.check();if(System.nanoTime()>=deadline)return null;
                    if(bytes.size()+count>262144)return null;bytes.write(buffer,0,count);
                }
            }
            String name=parseDescription(bytes.toByteArray());
            return name.isEmpty()?null:new String[]{ip,name,"UPnP","Device-provided friendlyName from "+location};
        } finally {task.unregister(close);connection.disconnect();}
    }

    static boolean safeDescription(URL url,String source) {
        if(!"http".equalsIgnoreCase(url.getProtocol())||url.getUserInfo()!=null||!url.getHost().equals(source))return false;
        try {
            long ip=Ip.parse(source);
            return (ip>>>24)==10||(ip>>>20)==0xac1||(ip>>>16)==0xc0a8||(ip>>>16)==0xa9fe||(ip>>>24)==127||(ip>>>22)==0x191;
        }catch(IllegalArgumentException invalid){return false;}
    }

    static String parseDescription(byte[] xml)throws Exception {
        // Reject DTDs before parser creation even on Android parsers that lack a feature toggle.
        String text=new String(xml,StandardCharsets.UTF_8).replace("\u0000","");
        if(text.toUpperCase(Locale.US).contains("<!DOCTYPE")||text.toUpperCase(Locale.US).contains("<!ENTITY"))throw new java.io.IOException("Device description contains a DTD or entity declaration");
        DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();factory.setNamespaceAware(true);factory.setExpandEntityReferences(false);
        try{factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);}catch(Exception unsupported){ }
        try{factory.setFeature("http://xml.org/sax/features/external-general-entities",false);}catch(Exception unsupported){ }
        try{factory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);}catch(Exception unsupported){ }
        DocumentBuilder builder=factory.newDocumentBuilder();builder.setEntityResolver((publicId,systemId)->{throw new org.xml.sax.SAXException("External entities are not allowed");});
        Document document=builder.parse(new ByteArrayInputStream(xml));NodeList names=document.getElementsByTagNameNS("*","friendlyName");
        if(names.getLength()==0)return "";String name=names.item(0).getTextContent().replaceAll("[\\p{Cntrl}]"," ").trim();
        return name.length()>180?name.substring(0,180):name;
    }
}
