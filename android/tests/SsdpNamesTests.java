package com.fieldkit.analyzer;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class SsdpNamesTests {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception {
        String xml="<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><device><friendlyName>Living Room &amp; TV</friendlyName><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><deviceList><device><friendlyName>Nested service</friendlyName></device></deviceList></device></root>";
        check(SsdpNames.parseDescription(xml.getBytes(StandardCharsets.UTF_8)).equals("Living Room & TV"),"real namespaced friendlyName parsed with XML escaping");
        check(SsdpNames.parseDescription("<root><device><modelName>Do not invent this name</modelName></device></root>".getBytes(StandardCharsets.UTF_8)).isEmpty(),"model or arbitrary HTML title never substituted for device name");
        String entity="<!DOCTYPE root [<!ENTITY secret SYSTEM 'file:///not-read'>]><root><friendlyName>&secret;</friendlyName></root>";
        boolean rejected=false;try{SsdpNames.parseDescription(entity.getBytes(StandardCharsets.UTF_8));}catch(Exception expected){rejected=true;}check(rejected,"DTD/entity device description rejected");
        check(SsdpNames.safeDescription(new URL("http://192.168.7.2:8080/device.xml"),"192.168.7.2"),"same-device local description allowed");
        check(!SsdpNames.safeDescription(new URL("http://192.168.7.3/device.xml"),"192.168.7.2"),"advertiser cannot ask for another device's URL");
        check(!SsdpNames.safeDescription(new URL("http://127.0.0.1/device.xml"),"192.168.7.2"),"remote advertiser cannot redirect discovery to localhost");
        check(!SsdpNames.safeDescription(new URL("http://8.8.8.8/device.xml"),"8.8.8.8"),"public description endpoint not fetched");
        check(!SsdpNames.safeDescription(new URL("http://user:pass@192.168.7.2/device.xml"),"192.168.7.2"),"embedded URL credentials not sent");
        check(!SsdpNames.safeDescription(new URL("https://192.168.7.2/device.xml"),"192.168.7.2"),"self-signed HTTPS is not bypassed by an insecure discovery client");
        AtomicReference<Throwable> failure=new AtomicReference<>();
        try(ServerSocket server=new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {
            Thread fixture=new Thread(()->{
                try(Socket socket=server.accept()) {
                    socket.setSoTimeout(1000);InputStream input=socket.getInputStream();ByteArrayOutputStream request=new ByteArrayOutputStream();
                    int b;while(request.size()<4096&&(b=input.read())>=0){request.write(b);if(request.toString("US-ASCII").endsWith("\r\n\r\n"))break;}
                    check(request.toString("US-ASCII").startsWith("GET /device.xml HTTP/1.1"),"read-only actual HTTP description request");
                    byte[] body=xml.getBytes(StandardCharsets.UTF_8);socket.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: "+body.length+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().write(body);
                }catch(Throwable error){failure.set(error);}
            },"ssdp-description-fixture");fixture.start();
            String[] name=SsdpNames.description("127.0.0.1","http://127.0.0.1:"+server.getLocalPort()+"/device.xml",new Task(null),System.nanoTime()+TimeUnit.SECONDS.toNanos(2));fixture.join(2000);
            check(name!=null&&name[1].equals("Living Room & TV")&&name[2].equals("UPnP"),"actual HTTP description supplies friendlyName with provenance");
            if(failure.get()!=null)throw new AssertionError(failure.get());
        }
        System.out.println("SsdpNamesTests: "+checks+" checks passed (actual HTTP description, local URL scope, XML parsing and provenance).");
    }
}
