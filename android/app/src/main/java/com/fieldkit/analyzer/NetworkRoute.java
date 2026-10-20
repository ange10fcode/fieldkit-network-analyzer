package com.fieldkit.analyzer;

import android.content.Context;
import android.net.Network;
import java.io.IOException;
import java.net.*;

/** Per-operation Android routing. Never changes the process-wide default network. */
public final class NetworkRoute {
    private NetworkRoute() {}

    public static void attach(Context context,String connectionId,Task task)throws Exception {
        task.check();
        if(connectionId==null||connectionId.isEmpty()) { task.route(null);return; }
        NetworkInventory.Connection connection=NetworkInventory.lookup(context,connectionId);
        if(connection==null)throw new Task.RouteException("Network disconnected","The selected network is no longer connected. Select a current network and try again, or choose Android routing to follow the current system/VPN route.",connectionId,true,null);
        if(connection.network==null)throw new Task.RouteException("Network is information only","Android exposes addresses for "+connection.title()+", but has not exposed a usable network handle. Choose Android routing to follow the system/VPN route, or select a network with an Android handle.",connection.title(),true,null);
        task.route(new BoundRoute(connection));
    }

    private static final class BoundRoute implements Task.Route {
        private final Network network;
        private final String title,dns;
        BoundRoute(NetworkInventory.Connection c){network=c.network;title=c.title();dns=c.dnsServer();}
        @Override public InetAddress[] resolve(String host)throws UnknownHostException {
            try{return network.getAllByName(host);}catch(SecurityException e){throw new UnknownHostException("Name resolution on "+title+" was denied by Android or VPN policy.");}
        }
        @Override public void bind(Socket socket)throws IOException {
            try{socket.getReuseAddress();network.bindSocket(socket);}catch(IOException|SecurityException e){throw denied("bind a TCP socket",e);}
        }
        @Override public Socket createSocket()throws IOException {
            // Android's factory creates and assigns the descriptor before connect().
            // This also avoids implementation-specific lazy SocketImpl creation.
            try{return network.getSocketFactory().createSocket();}catch(IOException|SecurityException e){throw denied("create a TCP probe",e);}
        }
        @Override public void bind(DatagramSocket socket)throws IOException {
            try{network.bindSocket(socket);}catch(IOException|SecurityException e){throw denied("bind a UDP socket",e);}
        }
        @Override public HttpURLConnection open(URL url)throws IOException {
            try{return (HttpURLConnection)network.openConnection(url);}catch(IOException|SecurityException e){throw denied("open a connection",e);}
        }
        @Override public String description(){return title+" (Android network "+network+")";}
        @Override public String dnsServer(){return dns;}
        private Task.RouteException denied(String operation,Exception cause){return new Task.RouteException("Selected network blocked or disconnected","Android could not "+operation+" on "+title+". This can happen when a VPN forbids using the underlying Wi-Fi/cellular link, or when the selected network disconnects. Choose Android routing to follow the current system/VPN policy. For a local subnet through a Tailscale exit node, check Tailscale's Allow LAN access setting. No different network was used. Details: "+(cause.getMessage()==null?cause.getClass().getSimpleName():cause.getMessage()),title,true,cause);}
    }
}
