package com.fieldkit.analyzer;

import java.io.Closeable;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/** Cancellation owns sockets and child processes as well as the logical operation. */
public final class Task {
    /** Per-operation route. Implementations must fail closed when their network disappears. */
    public interface Route {
        InetAddress[] resolve(String host) throws UnknownHostException;
        void bind(Socket socket) throws IOException;
        void bind(DatagramSocket socket) throws IOException;
        /** Create an unconnected socket already assigned to this route. */
        default Socket createSocket() throws IOException {
            Socket socket=new Socket();
            try { socket.getReuseAddress();bind(socket);return socket; }
            catch(IOException|RuntimeException error){try{socket.close();}catch(IOException ignored){}throw error;}
        }
        HttpURLConnection open(URL url) throws IOException;
        String description();
        String dnsServer();
    }
    private volatile Route route;
    /** A route choice could not be honored; never substitute another path silently. */
    public static final class RouteException extends IOException {
        public final String title,network;
        public final boolean canUseSystem;
        public RouteException(String title,String message,String network,boolean canUseSystem,Throwable cause){super(message,cause);this.title=title;this.network=network;this.canUseSystem=canUseSystem;}
    }
    /** Executor futures wrap failures; expose the useful route error to the UI. */
    public static RouteException routeFailure(Throwable failure){
        Set<Throwable> visited=Collections.newSetFromMap(new IdentityHashMap<Throwable,Boolean>());
        for(Throwable cause=failure;cause!=null&&visited.add(cause);cause=cause.getCause())if(cause instanceof RouteException)return (RouteException)cause;
        return null;
    }
    private final AtomicBoolean cancelled=new AtomicBoolean();
    private final Set<Closeable> resources=new HashSet<>();
    private final Set<Process> processes=new HashSet<>();
    private final Consumer<Report> listener;
    public Task(Consumer<Report> listener){this.listener=listener;}
    public void route(Route route){this.route=route;}
    public Route route(){return route;}
    public boolean hasRoute(){return route!=null;}
    /** Callers must unregister/close the returned socket, including after cancellation. */
    public Socket newSocket()throws IOException {
        Route r=route;Socket socket;
        try{socket=r==null?new Socket():r.createSocket();}
        catch(IOException error){if(r==null||error instanceof RouteException)throw error;throw new RouteException("Selected network unavailable","Cannot create a probe on "+r.description()+". The network may have disconnected or Android/VPN policy may block this path. Choose Android routing to use the current VPN policy, or reconnect the selected network. Details: "+error.getMessage(),r.description(),true,error);}
        register(socket);return socket;
    }
    public InetAddress[] resolve(String host)throws UnknownHostException {Route r=route;return r==null?InetAddress.getAllByName(host):r.resolve(host);}
    public void bind(Socket socket)throws IOException {Route r=route;if(r!=null)r.bind(socket);}
    public void bind(DatagramSocket socket)throws IOException {Route r=route;if(r!=null)r.bind(socket);}
    public HttpURLConnection open(URL url)throws IOException {Route r=route;return r==null?(HttpURLConnection)url.openConnection():r.open(url);}
    public boolean isCancelled(){return cancelled.get()||Thread.currentThread().isInterrupted();}
    public void check() throws InterruptedException {if(isCancelled())throw new InterruptedException("Operation stopped");}
    public void emit(Report report){if(!isCancelled()&&listener!=null)listener.accept(report);}
    public void sleep(long ms)throws InterruptedException {long end=System.nanoTime()+ms*1000000L;while(System.nanoTime()<end){check();Thread.sleep(Math.min(100,Math.max(1,(end-System.nanoTime())/1000000L)));}check();}
    public synchronized void register(Closeable c){if(cancelled.get())close(c);else resources.add(c);}
    public synchronized void unregister(Closeable c){resources.remove(c);}
    /** Close in-flight probes after a worker failure without turning it into user cancellation. */
    public synchronized void closeActiveResources(){for(Closeable c:resources)close(c);resources.clear();}
    public synchronized void own(Process p){processes.removeIf(old -> !old.isAlive());if(cancelled.get())p.destroy();else processes.add(p);}
    public synchronized void cancel(){cancelled.set(true);closeActiveResources();for(Process p:processes)p.destroy();processes.clear();}
    private static void close(Closeable c){try{c.close();}catch(Exception ignored){}}
}
