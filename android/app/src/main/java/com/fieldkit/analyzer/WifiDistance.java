package com.fieldkit.analyzer;

import android.content.Context;
import android.net.wifi.ScanResult;
import android.os.Build;
import java.util.List;
import java.util.concurrent.Executor;

/** API-isolated 802.11mc ranging. RSSI is never converted to meters. */
public final class WifiDistance {
    private WifiDistance(){}
    public interface Listener {void success(int millimeters,int deviationMillimeters,long elapsedTimestamp);void failure(String message);}
    public static boolean supported(Context context){return Build.VERSION.SDK_INT>=28&&context.getPackageManager().hasSystemFeature("android.hardware.wifi.rtt");}
    public static boolean responder(ScanResult target){return Build.VERSION.SDK_INT>=28&&target!=null&&Api28.responder(target);}
    public static boolean available(Context context){return supported(context)&&Api28.available(context);}
    public static void measure(Context context,ScanResult target,Executor executor,Listener listener){
        if(!supported(context)){listener.failure("This phone has no Wi-Fi RTT ranging hardware.");return;}
        if(!responder(target)){listener.failure("This access point does not advertise RTT distance support.");return;}
        Api28.measure(context,target,executor,listener);
    }
    private static final class Api28 {
        static boolean responder(ScanResult target){return target.is80211mcResponder();}
        static android.net.wifi.rtt.WifiRttManager manager(Context context){return (android.net.wifi.rtt.WifiRttManager)context.getSystemService(Context.WIFI_RTT_RANGING_SERVICE);}
        static boolean available(Context context){try{android.net.wifi.rtt.WifiRttManager manager=manager(context);return manager!=null&&manager.isAvailable();}catch(RuntimeException e){return false;}}
        static void measure(Context context,ScanResult target,Executor executor,Listener listener){
            try{
                android.net.wifi.rtt.WifiRttManager manager=manager(context);
                if(manager==null||!manager.isAvailable()){listener.failure("Wi-Fi RTT is unavailable. Turn on Wi-Fi and Location, then try again.");return;}
                manager.startRanging(new android.net.wifi.rtt.RangingRequest.Builder().addAccessPoint(target).build(),executor,new android.net.wifi.rtt.RangingResultCallback(){
                    @Override public void onRangingFailure(int code){listener.failure("Distance measurement failed (Android status "+code+"). Move into range and retry.");}
                    @Override public void onRangingResults(List<android.net.wifi.rtt.RangingResult> results){
                        for(android.net.wifi.rtt.RangingResult result:results){
                            if(result.getMacAddress()==null||!result.getMacAddress().toString().equalsIgnoreCase(target.BSSID))continue;
                            if(result.getStatus()!=android.net.wifi.rtt.RangingResult.STATUS_SUCCESS){listener.failure("The access point did not return a usable distance. Move into range and retry.");return;}
                            if(result.getDistanceMm()<0){listener.failure("The distance measurement was invalid. Retry from another position.");return;}
                            listener.success(result.getDistanceMm(),result.getDistanceStdDevMm(),result.getRangingTimestampMillis());return;
                        }
                        listener.failure("No distance result was returned for this access point.");
                    }
                });
            }catch(SecurityException e){listener.failure("Distance access was denied. Allow Nearby Wi-Fi devices and precise location in app settings.");}
            catch(RuntimeException e){listener.failure("Distance measurement could not start. Wi-Fi may be busy; retry shortly.");}
        }
    }
}
