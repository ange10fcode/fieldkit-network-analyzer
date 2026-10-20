package com.fieldkit.analyzer;

public final class NearbySignalTests {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    public static void main(String[] args){
        NearbySignal.Reading ble=new NearbySignal.Reading("ble:1","BLE","1","Device");
        check(!ble.update(127,1000),"Unavailable RSSI rejected");
        check(!ble.update(-50,0),"Unknown age rejected");
        check(ble.update(-80,1000),"First radio sample accepted");
        check(ble.trend(2000).contains("another"),"Single sample has no trend");
        check(!ble.update(-30,1000),"Cached timestamp not treated as fresh");
        check(ble.samples==1&&ble.rssi==-80,"Cached sample does not alter signal");
        check(ble.update(-55,2000),"Fresh sample accepted");
        check(ble.trend(2000).equals("Stronger signal"),"Warmer trend from fresh sample");
        check(ble.smoothed()==-70,"RSSI smoothing");
        check(ble.update(-100,3000),"Weak fresh sample accepted");
        check(ble.trend(3000).equals("Weaker signal"),"Colder trend from fresh sample");
        check(ble.trend(13001).contains("fresh"),"BLE stale trend not reused");
        NearbySignal.Reading wifi=new NearbySignal.Reading("wifi:1","Wi-Fi","1","AP");
        wifi.update(-60,1000);wifi.update(-60,2000);
        check(wifi.trend(2000).contains("steady"),"Stable signal");
        check(wifi.trend(93000).contains("fresh"),"Wi-Fi cached trend expires");
        check(NearbySignal.strengthPercent(-150)==0,"Strength lower bound");
        check(NearbySignal.strengthPercent(10)==100,"Strength upper bound");
        check(NearbySignal.strengthPercent(-75)==50,"Strength relative scale");
        check(NearbySignal.age(4500,1000).equals("3 s ago"),"Elapsed age");
        check(NearbySignal.age(122000,1000).equals("2 min ago"),"Minute age");
        check(NearbySignal.age(1000,2000).equals("0 s ago"),"Clock bound");
        check(NearbySignal.normalizeHeading(-90)==270,"Negative heading normalizes");
        check(NearbySignal.normalizeHeading(360)==0,"Full turn normalizes");
        check(NearbySignal.cardinal(0).equals("N"),"North");
        check(NearbySignal.cardinal(359).equals("N"),"North wrap");
        check(NearbySignal.cardinal(45).equals("NE"),"Northeast");
        check(NearbySignal.cardinal(180).equals("S"),"South");
        check(NearbySignal.cardinal(-90).equals("W"),"West");
        System.out.println("NearbySignalTests: "+checks+" checks passed");
    }
}
