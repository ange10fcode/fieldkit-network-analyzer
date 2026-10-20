package com.fieldkit.analyzer;

import java.util.ArrayList;

/** Radio measurements only. Signal strength cannot establish a distance or bearing. */
public final class NearbySignal {
    private NearbySignal(){}
    public static final class Reading {
        public final String key,kind,address;
        public String name,detail="";
        public int rssi,samples;
        public long observedAt,observedWall;
        public boolean restored;
        private double average,previous;
        private Integer baseline;
        private final ArrayList<Integer> history=new ArrayList<>();
        public Reading(String key,String kind,String address,String name){this.key=key;this.kind=kind;this.address=address;this.name=name;}
        public boolean update(int value,long at){
            return update(value,at,0);
        }
        public boolean update(int value,long at,long wall){
            if(value>0||value< -127||at<=0||(samples>0&&at<=observedAt))return false;
            if(wall>0&&observedWall>0&&wall<=observedWall)return false;
            previous=samples==0?value:average;
            average=samples==0?value:(average*.6+value*.4);
            rssi=value;observedAt=at;observedWall=wall;restored=false;samples++;
            if(baseline==null)baseline=value;
            history.add(value);if(history.size()>32)history.remove(0);return true;
        }
        public int smoothed(){return (int)Math.round(average);}
        public double average(){return average;}
        public double previous(){return previous;}
        public int[] history(){int[] result=new int[history.size()];for(int i=0;i<result.length;i++)result[i]=history.get(i);return result;}
        public int baseline(){return baseline==null?smoothed():baseline;}
        public void resetBaseline(){baseline=smoothed();}
        public int baselineChange(){return smoothed()-baseline();}
        public void restore(int value,int count,long at,long wall,double average,double previous,int baseline,int[] values){
            rssi=value;samples=Math.max(1,count);observedAt=at;observedWall=wall;this.average=average;this.previous=previous;this.baseline=baseline;restored=true;history.clear();
            for(int v:values)if(v>=-127&&v<=0){history.add(v);if(history.size()>32)history.remove(0);}
            if(history.isEmpty())history.add(value);
        }
        public boolean fresh(long now){return !restored&&now-observedAt<=staleAfter(kind);}
        public String trend(long now){
            long stale=staleAfter(kind);
            if(now-observedAt>stale)return "Waiting for a fresh sample";
            if(samples<2)return "Need another sample for a trend";
            double change=average-previous;
            if(change>=3)return "Stronger signal";
            if(change<=-3)return "Weaker signal";
            return "Signal approximately steady";
        }
    }
    public static long staleAfter(String kind){return "BLE".equals(kind)?10000:90000;}
    public static String strengthLabel(int rssi){return rssi>=-55?"Very strong":rssi>=-67?"Strong":rssi>=-75?"Moderate":rssi>=-85?"Weak":"Very weak";}
    public static String wallAge(long now,long at){long seconds=Math.max(0,(now-at)/1000);if(at<=0)return "time unknown";if(seconds<60)return seconds+" s ago";if(seconds<3600)return (seconds/60)+" min ago";if(seconds<86400)return (seconds/3600)+" h ago";return (seconds/86400)+" d ago";}
    public static int strengthPercent(int rssi){return Math.max(0,Math.min(100,(rssi+100)*2));}
    public static String age(long now,long at){long seconds=Math.max(0,(now-at)/1000);return seconds<60?seconds+" s ago":(seconds/60)+" min ago";}
    public static float normalizeHeading(float heading){return ((heading%360)+360)%360;}
    public static String cardinal(float heading){return new String[]{"N","NE","E","SE","S","SW","W","NW"}[(int)Math.floor((normalizeHeading(heading)+22.5)/45)%8];}
}
