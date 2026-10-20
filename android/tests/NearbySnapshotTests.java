package com.fieldkit.analyzer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import org.json.JSONArray;
import org.json.JSONObject;

public final class NearbySnapshotTests {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    public static void main(String[] args) throws Exception {
        NearbySignal.Reading ble=new NearbySignal.Reading("ble:00:11","BLE","00:11","Workshop sensor");
        ble.detail="BLE advertisement";
        check(ble.update(-90,1000,100000),"First sample accepted with wall time");
        check(ble.baseline()==-90,"First sample becomes baseline");
        ble.update(-60,2000,101000);
        check(ble.baselineChange()==12,"Trend compares smoothed RSSI to starting baseline");
        ble.resetBaseline();check(ble.baselineChange()==0,"Reset baseline uses current smoothed RSSI");
        check(!ble.update(-50,3000,101000),"Duplicate wall timestamp rejected");
        check(!ble.update(-50,2000,102000),"Duplicate elapsed timestamp rejected");
        ble.update(-70,3000,102000);
        JSONObject saved=NearbySnapshot.save(Arrays.asList(ble),"Bluetooth LE",ble.key,true);
        check(saved.getString("selected").equals(ble.key),"Selected target retained");
        check(saved.getString("mode").equals("Bluetooth LE"),"Mode retained");
        check(saved.getBoolean("feedback"),"Explicit feedback preference retained");
        LinkedHashMap<String,NearbySignal.Reading> loaded=NearbySnapshot.restore(new JSONObject(saved.toString()),10000,103000);
        check(loaded.size()==1,"Radio inventory round trip");
        NearbySignal.Reading copy=loaded.get(ble.key);
        check(copy.name.equals(ble.name)&&copy.detail.equals(ble.detail),"Advertised identity retained");
        check(copy.rssi==ble.rssi&&copy.samples==3,"Measurement and sample count retained");
        check(copy.baseline()==ble.baseline()&&copy.smoothed()==ble.smoothed(),"Baseline and smoothing retained");
        check(Arrays.equals(copy.history(),ble.history()),"Real sample history retained");
        check(copy.observedWall==102000,"Wall clock retained independent of process lifetime");
        check(copy.restored&&!copy.fresh(10000),"Restored sample cannot pretend to be live");
        check(copy.observedAt==9000,"Elapsed time remapped from wall age");
        check(NearbySignal.wallAge(103000,copy.observedWall).equals("1 s ago"),"Last-seen age survives restart");
        NearbySignal.Reading rebooted=NearbySnapshot.restore(saved,2000,3702000).get(ble.key);
        check(rebooted.observedAt==1,"Prior-boot timestamp bounded");
        check(rebooted.restored&&!rebooted.fresh(2000),"Prior-boot sample remains historical");
        check(NearbySignal.wallAge(3702000,rebooted.observedWall).equals("1 h ago"),"Prior-boot age uses wall clock");
        check(rebooted.update(-40,2500,3702500),"New reading accepted after reboot");
        check(!rebooted.restored&&rebooted.fresh(2501),"Only new actual sample enables live status");
        check(!rebooted.update(-30,3000,3702500),"Cached result not counted twice after restart");
        check(!rebooted.fresh(12501),"BLE live status expires");
        for(int i=1;i<=40;i++)ble.update(-100+i,3000+i,102000+i);
        check(ble.history().length==32,"History has bounded memory");
        check(ble.history()[0]==-91&&ble.history()[31]==-60,"History keeps latest real samples in order");
        int[] defensive=ble.history();defensive[0]=0;check(ble.history()[0]==-91,"History caller cannot corrupt readings");
        check(NearbySnapshot.restore(new JSONObject().put("version",99),1000,1000).isEmpty(),"Unknown snapshot format ignored");
        JSONObject invalid=new JSONObject(saved.toString());invalid.getJSONArray("readings").getJSONObject(0).put("rssi",127);
        check(NearbySnapshot.restore(invalid,10000,103000).isEmpty(),"Invalid RSSI not restored");
        JSONObject noWall=new JSONObject(saved.toString());noWall.getJSONArray("readings").getJSONObject(0).put("wall",0);
        check(NearbySnapshot.restore(noWall,10000,103000).isEmpty(),"Unknown observation time not represented as current");
        JSONObject corrupt=new JSONObject(saved.toString());corrupt.getJSONArray("readings").getJSONObject(0).put("kind","Unknown");
        check(NearbySnapshot.restore(corrupt,10000,103000).isEmpty(),"Unknown radio kind ignored");
        ArrayList<NearbySignal.Reading> many=new ArrayList<>();for(int i=0;i<300;i++){NearbySignal.Reading r=new NearbySignal.Reading("wifi:"+i,"Wi-Fi","address"+i,"AP "+i);r.update(-60,1000,1000);many.add(r);}
        JSONObject bounded=NearbySnapshot.save(many,"Wi-Fi","",false);check(bounded.getJSONArray("readings").length()==256,"Snapshot bounded to 256 actual observations");
        JSONArray over=bounded.getJSONArray("readings");for(int i=0;i<50;i++)over.put(over.getJSONObject(0));check(NearbySnapshot.restore(bounded,2000,2000).size()==256,"Restore bounds untrusted stored inventory");
        check(NearbySignal.wallAge(999999,0).equals("time unknown"),"Unknown wall clock stated honestly");
        check(NearbySignal.wallAge(90000000,1000).equals("1 d ago"),"Long saved age readable");
        check(NearbySignal.strengthLabel(-50).equals("Very strong")&&NearbySignal.strengthLabel(-90).equals("Very weak"),"Human-readable RSSI labels");
        System.out.println("NearbySnapshotTests: "+checks+" checks passed");
    }
}
