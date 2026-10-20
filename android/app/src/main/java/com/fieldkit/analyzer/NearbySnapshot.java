package com.fieldkit.analyzer;

import java.util.LinkedHashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** A bounded, last-seen radio inventory. Restoring never starts discovery. */
public final class NearbySnapshot {
    private NearbySnapshot(){}
    public static JSONObject save(Iterable<NearbySignal.Reading> readings,String mode,String selected,boolean feedback) throws JSONException {
        JSONObject root=new JSONObject().put("version",1).put("mode",mode).put("selected",selected).put("feedback",feedback);
        JSONArray entries=new JSONArray();int count=0;
        for(NearbySignal.Reading r:readings){
            if(r.samples<1||++count>256)continue;
            JSONArray samples=new JSONArray();for(int value:r.history())samples.put(value);
            entries.put(new JSONObject().put("key",r.key).put("kind",r.kind).put("address",r.address).put("name",r.name).put("detail",r.detail)
                    .put("rssi",r.rssi).put("samples",r.samples).put("wall",r.observedWall).put("average",r.average()).put("previous",r.previous())
                    .put("baseline",r.baseline()).put("history",samples));
        }
        return root.put("readings",entries);
    }
    public static LinkedHashMap<String,NearbySignal.Reading> restore(JSONObject root,long nowElapsed,long nowWall){
        LinkedHashMap<String,NearbySignal.Reading> out=new LinkedHashMap<>();
        if(root.optInt("version")!=1)return out;
        JSONArray entries=root.optJSONArray("readings");if(entries==null)return out;
        for(int i=0;i<Math.min(256,entries.length());i++){
            JSONObject entry=entries.optJSONObject(i);if(entry==null)continue;
            String key=entry.optString("key"),kind=entry.optString("kind"),address=entry.optString("address");
            int value=entry.optInt("rssi",127);long wall=entry.optLong("wall");
            if(key.isEmpty()||address.isEmpty()||(!"BLE".equals(kind)&&!"Wi-Fi".equals(kind))||value>0||value< -127||wall<=0)continue;
            NearbySignal.Reading reading=new NearbySignal.Reading(key,kind,address,entry.optString("name",address));reading.detail=entry.optString("detail");
            long age=Math.max(0,nowWall-wall),at=Math.max(1,nowElapsed-age);
            JSONArray history=entry.optJSONArray("history");int[] values=new int[history==null?0:Math.min(32,history.length())];
            for(int n=0;n<values.length;n++)values[n]=history.optInt(Math.max(0,history.length()-32)+n,value);
            double average=entry.optDouble("average",value),previous=entry.optDouble("previous",value);
            if(!Double.isFinite(average)||average>0||average< -127)average=value;
            if(!Double.isFinite(previous)||previous>0||previous< -127)previous=value;
            reading.restore(value,entry.optInt("samples",1),at,wall,average,previous,entry.optInt("baseline",value),values);out.put(key,reading);
        }
        return out;
    }
}
