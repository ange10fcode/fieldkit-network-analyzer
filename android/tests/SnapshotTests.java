package com.fieldkit.analyzer;

import org.json.JSONObject;

public final class SnapshotTests {
    private static int checks;
    private static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception{
        Report lan=new Report("LAN scan","192.168.4.0/24","IP address","Name");
        lan.add("192.168.4.2","Workstation");lan.note("Names observed on the local network.");
        JSONObject cfg=new JSONObject().put("lan_mode","CIDR").put("lan_cidr","192.168.4.0/24").put("lan_route","Android routing");
        JSONObject saved=SnapshotDocument.create(lan,cfg,1000);
        cfg.put("lan_cidr","10.0.0.0/24");lan.add("192.168.4.3","Another device");
        JSONObject reopened=SnapshotDocument.read(saved.toString());
        Report result=Report.from(reopened.getJSONObject("report"));
        check(result.rows.size()==1,"saved report is a snapshot rather than a mutable live alias");
        check(reopened.getJSONObject("cfg").getString("lan_cidr").equals("192.168.4.0/24"),"manual scan parameters retained independently");
        check(result.timestamp==lan.timestamp&&result.id.equals(lan.id),"original observation identity and date preserved");
        check(reopened.getLong("savedAt")==1000,"saved timestamp not substituted for observation timestamp");
        Report signal=new Report("Wi-Fi signal monitor","Connected Wi-Fi","Time","RSSI");
        signal.series("RSSI",-61);signal.series("RSSI",Double.NaN);signal.series("Elapsed seconds",0);signal.series("Elapsed seconds",3);
        Report chart=Report.from(SnapshotDocument.read(SnapshotDocument.create(signal,new JSONObject(),2000).toString()).getJSONObject("report"));
        check(chart.series.get("RSSI").size()==2&&Double.isNaN(chart.series.get("RSSI").get(1)),"signal values and unavailable gaps persist");
        check(chart.series.get("Elapsed seconds").get(1)==3,"signal chart time axis persists");
        Report empty=new Report("LAN scan","192.168.4.1","IP");empty.note("No hosts replied.");
        check(Report.from(SnapshotDocument.read(SnapshotDocument.create(empty,null,3000).toString()).getJSONObject("report")).rows.isEmpty(),"actual empty result retained rather than replaced with demo data");
        check(SnapshotDocument.read("broken").length()==0,"corrupt retained JSON safely ignored");
        check(SnapshotDocument.read("{\"snapshotVersion\":2,\"savedAt\":1,\"report\":{}}").length()==0,"unsupported snapshot ignored");
        check(SnapshotDocument.read("{\"snapshotVersion\":1,\"savedAt\":1,\"report\":{}}").length()==0,"invalid report shape ignored");
        check(SnapshotDocument.slot("lan").equals("lan"),"expected slot accepted");
        boolean traversal=false;try{SnapshotDocument.slot("../other");}catch(IllegalArgumentException expected){traversal=true;}
        check(traversal,"snapshot keys cannot escape private result directory");
        System.out.println("SnapshotTests: "+checks+" checks passed (retained results, configurations, timestamps and signal charts).");
    }
}
