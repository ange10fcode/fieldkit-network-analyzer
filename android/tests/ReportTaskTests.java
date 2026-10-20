package com.fieldkit.analyzer;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.*;

/** Runs on the JVM with JSON-java; no Android framework stubs are executed. */
public final class ReportTaskTests {
    private static int assertions;
    static void check(boolean condition,String message){assertions++;if(!condition)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception {
        Report report=new Report("DNS lookup","example.com","Name","Value");
        report.add("example.com","a,\"b\"\nnext");report.note("Resolver timed out, retry available");
        report.detail="Raw\nreply";report.series("RTT",12.5);report.series("RTT",Double.NaN);
        JSONObject exported=report.json();
        check(exported.getInt("schemaVersion")==1,"versioned schema");
        check(exported.getJSONArray("rows").getJSONArray(0).getString(1).equals("a,\"b\"\nnext"),"JSON preserves raw text");
        Report restored=Report.from(new JSONObject(exported.toString()));
        check(restored.id.equals(report.id)&&restored.timestamp==report.timestamp,"stable identity and date");
        check(restored.text().equals(report.text()),"history round trip");
        check(Double.isNaN(restored.series.get("RTT").get(1)),"failed probe graph points survive serialization");
        check(report.csv().startsWith("report_id,timestamp,title,target,row_type,\"Name\",\"Value\",notes\r\n"),"CSV headers");
        check(report.csv().contains("\"a,\"\"b\"\"\nnext\""),"CSV escapes multiline quote/comma fields");
        int columns=8; // fixed metadata 5 + result fields 2 + notes 1
        for(List<String> row:parseCsv(report.csv()))check(row.size()==columns,"CSV consistent column count");
        AtomicInteger emissions=new AtomicInteger(),closed=new AtomicInteger();
        Task task=new Task(r->emissions.incrementAndGet());
        task.register(()->closed.incrementAndGet());task.emit(report);task.cancel();task.cancel();task.emit(report);
        check(emissions.get()==1,"cancelled tasks cannot emit");check(closed.get()==1,"resources close exactly once");
        task.register(()->closed.incrementAndGet());check(closed.get()==2,"late resource registration closes immediately");
        boolean stopped=false;try{task.check();}catch(InterruptedException e){stopped=true;}check(stopped,"cancellation check interrupts work");
        Task socketTask=new Task(null);DatagramSocket socket=new DatagramSocket();socketTask.register(socket);socketTask.cancel();check(socket.isClosed(),"cancel closes live UDP socket");
        Task sleeper=new Task(null);Thread thread=new Thread(()->{try{sleeper.sleep(30000);throw new AssertionError("sleep completed");}catch(InterruptedException expected){}});
        thread.start();Thread.sleep(30);sleeper.cancel();thread.join(1000);check(!thread.isAlive(),"sleep responds promptly to cancellation");
        Report many=new Report("bounded graph","test","x");for(int i=0;i<4000;i++)many.series("x",i);check(many.series.get("x").size()==3600,"continuous graph bounded in memory");
        System.out.println("ReportTaskTests: "+assertions+" assertions passed");
    }
    private static List<List<String>> parseCsv(String csv){
        List<List<String>> rows=new ArrayList<>();List<String> row=new ArrayList<>();StringBuilder field=new StringBuilder();boolean quote=false;
        for(int i=0;i<csv.length();i++){char c=csv.charAt(i);if(c=='\"'){if(quote&&i+1<csv.length()&&csv.charAt(i+1)=='\"'){field.append(c);i++;}else quote=!quote;}
            else if(c==','&&!quote){row.add(field.toString());field.setLength(0);}else if(c=='\n'&&!quote){row.add(field.toString());rows.add(row);row=new ArrayList<>();field.setLength(0);}else if(c!='\r'||quote)field.append(c);}
        return rows;
    }
}
