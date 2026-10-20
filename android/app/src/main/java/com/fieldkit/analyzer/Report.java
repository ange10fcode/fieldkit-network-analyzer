package com.fieldkit.analyzer;

import org.json.*;
import java.util.*;

/** A diagnostic snapshot, with a stable local identity and export schema. */
public final class Report {
    public final String id, title, target;
    public long timestamp;
    public final String[] columns;
    public final List<List<String>> rows = new ArrayList<>();
    public final List<String> notes = new ArrayList<>();
    public final Map<String,List<Double>> series = new LinkedHashMap<>();
    public String detail = "";
    public Report(String title, String target, String... columns) {
        this(UUID.randomUUID().toString(), System.currentTimeMillis(), title, target, columns);
    }
    private Report(String id,long timestamp,String title,String target,String[] columns) {
        this.id=id;this.timestamp=timestamp;this.title=title;this.target=target;this.columns=columns;
    }
    public synchronized void add(String... cells) { rows.add(Arrays.asList(cells.clone())); }
    public synchronized void note(String text) { if(text!=null&&!text.isEmpty()) notes.add(text); }
    public synchronized void series(String name,double value) {
        if(!series.containsKey(name)) series.put(name,new ArrayList<>());
        List<Double> points=series.get(name); points.add(value);
        if(points.size()>3600) points.remove(0);
    }
    public synchronized JSONObject json() {
        JSONObject o=new JSONObject();
        try {
            o.put("schemaVersion",1).put("id",id).put("timestamp",timestamp)
                .put("title",title).put("target",target).put("columns",new JSONArray(Arrays.asList(columns)));
            JSONArray data=new JSONArray();for(List<String> row:rows) data.put(new JSONArray(row));
            o.put("rows",data).put("notes",new JSONArray(notes)).put("detail",detail);
            JSONObject points=new JSONObject();for(Map.Entry<String,List<Double>> e:series.entrySet()) {
                JSONArray a=new JSONArray();for(Double d:e.getValue()) a.put(d==null||Double.isNaN(d)||Double.isInfinite(d)?JSONObject.NULL:d);
                points.put(e.getKey(),a);
            }o.put("series",points);
        } catch(JSONException e) { throw new IllegalStateException(e); } return o;
    }
    public static Report from(JSONObject o) {
        JSONArray c=o.optJSONArray("columns");String[] columns=new String[c==null?0:c.length()];
        for(int i=0;i<columns.length;i++)columns[i]=c.optString(i);
        Report r=new Report(o.optString("id",UUID.randomUUID().toString()),o.optLong("timestamp",System.currentTimeMillis()),o.optString("title"),o.optString("target"),columns);
        JSONArray rows=o.optJSONArray("rows");if(rows!=null)for(int i=0;i<rows.length();i++) {
            JSONArray row=rows.optJSONArray(i);if(row==null)continue;
            String[] cells=new String[row.length()];for(int j=0;j<cells.length;j++)cells[j]=row.optString(j);r.add(cells);
        }
        JSONArray notes=o.optJSONArray("notes");if(notes!=null)for(int i=0;i<notes.length();i++)r.note(notes.optString(i));
        r.detail=o.optString("detail","");JSONObject series=o.optJSONObject("series");
        if(series!=null)for(Iterator<String> it=series.keys();it.hasNext();) {String key=it.next();JSONArray a=series.optJSONArray(key);
            if(a!=null)for(int i=0;i<a.length();i++)r.series(key,a.isNull(i)?Double.NaN:a.optDouble(i));}
        return r;
    }
    public synchronized String text() {
        StringBuilder s=new StringBuilder(title).append("\nTarget: ").append(target)
            .append("\nTime: ").append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z",Locale.US).format(new Date(timestamp))).append("\n\n");
        s.append(String.join(" | ",columns)).append('\n');
        for(List<String> row:rows)s.append(String.join(" | ",row)).append('\n');
        for(String n:notes)s.append("\n").append(n).append('\n');
        if(detail!=null&&!detail.isEmpty())s.append("\n").append(detail).append('\n');return s.toString();
    }
    private static String cell(String value) { return "\""+(value==null?"":value).replace("\"","\"\"")+"\""; }
    public synchronized String csv() {
        // One consistent record layout includes metadata and ancillary result notes.
        StringBuilder s=new StringBuilder("report_id,timestamp,title,target,row_type");
        for(String c:columns)s.append(',').append(cell(c));s.append(",notes\r\n");
        String meta=cell(id)+","+timestamp+","+cell(title)+","+cell(target)+",";
        for(List<String> row:rows){s.append(meta).append("data");for(int i=0;i<columns.length;i++)s.append(',').append(cell(i<row.size()?row.get(i):""));s.append(",\r\n");}
        List<String> extra=new ArrayList<>(notes);if(detail!=null&&!detail.isEmpty())extra.add(detail);
        for(String n:extra){s.append(meta).append("note");for(int i=0;i<columns.length;i++)s.append(',');s.append(',').append(cell(n)).append("\r\n");}
        return s.toString();
    }
}
