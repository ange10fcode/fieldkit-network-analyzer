package com.fieldkit.analyzer;

import android.content.*;
import android.database.Cursor;
import android.database.sqlite.*;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import org.json.*;
import java.util.*;

/** Private SQLite storage; no account, cloud sync, or analytics. */
public final class Store extends SQLiteOpenHelper {
    public final SharedPreferences prefs;
    private final File retainedDir;
    public Store(Context c){super(c,"fieldkit.db",null,1);prefs=c.getSharedPreferences("fieldkit",Context.MODE_PRIVATE);retainedDir=new File(c.getFilesDir(),"retained-results");}
    @Override public void onCreate(SQLiteDatabase db){
        db.execSQL("CREATE TABLE reports(id TEXT PRIMARY KEY,stamp INTEGER NOT NULL,body TEXT NOT NULL)");
        db.execSQL("CREATE TABLE favorites(id TEXT PRIMARY KEY,body TEXT NOT NULL)");
        db.execSQL("CREATE TABLE labels(target TEXT PRIMARY KEY,label TEXT NOT NULL)");
    }
    @Override public void onUpgrade(SQLiteDatabase db,int oldVersion,int newVersion){}
    public synchronized void save(Report report){ContentValues v=new ContentValues();v.put("id",report.id);v.put("stamp",report.timestamp);v.put("body",report.json().toString());getWritableDatabase().insertWithOnConflict("reports",null,v,SQLiteDatabase.CONFLICT_REPLACE);getWritableDatabase().execSQL("DELETE FROM reports WHERE id NOT IN (SELECT id FROM reports ORDER BY stamp DESC LIMIT 500)");}
    public synchronized List<Report> history(){List<Report> out=new ArrayList<>();try(Cursor c=getReadableDatabase().rawQuery("SELECT body FROM reports ORDER BY stamp DESC",null)){while(c.moveToNext())try{out.add(Report.from(new JSONObject(c.getString(0))));}catch(JSONException ignored){}}return out;}
    /** One older history record for upgrading the retained tool views; call off the UI thread. */
    public synchronized Report latestResult(String kind){
        if(prefs.getBoolean("retained_history_disabled",false))return null;
        String title=kind.equals("lan")?"LAN scan":kind.equals("wifi")?"Wi-Fi analyzer":kind.equals("signal")?"Wi-Fi signal monitor":"";
        if(title.isEmpty())return null;
        try(Cursor c=getReadableDatabase().query("reports",new String[]{"body"},"body LIKE ?",new String[]{"%\"title\":\""+title+"\"%"},null,null,"stamp DESC","1")){
            if(c.moveToFirst())try{return Report.from(new JSONObject(c.getString(0)));}catch(JSONException invalid){return null;}
        }catch(SQLiteException unreadable){return null;}
        return null;
    }
    public synchronized void delete(String id){getWritableDatabase().delete("reports","id=?",new String[]{id});}
    public synchronized void clearHistory(){getWritableDatabase().delete("reports",null,null);}
    public synchronized void favorite(String name,String target,String kind,String extra){
        String id=kind+":"+target+":"+extra;
        try{JSONObject o=new JSONObject().put("id",id).put("name",name).put("target",target).put("kind",kind).put("extra",extra);
            ContentValues v=new ContentValues();v.put("id",id);v.put("body",o.toString());getWritableDatabase().insertWithOnConflict("favorites",null,v,SQLiteDatabase.CONFLICT_REPLACE);
        }catch(JSONException e){throw new IllegalArgumentException(e);}
    }
    public synchronized List<JSONObject> favorites(){List<JSONObject> out=new ArrayList<>();try(Cursor c=getReadableDatabase().rawQuery("SELECT body FROM favorites ORDER BY rowid DESC",null)){while(c.moveToNext())try{out.add(new JSONObject(c.getString(0)));}catch(JSONException ignored){}}return out;}
    public synchronized void removeFavorite(String id){getWritableDatabase().delete("favorites","id=?",new String[]{id});}
    public synchronized void clearFavorites(){getWritableDatabase().delete("favorites",null,null);}
    public synchronized void label(String target,String label){ContentValues v=new ContentValues();v.put("target",target);v.put("label",label);getWritableDatabase().insertWithOnConflict("labels",null,v,SQLiteDatabase.CONFLICT_REPLACE);}
    public synchronized String label(String target){try(Cursor c=getReadableDatabase().rawQuery("SELECT label FROM labels WHERE target=?",new String[]{target})){return c.moveToFirst()?c.getString(0):"";}}
    /** Independent of history pruning: reopening a tool restores its last actual result. */
    public synchronized void snapshot(String key,Report report,JSONObject cfg){
        snapshot(key,report,cfg,System.currentTimeMillis());
    }
    public synchronized void snapshot(String key,Report report,JSONObject cfg,long savedAt){
        if(report==null)return;
        writeRetained(SnapshotDocument.slot(key),SnapshotDocument.create(report,cfg,savedAt).toString());
    }
    public synchronized JSONObject snapshot(String key){return SnapshotDocument.read(readRetained(SnapshotDocument.slot(key)));}
    /** Explicit user action only; ordinary Back, navigation and history pruning keep these views. */
    public synchronized void clearSnapshots(){
        for(String key:new String[]{"lan","wifi","signal"})new AtomicFile(new File(retainedDir,key+".json")).delete();
        prefs.edit().putBoolean("retained_history_disabled",true).apply();
    }
    public synchronized void uiState(JSONObject state){
        if(state==null)return;
        writeRetained("screen",state.toString());
    }
    public synchronized JSONObject uiState(){try{return new JSONObject(readRetained("screen"));}catch(Exception invalid){return new JSONObject();}}
    private void writeRetained(String key,String text){
        if(!retainedDir.isDirectory()&&!retainedDir.mkdirs())return;
        AtomicFile file=new AtomicFile(new File(retainedDir,key+".json"));FileOutputStream output=null;
        try{output=file.startWrite();output.write(text.getBytes(StandardCharsets.UTF_8));file.finishWrite(output);}
        catch(IOException failure){if(output!=null)file.failWrite(output);}
    }
    private String readRetained(String key){
        AtomicFile file=new AtomicFile(new File(retainedDir,key+".json"));
        try(InputStream input=file.openRead();ByteArrayOutputStream bytes=new ByteArrayOutputStream()){
            byte[] block=new byte[8192];int count;while((count=input.read(block))!=-1)bytes.write(block,0,count);
            return new String(bytes.toByteArray(),StandardCharsets.UTF_8);
        }catch(IOException failure){return "";}
    }
}
