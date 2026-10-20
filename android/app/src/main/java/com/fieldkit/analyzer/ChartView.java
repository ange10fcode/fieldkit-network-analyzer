package com.fieldkit.analyzer;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.view.MotionEvent;
import android.view.View;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.IntConsumer;

/** Small, dependency-free chart. Every plotted point comes from a diagnostic report. */
public final class ChartView extends View {
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Map<String, List<Double>> series = new LinkedHashMap<>();
    private final List<Double> elapsed=new ArrayList<>();
    private final List<List<String>> networks = new ArrayList<>();
    private final int[] palette = {0xff1766cb,0xff00a78f,0xffd28a19,0xff9860cf,0xffd66554,0xff73923e};
    private int foreground=0xff202124,mutedColor=0xff626975,gridColor=0xffdfe3e8;
    private boolean dark, wifi;
    private int band = 0, selected = -1;
    private String title = "", unit = "";
    private IntConsumer selectedListener;

    public ChartView(Context context) {
        super(context);
        setMinimumHeight(dp(240));
        setFocusable(true);
        setClickable(true);
        setContentDescription("Diagnostic chart. No samples yet.");
    }
    private int dp(float n) { return (int)(n * getResources().getDisplayMetrics().density + .5f); }
    public void colors(boolean dark) {
        this.dark = dark;
        ThemePalette theme=ThemePalette.load(getContext(),getContext().getSharedPreferences("fieldkit",Context.MODE_PRIVATE));
        foreground=theme.foreground;mutedColor=theme.muted;gridColor=theme.border;palette[0]=theme.accent;
        invalidate();
    }
    public void setLines(Map<String,List<Double>> values, String title, String unit) {
        wifi = false; this.title = title; this.unit = unit; series.clear();elapsed.clear();
        for (Map.Entry<String,List<Double>> e : values.entrySet()) {if(e.getKey().equals("Elapsed seconds"))elapsed.addAll(e.getValue());else series.put(e.getKey(),new ArrayList<>(e.getValue()));}
        setContentDescription(title + ". " + series.size() + " series. Latest values " + latest());
        invalidate();
    }
    public void setWifi(List<List<String>> rows, int band, IntConsumer listener) {
        wifi = true; this.band = band; this.title = "Channel occupancy · " + new String[]{"2.4 GHz","5 GHz","6 GHz"}[band];
        selectedListener = listener; networks.clear();
        for (List<String> r : rows) networks.add(new ArrayList<>(r));
        setContentDescription(title + ". " + rows.size() + " observed access points. Tap a curve to inspect its network.");
        invalidate();
    }
    private String latest() {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String,List<Double>> e : series.entrySet()) {
            if(!e.getValue().isEmpty()) {
                Double last=e.getValue().get(e.getValue().size()-1);
                String label=e.getKey().replace(" ms","").replace(" Mbps","");
                out.append(label).append(": ");
                if(last==null||!Double.isFinite(last))out.append("no reply");
                else out.append(String.format(Locale.US,"%.1f",last)).append(' ').append(unit);
                out.append("  ");
            }
        }
        return out.toString();
    }
    private float number(String n, float fallback) {
        try { return Float.parseFloat(n.replaceAll("[^0-9.\\-]", "")); } catch(Exception ignored) { return fallback; }
    }
    private void text(Canvas c,String s,float x,float y,int color,float size) {
        paint.setColor(color); paint.setStyle(Paint.Style.FILL); paint.setTextSize(dp(size)); c.drawText(s,x,y,paint);
    }
    private String fit(String value,float width,float size){
        paint.setTextSize(dp(size));if(paint.measureText(value)<=width)return value;
        int end=value.length();while(end>0&&paint.measureText(value.substring(0,end)+"…")>width)end--;
        return end==0?"":value.substring(0,end)+"…";
    }
    @Override protected void onDraw(Canvas c) {
        super.onDraw(c);
        int fg = foreground, muted=mutedColor;
        float l=dp(43), r=getWidth()-dp(18), t=dp(49), b=getHeight()-dp(43);
        text(c,fit(title,getWidth()-dp(24),13),dp(12),dp(23),fg,13);
        double min=0,max=1; int count=0;
        if(wifi) { min=-100; max=-20; }
        else {
            boolean found=false;
            for(List<Double> vals:series.values()) for(Double v:vals) if(v!=null && Double.isFinite(v) && v>=-150) {
                if(!found) {min=v;max=v;found=true;} else {min=Math.min(min,v);max=Math.max(max,v);}
            }
            for(List<Double> vals:series.values()) count=Math.max(count,vals.size());
            if(unit.equals("dBm")){min=Math.min(-100,Math.floor(min/10)*10);max=Math.max(-20,Math.ceil(max/10)*10);}
            else min=0;
            if(max-min<1) {max+=1;min-=unit.equals("dBm")?1:0;}
            if(!unit.equals("dBm"))max += (max-min)*.1;
        }
        paint.setStrokeWidth(dp(1));
        for(int i=0;i<=4;i++) {
            float y=b-(b-t)*i/4;
            paint.setColor(gridColor);paint.setAlpha(130);c.drawLine(l,y,r,y,paint);paint.setAlpha(255);
            String tickFormat=max-min<2?"%.2f":max-min<10?"%.1f":"%.0f";
            text(c,String.format(Locale.US,tickFormat,min+(max-min)*i/4),dp(4),y+dp(4),muted,10);
        }
        if(wifi) {
            float low=band==0?2400:band==1?5150:5925, high=band==0?2500:band==1?5895:7125;
            int drawn=0;
            for(int i=0;i<networks.size();i++) {
                List<String> n=networks.get(i); if(n.size()<6) continue;
                float freq=number(n.get(3),0), strength=number(n.get(2),-100), width=number(n.get(5),20);
                if(freq<low||freq>high)continue;
                width=Math.max(20,Math.min(320,width));
                float center=l+(freq-low)/(high-low)*(r-l), half=width/2/(high-low)*(r-l), top=b-(Math.max(-100,Math.min(-20,strength))+100)/80*(b-t);
                Path p=new Path();p.moveTo(Math.max(l,center-half),b);
                for(int j=0;j<=30;j++) {
                    float x=center-half+2*half*j/30;
                    float relative=(x-center)/half;
                    float y=b-(b-top)*(1-relative*relative);
                    p.lineTo(Math.max(l,Math.min(r,x)),y);
                }
                p.lineTo(Math.min(r,center+half),b);p.close();
                int col=palette[i%palette.length];paint.setStyle(Paint.Style.FILL);paint.setColor((col&0xffffff)|(selected==i?0x70000000:0x28000000));c.drawPath(p,paint);
                paint.setStyle(Paint.Style.STROKE);paint.setColor(col);paint.setStrokeWidth(dp(selected==i?3:1.6f));c.drawPath(p,paint);
                paint.setStyle(Paint.Style.FILL);
                if(selected==i||drawn<5)text(c,truncate(n.get(0),15),Math.max(l,Math.min(r-dp(90),center-half)),Math.max(t+dp(12),top-dp(5)),col,10);
                drawn++;
            }
            int[] ticks=band==0?new int[]{1,6,11,14}:band==1?new int[]{36,64,100,132,165}:new int[]{1,65,129,193,233};
            for(int ch:ticks) {
                float freq=band==0?(ch==14?2484:2407+5*ch):band==1?5000+5*ch:5950+5*ch;
                text(c,String.valueOf(ch),l+(freq-low)/(high-low)*(r-l)-dp(6),b+dp(19),muted,10);
            }
            if(drawn==0)text(c,"No access points in this band",l+dp(10),t+dp(45),muted,12);
            text(c,"Channel · approximate occupancy / dBm",l,getHeight()-dp(7),muted,10);
        } else {
            int si=0;
            for(Map.Entry<String,List<Double>> e:series.entrySet()) {
                List<Double> vals=e.getValue();Path p=new Path();boolean started=false;
                int col=palette[si++%palette.length];
                for(int i=0;i<vals.size();i++) {
                    Double v=vals.get(i);
                    double elapsedMax=elapsed.isEmpty()?0:elapsed.get(elapsed.size()-1),elapsedMin=elapsed.isEmpty()?0:elapsed.get(0);
                    float x=elapsed.size()==vals.size()&&elapsedMax>elapsedMin?l+(r-l)*(float)((elapsed.get(i)-elapsedMin)/(elapsedMax-elapsedMin)):l+(r-l)*i/Math.max(1,count-1);
                    if(v==null||!Double.isFinite(v)||v<-150) {
                        started=false;paint.setColor(0xffe67668);paint.setStrokeWidth(dp(2));c.drawLine(x-dp(3),b-dp(3),x+dp(3),b+dp(3),paint);c.drawLine(x-dp(3),b+dp(3),x+dp(3),b-dp(3),paint);continue;
                    }
                    float y=(float)(b-(v-min)/(max-min)*(b-t));
                    if(started)p.lineTo(x,y);else p.moveTo(x,y);started=true;
                    paint.setStyle(Paint.Style.FILL);paint.setColor(col);c.drawCircle(x,y,dp(2),paint);
                }
                paint.setStyle(Paint.Style.STROKE);paint.setColor(col);paint.setStrokeWidth(dp(2));c.drawPath(p,paint);paint.setStyle(Paint.Style.FILL);
            }
            if(count==0)text(c,"Start to collect measurements",l+dp(8),t+dp(30),muted,12);
            text(c,elapsed.isEmpty()?"Sample 1":String.format(Locale.US,"%.1f s",elapsed.get(0)),l,b+dp(20),muted,10);
            text(c,elapsed.isEmpty()?""+count:String.format(Locale.US,"%.1f s",elapsed.get(elapsed.size()-1)),r-dp(elapsed.isEmpty()?20:55),b+dp(20),muted,10);
            int legendIndex=0;float legendX=l;
            for(Map.Entry<String,List<Double>> entry:series.entrySet()){
                if(legendIndex>=3)break;int color=palette[legendIndex%palette.length];String label=entry.getKey();
                List<Double> values=entry.getValue();Double last=values.isEmpty()?null:values.get(values.size()-1);
                label=label.replace(" ms","").replace(" Mbps","");
                if(last!=null&&Double.isFinite(last))label+=" "+String.format(Locale.US,unit.equals("dBm")?"%.0f":"%.1f",last)+" "+unit;
                else label+=" unavailable";
                float share=(r-l)/Math.min(3,Math.max(1,series.size()));String fitted=fit(label,share-dp(18),10);
                paint.setStyle(Paint.Style.FILL);paint.setColor(color);c.drawCircle(legendX+dp(3),getHeight()-dp(10),dp(3),paint);
                text(c,fitted,legendX+dp(12),getHeight()-dp(7),muted,10);legendX+=share;legendIndex++;
            }
        }
    }
    private static String truncate(String s,int n) {return s.length()>n?s.substring(0,n-1)+"…":s;}
    @Override public boolean onTouchEvent(MotionEvent e) {
        if(e.getAction()==MotionEvent.ACTION_UP) {
            performClick();
            if(wifi&&!networks.isEmpty()) {
                float low=band==0?2400:band==1?5150:5925, high=band==0?2500:band==1?5895:7125;
                float at=low+(e.getX()-dp(43))/(getWidth()-dp(61))*(high-low), best=Float.MAX_VALUE;int idx=-1;
                for(int i=0;i<networks.size();i++)if(networks.get(i).size()>3) {
                    float f=number(networks.get(i).get(3),0),d=Math.abs(f-at);if(f>=low&&f<=high&&d<best){best=d;idx=i;}
                }
                selected=idx;invalidate();if(idx>=0&&selectedListener!=null)selectedListener.accept(idx);
            }
            return true;
        }
        return true;
    }
    @Override public boolean performClick() {return super.performClick();}
}
