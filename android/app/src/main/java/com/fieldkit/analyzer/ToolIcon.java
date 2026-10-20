package com.fieldkit.analyzer;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/** A consistent 24-unit icon family. Shapes are vectors, never font glyphs. */
public final class ToolIcon extends Drawable {
    private final String key;
    private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
    private final int size;
    public ToolIcon(String key,int color,float density){
        this.key=key==null?"network":key;
        this.size=Math.round(24*density);
        paint.setColor(color);paint.setStyle(Paint.Style.STROKE);paint.setStrokeWidth(1.8f);
        paint.setStrokeCap(Paint.Cap.ROUND);paint.setStrokeJoin(Paint.Join.ROUND);
    }
    @Override public int getIntrinsicWidth(){return size;}
    @Override public int getIntrinsicHeight(){return size;}
    @Override public void setAlpha(int alpha){paint.setAlpha(alpha);invalidateSelf();}
    @Override public void setColorFilter(ColorFilter filter){paint.setColorFilter(filter);invalidateSelf();}
    @Override public int getOpacity(){return PixelFormat.TRANSLUCENT;}
    private void line(Canvas c,float x,float y,float xx,float yy){c.drawLine(x,y,xx,yy,paint);}
    private void box(Canvas c,float l,float t,float r,float b){c.drawRoundRect(new RectF(l,t,r,b),1.2f,1.2f,paint);}
    private void dot(Canvas c,float x,float y,float radius){Paint.Style old=paint.getStyle();paint.setStyle(Paint.Style.FILL);c.drawCircle(x,y,radius,paint);paint.setStyle(old);}
    private void path(Canvas c,float... points){Path p=new Path();p.moveTo(points[0],points[1]);for(int i=2;i<points.length;i+=2)p.lineTo(points[i],points[i+1]);c.drawPath(p,paint);}
    @Override public void draw(Canvas canvas){
        Rect bounds=getBounds();if(bounds.isEmpty())return;
        int saved=canvas.save();float scale=Math.min(bounds.width(),bounds.height())/24f;
        canvas.translate(bounds.left+(bounds.width()-24*scale)/2,bounds.top+(bounds.height()-24*scale)/2);canvas.scale(scale,scale);
        Canvas c=canvas;
        switch(key){
            case "network":case "info":
                if(key.equals("info")){c.drawCircle(12,12,9,paint);dot(c,12,7,1);line(c,12,11,12,17);break;}
                box(c,4,3,20,21);line(c,7,7,17,7);dot(c,7,12,.7f);line(c,11,12,17,12);dot(c,7,17,.7f);line(c,11,17,17,17);break;
            case "wifi":case "signal":{
                Path p=new Path();p.moveTo(2.5f,8.5f);p.quadTo(12,1.1f,21.5f,8.5f);c.drawPath(p,paint);
                p.reset();p.moveTo(5.5f,12);p.quadTo(12,6.8f,18.5f,12);c.drawPath(p,paint);
                p.reset();p.moveTo(8.5f,15.5f);p.quadTo(12,12.6f,15.5f,15.5f);c.drawPath(p,paint);dot(c,12,19,1.2f);break;}
            case "lan":
                box(c,8,2.5f,16,8);box(c,2,16,9,21);box(c,15,16,22,21);path(c,12,8,12,12,5.5f,12,5.5f,16);path(c,12,12,18.5f,12,18.5f,16);break;
            case "nearby":
                c.drawCircle(12,12,9,paint);c.drawCircle(12,12,5.5f,paint);line(c,12,12,18.4f,5.6f);dot(c,12,12,1);dot(c,7.2f,15.8f,1);dot(c,15.2f,16.2f,1);break;
            case "precision":
                c.drawCircle(12,12,8,paint);path(c,8,12,12,6,16,12);line(c,12,6,12,17);line(c,2,12,5,12);line(c,19,12,22,12);break;
            case "tools":
                path(c,15,3,13,5,14,9,18,10,21,7);path(c,21,7,20,12,16,14,7,22,3,18,12,10,10,6,11,3,15,3);line(c,5,4,9,8);path(c,4,3,3,4,5,7,7,5,4,3);break;
            case "speed":
                c.drawArc(new RectF(3,4,21,22),150,240,false,paint);line(c,12,13,17,8);dot(c,12,13,1.2f);line(c,5,17,7,16);line(c,5,9,7,10);line(c,12,5,12,7);line(c,19,17,17,16);break;
            case "more":
                dot(c,5,12,1.6f);dot(c,12,12,1.6f);dot(c,19,12,1.6f);break;
            case "ping":
                path(c,2,13,6,13,9,5,13,20,16,10,18,13,22,13);break;
            case "trace":
                c.drawCircle(5,5,2.2f,paint);c.drawCircle(19,12,2.2f,paint);c.drawCircle(5,19,2.2f,paint);path(c,7.5f,5,13,5,13,12,16.5f,12);path(c,16.5f,12,11,12,11,19,7.5f,19);break;
            case "ports":
                box(c,3,3,21,9);box(c,3,15,21,21);dot(c,6,6,.7f);dot(c,6,18,.7f);line(c,11,6,18,6);line(c,11,18,18,18);line(c,12,9,12,15);break;
            case "dns":case "public":
                c.drawCircle(12,12,9,paint);c.drawOval(new RectF(8,3,16,21),paint);line(c,3.5f,9,20.5f,9);line(c,3.5f,15,20.5f,15);break;
            case "registration":
                box(c,4,3,20,21);c.drawCircle(9,9,2,paint);path(c,6,15,6,14,9,12.5f,12,14,12,15);line(c,15,8,18,8);line(c,15,12,18,12);line(c,7,18,17,18);break;
            case "mdns":
                c.drawCircle(12,12,2,paint);c.drawArc(new RectF(6,6,18,18),-60,120,false,paint);c.drawArc(new RectF(6,6,18,18),120,120,false,paint);c.drawArc(new RectF(2,2,22,22),-55,110,false,paint);c.drawArc(new RectF(2,2,22,22),125,110,false,paint);break;
            case "upnp":
                box(c,2,4,17,16);line(c,9.5f,16,9.5f,20);line(c,5.5f,20,13.5f,20);box(c,17,11,22,21);line(c,19.5f,18.5f,19.5f,18.5f);break;
            case "wol":
                c.drawArc(new RectF(4,4,20,20),-52,284,false,paint);line(c,12,2,12,12);break;
            case "history":
                c.drawArc(new RectF(4,3,22,21),-165,320,false,paint);path(c,2,5,4,9,8,7);path(c,13,7,13,12,16,14);break;
            case "favorites":case "star":{
                Path p=new Path();for(int i=0;i<10;i++){double angle=-Math.PI/2+i*Math.PI/5;double radius=i%2==0?9.4:4.5;float x=12+(float)(Math.cos(angle)*radius),y=12+(float)(Math.sin(angle)*radius);if(i==0)p.moveTo(x,y);else p.lineTo(x,y);}p.close();c.drawPath(p,paint);break;}
            case "settings":
                c.drawCircle(12,12,6.3f,paint);c.drawCircle(12,12,2.5f,paint);for(int i=0;i<8;i++){double a=i*Math.PI/4;line(c,12+(float)Math.cos(a)*6.3f,12+(float)Math.sin(a)*6.3f,12+(float)Math.cos(a)*9.2f,12+(float)Math.sin(a)*9.2f);}break;
            case "search":
                c.drawCircle(10.5f,10.5f,6.5f,paint);line(c,15.5f,15.5f,21,21);break;
            case "refresh":
                c.drawArc(new RectF(4,4,20,20),40,290,false,paint);path(c,20,4,20,9,15,9);break;
            case "play":{
                Path p=new Path();p.moveTo(7,4);p.lineTo(20,12);p.lineTo(7,20);p.close();paint.setStyle(Paint.Style.FILL);c.drawPath(p,paint);paint.setStyle(Paint.Style.STROKE);break;}
            case "stop":
                paint.setStyle(Paint.Style.FILL);box(c,5,5,19,19);paint.setStyle(Paint.Style.STROKE);break;
            case "options":
                line(c,5,3,5,6);line(c,5,11,5,21);line(c,12,3,12,13);line(c,12,18,12,21);line(c,19,3,19,7);line(c,19,12,19,21);box(c,2.5f,6,7.5f,11);box(c,9.5f,13,14.5f,18);box(c,16.5f,7,21.5f,12);break;
            case "back":
                path(c,14.5f,5,7.5f,12,14.5f,19);break;
            case "share":
                c.drawCircle(5,12,2.3f,paint);c.drawCircle(19,5,2.3f,paint);c.drawCircle(19,19,2.3f,paint);line(c,7.3f,11,16.7f,6);line(c,7.3f,13,16.7f,18);break;
            case "export":
                path(c,4,15,4,21,20,21,20,15);path(c,7,10,12,15,17,10);line(c,12,3,12,15);break;
            case "copy":
                box(c,8,7,21,21);path(c,16,4,16,2,2,2,2,16,5,16);break;
            case "check":
                path(c,4,12,9,17,20,6);break;
            default:
                c.drawCircle(12,12,9,paint);line(c,8,12,16,12);line(c,12,8,12,16);break;
        }
        canvas.restoreToCount(saved);
    }
}
