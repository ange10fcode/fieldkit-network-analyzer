package com.fieldkit.analyzer;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;

/** Small accessible labels that wrap at the measured card width and font scale. */
final class TagFlow extends ViewGroup {
    private final int gap;
    TagFlow(Context context){super(context);gap=Math.round(6*getResources().getDisplayMetrics().density);}
    @Override protected void onMeasure(int widthSpec,int heightSpec){
        int width=MeasureSpec.getSize(widthSpec);if(MeasureSpec.getMode(widthSpec)==MeasureSpec.UNSPECIFIED)width=Math.round(320*getResources().getDisplayMetrics().density);
        int available=Math.max(0,width-getPaddingLeft()-getPaddingRight()),x=0,y=0,line=0;
        for(int i=0;i<getChildCount();i++){View child=getChildAt(i);if(child.getVisibility()==GONE)continue;child.measure(MeasureSpec.makeMeasureSpec(available,MeasureSpec.AT_MOST),MeasureSpec.makeMeasureSpec(0,MeasureSpec.UNSPECIFIED));int cw=child.getMeasuredWidth(),ch=child.getMeasuredHeight();if(x>0&&x+cw>available){x=0;y+=line+gap;line=0;}x+=cw+gap;line=Math.max(line,ch);}
        setMeasuredDimension(resolveSize(width,widthSpec),resolveSize(y+line+getPaddingTop()+getPaddingBottom(),heightSpec));
    }
    @Override protected void onLayout(boolean changed,int left,int top,int right,int bottom){
        int available=right-left-getPaddingLeft()-getPaddingRight(),x=0,y=getPaddingTop(),line=0;
        for(int i=0;i<getChildCount();i++){View child=getChildAt(i);if(child.getVisibility()==GONE)continue;int cw=child.getMeasuredWidth(),ch=child.getMeasuredHeight();if(x>0&&x+cw>available){x=0;y+=line+gap;line=0;}child.layout(getPaddingLeft()+x,y,getPaddingLeft()+x+cw,y+ch);x+=cw+gap;line=Math.max(line,ch);}
    }
    @Override protected LayoutParams generateDefaultLayoutParams(){return new LayoutParams(LayoutParams.WRAP_CONTENT,LayoutParams.WRAP_CONTENT);}
}
