package com.fieldkit.analyzer;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;

/** One palette for screens, controls, charts, and system bars. */
public final class ThemePalette {
    public static final String[] MODES={"System","Light","Dark","AMOLED"};
    public static final String[] ACCENTS={"Blue","Teal","Amber","Violet"};
    public final int background,surface,foreground,muted,accent,border,toolbar;
    public final boolean dark;
    private ThemePalette(boolean dark,boolean black,String color){
        this.dark=dark;
        background=black?0xff000000:dark?0xff17191d:0xfff4f5f7;
        surface=black?0xff08090b:dark?0xff202227:0xffffffff;
        toolbar=black?0xff08090b:dark?0xff25282e:0xffffffff;
        foreground=dark?0xffe8eaed:0xff202124;
        muted=dark?0xffa8aeb8:0xff626975;
        border=black?0xff282b31:dark?0xff363a42:0xffdfe3e8;
        if("Teal".equals(color))accent=dark?0xff53d6bd:0xff007f70;
        else if("Amber".equals(color))accent=dark?0xffffc15a:0xff8c5700;
        else if("Violet".equals(color))accent=dark?0xffc4a5ff:0xff7040b5;
        else accent=dark?0xff8ab4f8:0xff1766cb;
    }
    public static boolean isDark(Context context,SharedPreferences preferences){
        String mode=preferences.getString("theme","System");
        return "Dark".equals(mode)||"AMOLED".equals(mode)||("System".equals(mode)&&
                (context.getResources().getConfiguration().uiMode&Configuration.UI_MODE_NIGHT_MASK)==Configuration.UI_MODE_NIGHT_YES);
    }
    public static ThemePalette load(Context context,SharedPreferences preferences){
        return new ThemePalette(isDark(context,preferences),"AMOLED".equals(preferences.getString("theme","System")),preferences.getString("accent","Blue"));
    }
    public static int previewAccent(String color,boolean dark){return new ThemePalette(dark,false,color).accent;}
    public static int style(boolean dark,String color){
        if("Teal".equals(color))return dark?R.style.FkTealDark:R.style.FkTealLight;
        if("Amber".equals(color))return dark?R.style.FkAmberDark:R.style.FkAmberLight;
        if("Violet".equals(color))return dark?R.style.FkVioletDark:R.style.FkVioletLight;
        return dark?R.style.FkBlueDark:R.style.FkBlueLight;
    }
}
