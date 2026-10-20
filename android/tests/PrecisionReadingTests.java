package com.fieldkit.analyzer;

public final class PrecisionReadingTests {
    private static int count;
    private static void check(boolean condition,String why){if(!condition)throw new AssertionError(why);count++;}
    public static void main(String[] args){
        check(!PrecisionReading.hardwareSupported(26,true),"old Android must not load UWB");
        check(!PrecisionReading.hardwareSupported(30,true),"API 30 guard");
        check(!PrecisionReading.hardwareSupported(34,false),"S10e/missing feature unsupported");
        check(PrecisionReading.hardwareSupported(31,true),"minimum capable Android");
        long now=20_000_000_000L;
        PrecisionReading on=PrecisionReading.from(2.5f,0f,null,now,now);
        check(on!=null&&on.direction(now).equals("On target"),"real centered bearing");
        check(on.pointsAtTarget(now),"fresh centered arrow");
        check(on.pointsAtTarget(now+PrecisionReading.FRESH_NANOS),"freshness boundary");
        check(!on.pointsAtTarget(now+PrecisionReading.FRESH_NANOS+1),"stale arrow hidden");
        check(!on.pointsAtTarget(now-1),"clock reversal must not display arrow");
        check(PrecisionReading.from(1f,-30f,null,now,now).direction(now).equals("Turn left"),"left angle sign");
        check(PrecisionReading.from(1f,30f,null,now,now).direction(now).equals("Turn right"),"right angle sign");
        check(PrecisionReading.from(1f,120f,null,now,now).direction(now).equals("Turn around"),"behind device guidance");
        PrecisionReading distanceOnly=PrecisionReading.from(3f,null,null,now,now);
        check(distanceOnly!=null&&!distanceOnly.pointsAtTarget(now),"distance does not invent bearing");
        check(distanceOnly.direction(now).contains("distance only"),"missing bearing explained");
        check(PrecisionReading.from(0f,null,null,now,now).distanceMeters==0f,"zero distance valid");
        check(PrecisionReading.from(Float.NaN,Float.NaN,Float.NaN,now,now)==null,"NaNs absent");
        check(PrecisionReading.from(Float.POSITIVE_INFINITY,Float.NEGATIVE_INFINITY,null,now,now)==null,"infinite data absent");
        PrecisionReading badDistance=PrecisionReading.from(-2f,20f,100f,now,now);
        check(badDistance.distanceMeters==null&&badDistance.elevationDegrees==null,"invalid independent fields omitted");
        check(PrecisionReading.from(1f,181f,-91f,now,now).azimuthDegrees==null,"out of range azimuth absent");
        check(PrecisionReading.from(null,null,null,now,now)==null,"no measurement is not a result");
        check(PrecisionReading.from(1f,0f,0f,0,now)==null,"zero timestamp absent");
        check(PrecisionReading.from(1f,0f,0f,now+1,now)==null,"future measurement absent");
        check(PrecisionReading.from(1f,0f,0f,now-PrecisionReading.FRESH_NANOS-1,now)==null,"old measurement absent");
        System.out.println("PrecisionReadingTests: "+count+" checks passed (hardware gate, real bearing, absent/invalid data and stale arrow).");
    }
}
