package com.fieldkit.analyzer;

/** Display only measurements reported by a live ranging session, never RSSI or compass guesses. */
public final class PrecisionReading {
    public static final long FRESH_NANOS=5_000_000_000L;
    public final Float distanceMeters,azimuthDegrees,elevationDegrees;
    public final long elapsedNanos;
    private PrecisionReading(Float distance,Float azimuth,Float elevation,long stamp){distanceMeters=distance;azimuthDegrees=azimuth;elevationDegrees=elevation;elapsedNanos=stamp;}
    public static boolean hardwareSupported(int api,boolean uwbFeature){return api>=31&&uwbFeature;}
    public static PrecisionReading from(Float distance,Float azimuth,Float elevation,long stamp,long now){
        if(stamp<=0||now<stamp||now-stamp>FRESH_NANOS)return null;
        Float d=valid(distance,0,10000),a=valid(azimuth,-180,180),e=valid(elevation,-90,90);
        if(d==null&&a==null&&e==null)return null;
        return new PrecisionReading(d,a,e,stamp);
    }
    private static Float valid(Float value,float min,float max){return value==null||Float.isNaN(value)||Float.isInfinite(value)||value<min||value>max?null:value;}
    public boolean fresh(long now){return now>=elapsedNanos&&now-elapsedNanos<=FRESH_NANOS;}
    public boolean pointsAtTarget(long now){return fresh(now)&&azimuthDegrees!=null;}
    public String direction(long now){
        if(!fresh(now))return "Waiting for a fresh measurement";
        if(azimuthDegrees==null)return "Direction unavailable · distance only";
        float angle=azimuthDegrees;
        if(Math.abs(angle)<=10)return "On target";
        if(Math.abs(angle)>90)return "Turn around";
        return angle>0?"Turn right":"Turn left";
    }
}
