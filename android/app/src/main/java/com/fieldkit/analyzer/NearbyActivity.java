package com.fieldkit.analyzer;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanSettings;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.*;
import android.graphics.drawable.GradientDrawable;
import android.hardware.*;
import android.location.LocationManager;
import android.media.AudioManager;
import android.media.ToneGenerator;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.*;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.*;
import android.widget.*;
import java.util.*;
import org.json.*;

/** A target-first radio finder. A signal trend is never represented as a target bearing. */
public final class NearbyActivity extends Activity implements SensorEventListener {
    private static final int REQUEST_ACCESS=410,REQUEST_DISTANCE=411;
    private static final String SNAPSHOT="nearby_snapshot_v1";
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final LinkedHashMap<String,NearbySignal.Reading> readings=new LinkedHashMap<>();
    private final LinkedHashMap<String,TextView> rows=new LinkedHashMap<>();
    private final HashMap<String,android.net.wifi.ScanResult> wifiTargets=new HashMap<>();
    private ThemePalette palette;
    private Store store;
    private WifiManager wifi;
    private BluetoothAdapter bluetooth;
    private BluetoothLeScanner scanner;
    private SensorManager sensors;
    private Sensor rotation,accelerometer,magnetometer;
    private final float[] gravity=new float[3],magnetic=new float[3];
    private boolean gotGravity,gotMagnetic,resumed,registered,scanning,pendingScan,feedback,rangePending,saveScheduled;
    private long stopAt,lastWifiRequest,lastBleRender,lastFeedback,lastHeadingRender;
    private int rangeGeneration;
    private String mode="Wi-Fi",selected="",scanMessage="Choose a device, then start finding. Your observations stay saved.";
    private String distanceTarget="",distanceMessage="";
    private int distanceMm,distanceDeviation;
    private long distanceWall;
    private TextView status,selectedTitle,stateText,signalText,distanceText,headingText,empty,sourceCount;
    private LinearLayout list,headingPanel;
    private Button scanButton,distanceButton,baselineButton;
    private SignalDial dial;
    private SignalHistory history;
    private Compass compass;
    private ToneGenerator tone;
    private boolean compassSupported,headingAvailable;
    private float heading;
    private int accuracy=SensorManager.SENSOR_STATUS_UNRELIABLE;
    private final Runnable saveLater=()->{saveScheduled=false;saveSnapshot(false);};
    private final Runnable tick=new Runnable(){public void run(){
        if(!resumed)return;
        long now=SystemClock.elapsedRealtime();
        if(scanning&&now>=stopAt)stopScan("Finding paused. Your results are saved. Tap Continue finding to keep walking.");
        else if(scanning&&"Wi-Fi".equals(mode)&&now-lastWifiRequest>=30000)requestWifiScan();
        updateRows();updateSelection();updateStatus();handler.postDelayed(this,scanning?1000:5000);
    }};
    private final BroadcastReceiver wifiReceiver=new BroadcastReceiver(){@Override public void onReceive(Context context,Intent intent){
        if(!scanning||!"Wi-Fi".equals(mode))return;
        boolean updated=intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED,false);readWifi();
        scanMessage=updated?"New Wi-Fi readings received. Walk slowly and watch the trend.":"Android has not refreshed Wi-Fi yet. Last-seen ages show the age of each reading.";updateStatus();
    }};
    private final ScanCallback bleCallback=new ScanCallback(){
        @Override public void onScanResult(int callbackType,android.bluetooth.le.ScanResult result){handler.post(()->acceptBle(result));}
        @Override public void onBatchScanResults(List<android.bluetooth.le.ScanResult> results){handler.post(()->{for(android.bluetooth.le.ScanResult result:results)acceptBle(result);});}
        @Override public void onScanFailed(int code){handler.post(()->{if(scanning&&"Bluetooth LE".equals(mode))stopScan("Bluetooth scan failed ("+bleError(code)+"). Check Bluetooth and permissions, then retry.");});}
    };

    @Override public void onCreate(Bundle savedInstanceState){
        store=new Store(this);palette=ThemePalette.load(this,store.prefs);setTheme(ThemePalette.style(palette.dark,store.prefs.getString("accent","Blue")));super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(palette.toolbar);getWindow().setNavigationBarColor(palette.background);
        getWindow().getDecorView().setSystemUiVisibility(palette.dark?0:View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR|View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        wifi=(WifiManager)getApplicationContext().getSystemService(WIFI_SERVICE);
        BluetoothManager manager=(BluetoothManager)getSystemService(BLUETOOTH_SERVICE);bluetooth=manager==null?null:manager.getAdapter();sensors=(SensorManager)getSystemService(SENSOR_SERVICE);
        restoreSnapshot();buildUi();
    }
    private void buildUi(){
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setBackgroundColor(palette.background);
        root.setOnApplyWindowInsetsListener((view,insets)->{if(Build.VERSION.SDK_INT>=30){android.graphics.Insets bars=insets.getInsets(WindowInsets.Type.systemBars()|WindowInsets.Type.displayCutout());view.setPadding(bars.left,bars.top,bars.right,bars.bottom);}else view.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());return insets;});setContentView(root);root.requestApplyInsets();
        LinearLayout toolbar=new LinearLayout(this);toolbar.setGravity(Gravity.CENTER_VERTICAL);toolbar.setPadding(dp(8),dp(4),dp(12),dp(4));toolbar.setBackgroundColor(palette.toolbar);root.addView(toolbar,new LinearLayout.LayoutParams(-1,dp(56)));
        ImageButton back=new ImageButton(this);back.setImageDrawable(new ToolIcon("back",palette.foreground,getResources().getDisplayMetrics().density));back.setBackgroundColor(Color.TRANSPARENT);back.setContentDescription("Back");back.setOnClickListener(v->finish());toolbar.addView(back,new LinearLayout.LayoutParams(dp(44),dp(44)));
        TextView title=text("Nearby finder",20,palette.foreground);title.setTypeface(null,Typeface.BOLD);toolbar.addView(title,new LinearLayout.LayoutParams(0,-2,1));
        Button help=button("How it works",v->showCapabilities());help.setTextSize(12);toolbar.addView(help,new LinearLayout.LayoutParams(dp(112),dp(44)));
        LinearLayout controls=new LinearLayout(this);controls.setGravity(Gravity.CENTER_VERTICAL);controls.setPadding(dp(12),dp(8),dp(12),0);root.addView(controls);
        Spinner modes=new Spinner(this);ArrayAdapter<String> adapter=new ArrayAdapter<String>(this,android.R.layout.simple_spinner_item,new String[]{"Wi-Fi","Bluetooth LE"}){
            @Override public View getView(int p,View v,ViewGroup g){TextView t=(TextView)super.getView(p,v,g);t.setTextColor(palette.foreground);return t;}
            @Override public View getDropDownView(int p,View v,ViewGroup g){TextView t=(TextView)super.getDropDownView(p,v,g);t.setTextColor(palette.foreground);t.setBackgroundColor(palette.surface);return t;}
        };adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);modes.setAdapter(adapter);modes.setSelection("Bluetooth LE".equals(mode)?1:0);controls.addView(modes,new LinearLayout.LayoutParams(0,dp(48),1));
        modes.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){public void onNothingSelected(AdapterView<?> p){}public void onItemSelected(AdapterView<?> p,View v,int position,long id){String next=position==0?"Wi-Fi":"Bluetooth LE";if(!mode.equals(next)){stopScan(null);mode=next;selected="";scanMessage="Choose a source or scan for "+(position==0?"Wi-Fi access points.":"Bluetooth LE advertisements.");rebuildRows();updateSelection();updateStatus();saveSnapshot(false);}}});
        scanButton=button("Scan nearby",v->{if(scanning)stopScan("Finding paused. Observations remain saved.");else beginScan(true);});controls.addView(scanButton,new LinearLayout.LayoutParams(dp(164),dp(48)));
        Button precision=button("Precision finding · check phone support",v->startActivity(new Intent(this,PrecisionFinderActivity.class)));LinearLayout.LayoutParams precisionParams=new LinearLayout.LayoutParams(-1,dp(44));precisionParams.setMargins(dp(12),0,dp(12),0);root.addView(precision,precisionParams);
        status=text(scanMessage,12,palette.muted);status.setPadding(dp(16),dp(4),dp(16),dp(8));status.setLines(2);status.setEllipsize(TextUtils.TruncateAt.END);status.setOnClickListener(v->new AlertDialog.Builder(this).setTitle("Radio status").setMessage(scanMessage).setPositiveButton("OK",null).setNeutralButton("Settings",(d,w)->openSettings()).show());root.addView(status);
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));LinearLayout content=new LinearLayout(this);content.setOrientation(LinearLayout.VERTICAL);content.setPadding(dp(12),0,dp(12),dp(16));scroll.addView(content);
        LinearLayout finder=new LinearLayout(this);finder.setOrientation(LinearLayout.VERTICAL);finder.setPadding(dp(16),dp(14),dp(16),dp(12));finder.setBackground(card(palette.surface));content.addView(finder,new LinearLayout.LayoutParams(-1,-2));
        TextView eyebrow=text("SIGNAL FINDER",11,palette.accent);eyebrow.setLetterSpacing(.1f);eyebrow.setTypeface(null,Typeface.BOLD);finder.addView(eyebrow);
        selectedTitle=text("Choose a device  ▾",18,palette.foreground);selectedTitle.setTypeface(null,Typeface.BOLD);selectedTitle.setMaxLines(2);selectedTitle.setEllipsize(TextUtils.TruncateAt.END);selectedTitle.setPadding(0,dp(5),0,0);selectedTitle.setMinHeight(dp(40));selectedTitle.setGravity(Gravity.CENTER_VERTICAL);selectedTitle.setOnClickListener(v->chooseTarget());selectedTitle.setContentDescription("Choose finder target");finder.addView(selectedTitle);
        stateText=text("Ready to find",22,palette.foreground);stateText.setTypeface(null,Typeface.BOLD);stateText.setMaxLines(2);stateText.setPadding(0,dp(8),0,0);finder.addView(stateText);
        LinearLayout reading=new LinearLayout(this);reading.setGravity(Gravity.CENTER_VERTICAL);finder.addView(reading);
        dial=new SignalDial();reading.addView(dial,new LinearLayout.LayoutParams(dp(108),dp(108)));
        signalText=text("Select an access point or BLE advertiser to follow its signal.",13,palette.muted);signalText.setPadding(dp(12),0,0,0);signalText.setMinLines(4);reading.addView(signalText,new LinearLayout.LayoutParams(0,-2,1));
        history=new SignalHistory();history.setContentDescription("Signal history: latest 32 real samples. Higher points mean stronger signal.");finder.addView(history,new LinearLayout.LayoutParams(-1,dp(42)));
        LinearLayout actions=new LinearLayout(this);finder.addView(actions);baselineButton=button("Reset baseline",v->{NearbySignal.Reading r=readings.get(selected);if(r!=null&&r.fresh(SystemClock.elapsedRealtime())){r.resetBaseline();updateSelection();saveSnapshot(false);}});actions.addView(baselineButton,new LinearLayout.LayoutParams(0,dp(44),1));
        distanceButton=button("Measure distance",v->measureDistance(true));actions.addView(distanceButton,new LinearLayout.LayoutParams(0,dp(44),1));
        distanceText=text("",12,palette.muted);distanceText.setPadding(0,dp(2),0,dp(4));finder.addView(distanceText);
        Switch feedbackSwitch=new Switch(this);feedbackSwitch.setText("Sound & vibration feedback");feedbackSwitch.setTextSize(13);feedbackSwitch.setTextColor(palette.foreground);feedbackSwitch.setChecked(feedback);feedbackSwitch.setMinHeight(dp(44));feedbackSwitch.setOnCheckedChangeListener((b,enabled)->{feedback=enabled;saveSnapshot(false);});finder.addView(feedbackSwitch);
        TextView guidance=text("Move a few steps, pause, then compare. A stronger signal can help you search; walls and reflections can change it.",12,palette.muted);guidance.setPadding(0,dp(4),0,dp(4));finder.addView(guidance);
        TextView bearing=text("Bearing unavailable · phone compass  ›",12,palette.muted);bearing.setMinHeight(dp(36));bearing.setGravity(Gravity.CENTER_VERTICAL);bearing.setOnClickListener(v->{boolean open=headingPanel.getVisibility()!=View.VISIBLE;headingPanel.setVisibility(open?View.VISIBLE:View.GONE);if(open)startCompass();else if(sensors!=null)sensors.unregisterListener(this);});finder.addView(bearing);
        headingPanel=new LinearLayout(this);headingPanel.setGravity(Gravity.CENTER_VERTICAL);headingPanel.setVisibility(View.GONE);finder.addView(headingPanel);compass=new Compass();headingPanel.addView(compass,new LinearLayout.LayoutParams(dp(72),dp(72)));headingText=text("Waiting for heading",12,palette.muted);headingText.setPadding(dp(10),0,0,0);headingPanel.addView(headingText,new LinearLayout.LayoutParams(0,-2,1));
        sourceCount=text("NEARBY SOURCES",12,palette.muted);sourceCount.setTypeface(null,Typeface.BOLD);sourceCount.setPadding(dp(4),dp(18),dp(4),dp(8));content.addView(sourceCount);
        list=new LinearLayout(this);list.setOrientation(LinearLayout.VERTICAL);content.addView(list);rebuildRows();updateSelection();updateStatus();
    }
    private TextView text(String value,int size,int color){TextView t=new TextView(this);t.setText(value);t.setTextSize(size);t.setTextColor(color);return t;}
    private Button button(String title,View.OnClickListener listener){Button b=new Button(this);b.setText(title);b.setTextSize(12);b.setAllCaps(false);b.setTextColor(palette.accent);b.setPadding(dp(4),0,dp(4),0);b.setOnClickListener(listener);return b;}
    private void updateText(TextView view,String value){if(view!=null&&!TextUtils.equals(view.getText(),value))view.setText(value);}
    private int dp(float value){return Math.round(value*getResources().getDisplayMetrics().density);}
    private GradientDrawable card(int color){GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(14));d.setStroke(dp(1),palette.border);return d;}
    private boolean visible(NearbySignal.Reading r){return r.samples>0&&("Wi-Fi".equals(mode)?"Wi-Fi":"BLE").equals(r.kind);}
    private int countVisible(){int count=0;for(NearbySignal.Reading r:readings.values())if(visible(r))count++;return count;}
    private void rebuildRows(){
        list.removeAllViews();rows.clear();empty=text("Wi-Fi".equals(mode)?"No saved access points yet. Tap Scan nearby to discover Wi-Fi sources. Use LAN discovery for IP devices.":"No saved BLE sources yet. Tap Scan nearby while the device is advertising.",14,palette.muted);empty.setPadding(dp(12),dp(14),dp(12),dp(14));list.addView(empty);
        for(NearbySignal.Reading r:readings.values())if(visible(r))addRow(r);updateRows();
    }
    private void addRow(NearbySignal.Reading r){
        if(!visible(r)||rows.containsKey(r.key))return;
        TextView row=text("",14,palette.foreground);row.setPadding(dp(14),dp(12),dp(14),dp(12));row.setMinHeight(dp(78));row.setBackground(card(palette.surface));row.setOnClickListener(v->selectTarget(r));row.setOnLongClickListener(v->{showRadioDetails(r);return true;});
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,0,0,dp(8));list.addView(row,lp);rows.put(r.key,row);empty.setVisibility(View.GONE);
    }
    private String age(NearbySignal.Reading r){return NearbySignal.wallAge(System.currentTimeMillis(),r.observedWall);}
    private void selectTarget(NearbySignal.Reading r){selected=r.key;distanceMessage="";updateSelection();updateRows();updateStatus();saveSnapshot(false);}
    private void chooseTarget(){ArrayList<NearbySignal.Reading> choices=new ArrayList<>();for(NearbySignal.Reading r:readings.values())if(visible(r))choices.add(r);if(choices.isEmpty()){new AlertDialog.Builder(this).setTitle("Choose a target").setMessage("Scan nearby to discover "+("Wi-Fi".equals(mode)?"Wi-Fi access points.":"Bluetooth LE advertisements.")).setPositiveButton("Scan nearby",(d,w)->beginScan(true)).setNegativeButton("Cancel",null).show();return;}String[] labels=new String[choices.size()];for(int i=0;i<labels.length;i++){NearbySignal.Reading r=choices.get(i);labels[i]=r.name+"\n"+r.rssi+" dBm · last seen "+age(r)+"\n"+r.address;}new AlertDialog.Builder(this).setTitle("Choose finder target").setItems(labels,(d,p)->selectTarget(choices.get(p))).setNegativeButton("Cancel",null).show();}
    private void showRadioDetails(NearbySignal.Reading r){new AlertDialog.Builder(this).setTitle(r.name).setMessage(("Wi-Fi".equals(r.kind)?"Wi-Fi access point":"Bluetooth LE advertiser")+"\n"+r.address+"\n\nLast seen "+age(r)+"\nSignal: "+r.rssi+" dBm ("+NearbySignal.strengthLabel(r.smoothed())+")\nSamples: "+r.samples+"\n\n"+r.detail+"\n\nRadio identity does not establish an IP address or a link to a LAN device.").setPositiveButton("Done",null).show();}
    private void updateRows(){
        for(NearbySignal.Reading r:readings.values()){TextView row=rows.get(r.key);if(row==null)continue;String capability="Wi-Fi".equals(r.kind)?"Wi-Fi access point":"Bluetooth LE";String label=r.restored?"Saved":"Last seen";
            updateText(row,(r.key.equals(selected)?"●  ":"")+r.name+"\n"+capability+" · "+NearbySignal.strengthLabel(r.smoothed())+" · "+r.rssi+" dBm\n"+label+" "+age(r)+"  ·  "+r.address);row.setTextColor(r.key.equals(selected)?palette.accent:palette.foreground);row.setContentDescription(r.name+", "+capability+", "+r.rssi+" dBm, last seen "+age(r)+". Tap to select this finder target.");}
        if(empty!=null)empty.setVisibility(rows.isEmpty()?View.VISIBLE:View.GONE);updateText(sourceCount,"NEARBY SOURCES · "+countVisible());
    }
    private void updateSelection(){
        if(dial==null)return;NearbySignal.Reading r=readings.get(selected);long now=SystemClock.elapsedRealtime();
        if(r==null||!visible(r)){updateText(selectedTitle,"Choose a device  ▾");updateText(stateText,"Ready to find");updateText(signalText,"Select an access point or BLE advertiser to follow its signal.");dial.setReading(null);history.setReading(null);baselineButton.setEnabled(false);}
        else{
            updateText(selectedTitle,r.name+"  ▾");String state;
            if(r.restored)state="Saved observation";
            else if(!r.fresh(now))state=scanning?"Signal lost":"Last seen signal";
            else if(r.samples<2)state="Signal detected";
            else if(r.baselineChange()>=4)state="Signal getting stronger";
            else if(r.baselineChange()<=-4)state="Signal getting weaker";
            else state="Signal holding steady";
            updateText(stateText,state);int change=r.baselineChange();String baseline=change==0?"At your baseline":(change>0?"+":"")+change+" dB from baseline";
            updateText(signalText,NearbySignal.strengthLabel(r.smoothed())+" · "+r.rssi+" dBm\n"+baseline+"\nLast seen "+age(r)+(r.restored?"\nStart finding for live readings.":!r.fresh(now)?"\nWaiting for a fresh reading.":"\n"+("BLE".equals(r.kind)?"Bluetooth LE advertisement":"Wi-Fi scan reading")));
            dial.setReading(r);history.setReading(r);baselineButton.setEnabled(r.fresh(now));
        }
        distanceButton.setVisibility("Wi-Fi".equals(mode)?View.VISIBLE:View.GONE);distanceButton.setEnabled(!rangePending);updateDistanceText(r);
        updateHeading();
    }
    private void updateHeading(){if(headingAvailable)updateText(headingText,String.format(Locale.US,"Phone top: %.0f° magnetic %s\n%s\nThis is not a target direction.",heading,NearbySignal.cardinal(heading),accuracyText()));else updateText(headingText,compassSupported?"Waiting for phone heading. Target bearing is unavailable.":"No magnetic heading sensor. Target bearing is unavailable.");}
    private void updateDistanceText(NearbySignal.Reading r){
        if(!distanceMessage.isEmpty()){updateText(distanceText,distanceMessage);return;}
        if(r!=null&&selected.equals(distanceTarget)&&distanceWall>0){updateText(distanceText,String.format(Locale.US,"Last RTT distance: %.2f m · deviation %.2f m\nMeasured %s · no target bearing",distanceMm/1000.0,distanceDeviation/1000.0,NearbySignal.wallAge(System.currentTimeMillis(),distanceWall)));return;}
        if("Bluetooth LE".equals(mode)){updateText(distanceText,"BLE signal finding · distance and target direction unavailable");return;}
        if(!WifiDistance.supported(this)){updateText(distanceText,"Signal finding available · this phone has no Wi-Fi RTT ranging hardware");return;}
        android.net.wifi.ScanResult target=wifiTargets.get(selected);updateText(distanceText,target==null?"RTT distance needs a fresh scan and a compatible access point.":WifiDistance.responder(target)?"This access point supports RTT distance. Tap Measure distance.":"This access point does not advertise RTT distance support.");
    }
    private void updateStatus(){updateText(status,scanMessage+(scanning?"\n"+Math.max(0,(stopAt-SystemClock.elapsedRealtime()+999)/1000)+" s remaining · "+countVisible()+" sources":""));updateText(scanButton,scanning?"Pause finding":selected.isEmpty()?"Scan nearby":"Continue finding");}
    private boolean granted(String permission){return checkSelfPermission(permission)==PackageManager.PERMISSION_GRANTED;}
    private String[] requiredPermissions(){ArrayList<String> result=new ArrayList<>();if(!granted(Manifest.permission.ACCESS_FINE_LOCATION)){if(Build.VERSION.SDK_INT>=31)result.add(Manifest.permission.ACCESS_COARSE_LOCATION);result.add(Manifest.permission.ACCESS_FINE_LOCATION);}if("Bluetooth LE".equals(mode)&&Build.VERSION.SDK_INT>=31){if(!granted(Manifest.permission.BLUETOOTH_SCAN))result.add(Manifest.permission.BLUETOOTH_SCAN);if(!granted(Manifest.permission.BLUETOOTH_CONNECT))result.add(Manifest.permission.BLUETOOTH_CONNECT);}return result.toArray(new String[0]);}
    private boolean locationOn(){try{LocationManager location=(LocationManager)getSystemService(LOCATION_SERVICE);return location!=null&&(Build.VERSION.SDK_INT>=28?location.isLocationEnabled():location.isProviderEnabled(LocationManager.GPS_PROVIDER)||location.isProviderEnabled(LocationManager.NETWORK_PROVIDER));}catch(RuntimeException e){return false;}}
    private void beginScan(boolean requestAccess){
        if(!resumed)return;String[] needed=requiredPermissions();if(needed.length>0){scanMessage="Allow precise location for radio finding"+("Bluetooth LE".equals(mode)&&Build.VERSION.SDK_INT>=31?" and Nearby devices for Bluetooth.":".");updateStatus();if(requestAccess){pendingScan=true;requestPermissions(needed,REQUEST_ACCESS);}return;}
        if(!locationOn()){scanMessage="Location is off. Tap this message to open Settings and enable radio results.";updateStatus();return;}
        stopAt=SystemClock.elapsedRealtime()+(selected.isEmpty()?30000:120000);
        try{
            if("Wi-Fi".equals(mode)){
                if(wifi==null){scanMessage="This phone has no Wi-Fi scan service.";updateStatus();return;}
                if(!wifi.isWifiEnabled()){scanMessage="Wi-Fi is off. Tap this message to open Settings.";updateStatus();return;}
                scanning=true;scanMessage="Finding Wi-Fi sources. Android controls how often signal readings refresh.";readWifi();if(scanning)requestWifiScan();
            }else{
                if(bluetooth==null||!getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)){scanMessage="This phone has no Bluetooth LE scanning hardware.";updateStatus();return;}
                if(!bluetooth.isEnabled()){scanMessage="Bluetooth is off. Tap this message to open Settings.";updateStatus();return;}
                scanner=bluetooth.getBluetoothLeScanner();if(scanner==null){scanMessage="Bluetooth scanner is unavailable. Check Bluetooth in Settings.";updateStatus();return;}
                scanning=true;scanMessage="Listening for BLE advertisements. Select a source, then move slowly.";scanner.startScan(null,new ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).setReportDelay(0).build(),bleCallback);
            }
            if(scanning)getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        }catch(SecurityException e){stopScan("Radio access was denied. Check precise location and Nearby devices in app settings.");}catch(RuntimeException e){stopScan("Radio scan could not start. Check system radio settings and retry.");}
        updateStatus();
    }
    private void requestWifiScan(){lastWifiRequest=SystemClock.elapsedRealtime();try{if(!wifi.startScan())scanMessage="Android has delayed this Wi-Fi scan. Last-seen ages remain accurate; wait before retrying.";}catch(SecurityException e){stopScan("Wi-Fi permission was denied. Allow precise location and enable Location.");}catch(RuntimeException e){stopScan("Wi-Fi scanning is unavailable. Check system radio settings.");}}
    private void readWifi(){
        try{long now=SystemClock.elapsedRealtime(),wall=System.currentTimeMillis();for(android.net.wifi.ScanResult result:wifi.getScanResults()){
            if(result.BSSID==null||result.BSSID.isEmpty())continue;String key="wifi:"+result.BSSID;wifiTargets.put(key,result);String name=result.SSID==null||result.SSID.trim().isEmpty()?"Hidden Wi-Fi access point":result.SSID;
            NearbySignal.Reading r=readings.get(key);if(r==null){if(readings.size()>=256)continue;r=new NearbySignal.Reading(key,"Wi-Fi",result.BSSID,name);readings.put(key,r);}else r.name=name;
            r.detail=result.frequency+" MHz"+(WifiDistance.responder(result)?" · RTT distance supported":"")+(result.capabilities==null?"":" · "+result.capabilities);
            long at=Math.min(now,result.timestamp/1000);if(r.update(result.level,at,wall-Math.max(0,now-at))){newSample(r);if(r.samples>0)addRow(r);}
        }updateRows();updateSelection();scheduleSave();}catch(SecurityException e){stopScan("Wi-Fi results are restricted. Allow precise location and turn Location on.");}catch(RuntimeException e){scanMessage="Wi-Fi results are unavailable. Check system radio settings.";}
    }
    private void acceptBle(android.bluetooth.le.ScanResult result){
        if(!scanning||!resumed||!"Bluetooth LE".equals(mode)||result==null||result.getDevice()==null)return;
        try{String address=result.getDevice().getAddress();ScanRecord record=result.getScanRecord();String name=record==null?null:record.getDeviceName();if(name==null||name.isEmpty())name=result.getDevice().getName();if(name==null||name.isEmpty())name="Unnamed BLE advertiser";
            String key="ble:"+address;NearbySignal.Reading r=readings.get(key);if(r==null){if(readings.size()>=256)return;r=new NearbySignal.Reading(key,"BLE",address,name);readings.put(key,r);}else r.name=name;
            r.detail="BLE advertisement"+(record!=null&&record.getServiceUuids()!=null?" · "+record.getServiceUuids().size()+" service UUIDs":"");long now=SystemClock.elapsedRealtime(),at=Math.min(now,result.getTimestampNanos()/1000000);
            if(r.update(result.getRssi(),at,System.currentTimeMillis()-Math.max(0,now-at))){newSample(r);if(r.samples>0)addRow(r);scheduleSave();}if(now-lastBleRender>=250){lastBleRender=now;updateRows();updateSelection();}
        }catch(SecurityException e){stopScan("Bluetooth access was revoked. Check Nearby devices permissions.");}
    }
    private void newSample(NearbySignal.Reading r){
        long now=SystemClock.elapsedRealtime();if(!feedback||!resumed||!scanning||!r.key.equals(selected)||!r.fresh(now)||now-lastFeedback<1800)return;lastFeedback=now;
        try{if(tone==null)tone=new ToneGenerator(AudioManager.STREAM_MUSIC,28);tone.startTone(r.baselineChange()>=4?ToneGenerator.TONE_PROP_ACK:r.baselineChange()<=-4?ToneGenerator.TONE_PROP_NACK:ToneGenerator.TONE_PROP_BEEP,90);}catch(RuntimeException ignored){}
        try{Vibrator vibrator=(Vibrator)getSystemService(VIBRATOR_SERVICE);if(vibrator!=null&&vibrator.hasVibrator())vibrator.vibrate(VibrationEffect.createOneShot(30,VibrationEffect.DEFAULT_AMPLITUDE));}catch(RuntimeException ignored){}
    }
    private void stopScan(String message){
        scanning=false;pendingScan=false;getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);if(scanner!=null){try{scanner.stopScan(bleCallback);}catch(RuntimeException ignored){}scanner=null;}
        if(message!=null){scanMessage=message;if("Bluetooth LE".equals(mode)&&countVisible()==0&&message.startsWith("Finding paused"))scanMessage="No BLE advertisements received. The device may not be advertising or may be out of range.";}if(scanButton!=null){updateStatus();updateSelection();}
    }
    private void measureDistance(boolean requestAccess){
        if(!resumed||rangePending)return;NearbySignal.Reading r=readings.get(selected);
        if(r==null||!"Wi-Fi".equals(r.kind)){distanceMessage="Choose a Wi-Fi access point before measuring distance.";updateSelection();return;}
        if(!WifiDistance.supported(this)){distanceMessage="This phone has no Wi-Fi RTT ranging hardware. Signal finding is still available.";updateSelection();return;}
        android.net.wifi.ScanResult target=wifiTargets.get(selected);if(target==null){distanceMessage="Start finding to get a fresh access-point scan, then measure distance.";updateSelection();return;}
        if(!WifiDistance.responder(target)){distanceMessage="This access point does not advertise Wi-Fi RTT distance support.";updateSelection();return;}
        ArrayList<String> needed=new ArrayList<>();if(Build.VERSION.SDK_INT>=33&&!granted(Manifest.permission.NEARBY_WIFI_DEVICES))needed.add(Manifest.permission.NEARBY_WIFI_DEVICES);if(!granted(Manifest.permission.ACCESS_FINE_LOCATION)){if(Build.VERSION.SDK_INT>=31)needed.add(Manifest.permission.ACCESS_COARSE_LOCATION);needed.add(Manifest.permission.ACCESS_FINE_LOCATION);}
        if(!needed.isEmpty()){distanceMessage="Distance measurement needs Nearby Wi-Fi devices and precise location access.";updateSelection();if(requestAccess)requestPermissions(needed.toArray(new String[0]),REQUEST_DISTANCE);return;}
        if(!locationOn()){distanceMessage="Turn Location on in system settings before measuring distance.";updateSelection();return;}
        final String requestedTarget=selected;final int generation=++rangeGeneration;rangePending=true;distanceMessage="Measuring distance with Wi-Fi RTT…";updateSelection();
        handler.postDelayed(()->{if(generation==rangeGeneration&&rangePending){rangePending=false;rangeGeneration++;distanceMessage="Distance measurement timed out. Move into range and retry.";if(resumed)updateSelection();}},15000);
        WifiDistance.measure(this,target,command->handler.post(command),new WifiDistance.Listener(){
            public void success(int mm,int deviation,long timestamp){if(generation!=rangeGeneration)return;rangePending=false;if(!resumed)return;distanceTarget=requestedTarget;distanceMm=mm;distanceDeviation=Math.max(0,deviation);distanceWall=System.currentTimeMillis()-Math.max(0,SystemClock.elapsedRealtime()-timestamp);distanceMessage="";updateSelection();saveSnapshot(false);}
            public void failure(String message){if(generation!=rangeGeneration)return;rangePending=false;if(!resumed)return;if(selected.equals(requestedTarget))distanceMessage=message;updateSelection();}
        });
    }
    private void openSettings(){Intent intent;if(requiredPermissions().length>0)intent=new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+getPackageName()));else if(!locationOn())intent=new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS);else intent=new Intent("Wi-Fi".equals(mode)?Settings.ACTION_WIFI_SETTINGS:Settings.ACTION_BLUETOOTH_SETTINGS);try{startActivity(intent);}catch(ActivityNotFoundException e){startActivity(new Intent(Settings.ACTION_SETTINGS));}}
    private void showCapabilities(){String rtt=Build.VERSION.SDK_INT<28?"Requires Android 9 or later":WifiDistance.supported(this)?"Phone supports RTT; the access point must also support it":"This phone does not report RTT hardware";boolean uwb=Build.VERSION.SDK_INT>=31&&getPackageManager().hasSystemFeature("android.hardware.uwb");new AlertDialog.Builder(this).setTitle("Finding nearby devices").setMessage("Signal finder\nChoose a Wi-Fi access point or BLE advertiser. Move a few steps and compare live signal strength with your starting baseline. Sound and vibration only respond to fresh target readings.\n\nWi-Fi RTT distance\n"+rtt+". Only a successful RTT measurement produces a distance; signal strength is never converted into meters.\n\nPrecision direction\n"+(uwb?"This phone reports UWB hardware. ":"This phone does not report UWB hardware. ")+"Open Precision finding to check hardware and pair two compatible phones running FieldKit. Real UWB reports supply distance and direction when supported. An IP address or BLE advertisement alone cannot provide a target bearing. This app does not connect to Apple Find My or Google's tracking network.\n\nSaved observations\nBack and closing the app retain your readings, selected target, baseline and history. Reopening does not start a radio scan. Last-seen times stay visible. Use Clear observations below to delete this finder inventory.\n\nWi-Fi names identify access points; Bluetooth names appear only when advertised or exposed by Android. These are not proof that a radio belongs to a particular LAN device.").setPositiveButton("Got it",null).setNeutralButton("Clear observations",(dialog,which)->confirmClearObservations()).show();}
    private void confirmClearObservations(){new AlertDialog.Builder(this).setTitle("Clear nearby observations?").setMessage("This stops finding and deletes saved nearby radios, the selected target, signal history, baselines and RTT distance measurements. LAN results, permissions and appearance settings stay saved.").setPositiveButton("Clear",(dialog,which)->{stopScan(null);rangePending=false;rangeGeneration++;handler.removeCallbacks(saveLater);saveScheduled=false;readings.clear();wifiTargets.clear();selected="";distanceTarget="";distanceMessage="";distanceMm=0;distanceDeviation=0;distanceWall=0;store.prefs.edit().remove(SNAPSHOT).commit();scanMessage="Nearby observations cleared. Tap Scan nearby when ready.";rebuildRows();updateSelection();updateStatus();saveSnapshot(true);}).setNegativeButton("Cancel",null).show();}
    private void scheduleSave(){if(!saveScheduled){saveScheduled=true;handler.postDelayed(saveLater,750);}}
    private void saveSnapshot(boolean sync){if(store==null)return;try{JSONObject snapshot=NearbySnapshot.save(readings.values(),mode,selected,feedback);snapshot.put("distance_target",distanceTarget).put("distance_mm",distanceMm).put("distance_deviation",distanceDeviation).put("distance_wall",distanceWall);android.content.SharedPreferences.Editor edit=store.prefs.edit().putString(SNAPSHOT,snapshot.toString());if(sync)edit.commit();else edit.apply();}catch(JSONException ignored){}}
    private void restoreSnapshot(){String raw=store.prefs.getString(SNAPSHOT,"");if(raw.isEmpty())return;try{JSONObject snapshot=new JSONObject(raw);readings.putAll(NearbySnapshot.restore(snapshot,SystemClock.elapsedRealtime(),System.currentTimeMillis()));mode="Bluetooth LE".equals(snapshot.optString("mode"))?"Bluetooth LE":"Wi-Fi";selected=snapshot.optString("selected");feedback=snapshot.optBoolean("feedback");distanceTarget=snapshot.optString("distance_target");distanceMm=Math.max(0,snapshot.optInt("distance_mm"));distanceDeviation=Math.max(0,snapshot.optInt("distance_deviation"));distanceWall=snapshot.optLong("distance_wall");if(!readings.isEmpty())scanMessage="Saved observations restored. Tap Continue finding for fresh readings.";}catch(JSONException ignored){scanMessage="Ready to scan. The previous observation snapshot could not be restored.";}}
    @Override public void onRequestPermissionsResult(int requestCode,String[] permissions,int[] results){super.onRequestPermissionsResult(requestCode,permissions,results);if(requestCode==REQUEST_DISTANCE){if(resumed)measureDistance(false);return;}if(requestCode!=REQUEST_ACCESS)return;if(requiredPermissions().length==0){if(resumed){pendingScan=false;beginScan(false);}else pendingScan=true;}else{pendingScan=false;scanMessage="Access was not granted. Tap this message for Settings, then allow precise location and Nearby devices for Bluetooth.";updateStatus();}}
    @Override protected void onResume(){super.onResume();resumed=true;if(!registered){IntentFilter filter=new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);if(Build.VERSION.SDK_INT>=33)registerReceiver(wifiReceiver,filter,Context.RECEIVER_EXPORTED);else registerReceiver(wifiReceiver,filter);registered=true;}if(headingPanel.getVisibility()==View.VISIBLE)startCompass();handler.removeCallbacks(tick);handler.post(tick);if(pendingScan&&requiredPermissions().length==0){pendingScan=false;beginScan(false);}}
    @Override protected void onPause(){resumed=false;rangePending=false;rangeGeneration++;stopScan(scanning?"Finding paused while this screen is inactive. Tap Continue finding to resume.":null);handler.removeCallbacks(tick);handler.removeCallbacks(saveLater);saveScheduled=false;saveSnapshot(true);if(sensors!=null)sensors.unregisterListener(this);if(registered){try{unregisterReceiver(wifiReceiver);}catch(IllegalArgumentException ignored){}registered=false;}if(tone!=null){tone.release();tone=null;}super.onPause();}
    @Override protected void onDestroy(){handler.removeCallbacksAndMessages(null);if(store!=null)store.close();super.onDestroy();}
    private void startCompass(){
        compassSupported=false;headingAvailable=false;gotGravity=false;gotMagnetic=false;accuracy=SensorManager.SENSOR_STATUS_UNRELIABLE;if(sensors==null){updateSelection();return;}
        rotation=sensors.getDefaultSensor(Sensor.TYPE_ROTATION_VECTOR);if(rotation==null)rotation=sensors.getDefaultSensor(Sensor.TYPE_GEOMAGNETIC_ROTATION_VECTOR);
        if(rotation!=null)compassSupported=sensors.registerListener(this,rotation,SensorManager.SENSOR_DELAY_UI);else{accelerometer=sensors.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);magnetometer=sensors.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD);if(accelerometer!=null&&magnetometer!=null){boolean a=sensors.registerListener(this,accelerometer,SensorManager.SENSOR_DELAY_UI);boolean m=sensors.registerListener(this,magnetometer,SensorManager.SENSOR_DELAY_UI);compassSupported=a&&m;}}updateSelection();
    }
    @Override public void onSensorChanged(SensorEvent event){
        float[] matrix=new float[9];if(event.sensor.getType()==Sensor.TYPE_ROTATION_VECTOR||event.sensor.getType()==Sensor.TYPE_GEOMAGNETIC_ROTATION_VECTOR){SensorManager.getRotationMatrixFromVector(matrix,event.values);accuracy=event.accuracy;}else{if(event.sensor.getType()==Sensor.TYPE_ACCELEROMETER){System.arraycopy(event.values,0,gravity,0,3);gotGravity=true;}if(event.sensor.getType()==Sensor.TYPE_MAGNETIC_FIELD){System.arraycopy(event.values,0,magnetic,0,3);gotMagnetic=true;accuracy=event.accuracy;}if(!gotGravity||!gotMagnetic||!SensorManager.getRotationMatrix(matrix,null,gravity,magnetic))return;}
        float[] display=new float[9];int x=SensorManager.AXIS_X,y=SensorManager.AXIS_Y;int turn=getWindowManager().getDefaultDisplay().getRotation();if(turn==Surface.ROTATION_90){x=SensorManager.AXIS_Y;y=SensorManager.AXIS_MINUS_X;}else if(turn==Surface.ROTATION_180){x=SensorManager.AXIS_MINUS_X;y=SensorManager.AXIS_MINUS_Y;}else if(turn==Surface.ROTATION_270){x=SensorManager.AXIS_MINUS_Y;y=SensorManager.AXIS_X;}if(!SensorManager.remapCoordinateSystem(matrix,x,y,display))return;float[] orientation=new float[3];SensorManager.getOrientation(display,orientation);heading=NearbySignal.normalizeHeading((float)Math.toDegrees(orientation[0]));headingAvailable=true;long now=SystemClock.elapsedRealtime();if(now-lastHeadingRender>=250){lastHeadingRender=now;compass.invalidate();updateHeading();}
    }
    @Override public void onAccuracyChanged(Sensor sensor,int value){if(sensor==rotation||sensor==magnetometer){accuracy=value;updateHeading();}}
    private String accuracyText(){return accuracy==SensorManager.SENSOR_STATUS_ACCURACY_HIGH?"Compass accuracy: high":accuracy==SensorManager.SENSOR_STATUS_ACCURACY_MEDIUM?"Compass accuracy: medium":"Low accuracy: calibrate away from metal";}
    private static String bleError(int code){switch(code){case ScanCallback.SCAN_FAILED_ALREADY_STARTED:return "already scanning";case ScanCallback.SCAN_FAILED_APPLICATION_REGISTRATION_FAILED:return "registration failed";case ScanCallback.SCAN_FAILED_FEATURE_UNSUPPORTED:return "unsupported";case ScanCallback.SCAN_FAILED_INTERNAL_ERROR:return "radio error";default:return "code "+code;}}
    private final class SignalDial extends View {
        private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);private NearbySignal.Reading reading;
        SignalDial(){super(NearbyActivity.this);setContentDescription("Signal strength, not distance");}
        void setReading(NearbySignal.Reading r){if(reading!=r||r!=null){reading=r;invalidate();}}
        @Override protected void onDraw(Canvas c){super.onDraw(c);float cx=getWidth()/2f,cy=getHeight()/2f,r=Math.min(cx,cy)-dp(10);RectF oval=new RectF(cx-r,cy-r,cx+r,cy+r);paint.setStyle(Paint.Style.STROKE);paint.setStrokeWidth(dp(8));paint.setStrokeCap(Paint.Cap.ROUND);paint.setColor(palette.border);c.drawArc(oval,135,270,false,paint);boolean fresh=reading!=null&&reading.fresh(SystemClock.elapsedRealtime());paint.setColor(fresh?palette.accent:palette.muted);if(reading!=null)c.drawArc(oval,135,270*NearbySignal.strengthPercent(reading.smoothed())/100f,false,paint);paint.setStyle(Paint.Style.FILL);paint.setTextAlign(Paint.Align.CENTER);paint.setTypeface(Typeface.DEFAULT_BOLD);paint.setTextSize(dp(25));paint.setColor(palette.foreground);c.drawText(reading==null?"—":Integer.toString(reading.rssi),cx,cy+dp(2),paint);paint.setTypeface(Typeface.DEFAULT);paint.setTextSize(dp(11));paint.setColor(palette.muted);c.drawText("dBm",cx,cy+dp(19),paint);}
    }
    private final class SignalHistory extends View {
        private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);private NearbySignal.Reading reading;
        SignalHistory(){super(NearbyActivity.this);}
        void setReading(NearbySignal.Reading r){reading=r;invalidate();}
        @Override protected void onDraw(Canvas c){super.onDraw(c);paint.setColor(palette.border);paint.setStrokeWidth(dp(1));c.drawLine(0,getHeight()-dp(6),getWidth(),getHeight()-dp(6),paint);int[] values=reading==null?new int[0]:reading.history();if(values.length==0)return;float w=getWidth()-dp(8),h=getHeight()-dp(12);paint.setColor(reading.restored?palette.muted:palette.accent);paint.setStrokeWidth(dp(2));paint.setStrokeCap(Paint.Cap.ROUND);for(int i=0;i<values.length;i++){float x=dp(4)+(values.length==1?0:i*w/(values.length-1)),y=dp(5)+h*(1-NearbySignal.strengthPercent(values[i])/100f);if(i>0){float px=dp(4)+(i-1)*w/(values.length-1),py=dp(5)+h*(1-NearbySignal.strengthPercent(values[i-1])/100f);c.drawLine(px,py,x,y,paint);}else c.drawCircle(x,y,dp(2),paint);}}
    }
    private final class Compass extends View {
        private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);Compass(){super(NearbyActivity.this);setContentDescription("Magnetic phone orientation only. Target bearing is unknown.");}
        @Override protected void onDraw(Canvas c){super.onDraw(c);float cx=getWidth()/2f,cy=getHeight()/2f,r=Math.min(cx,cy)-dp(5);paint.setStyle(Paint.Style.STROKE);paint.setStrokeWidth(dp(1));paint.setColor(palette.border);c.drawCircle(cx,cy,r,paint);paint.setStyle(Paint.Style.FILL);paint.setColor(palette.muted);paint.setTextAlign(Paint.Align.CENTER);paint.setTextSize(dp(9));c.drawText("PHONE",cx,cy+dp(4),paint);if(!headingAvailable)return;int saved=c.save();c.rotate(-heading,cx,cy);paint.setColor(palette.accent);c.drawText("N",cx,cy-r+dp(12),paint);Path needle=new Path();needle.moveTo(cx,cy-r+dp(16));needle.lineTo(cx-dp(4),cy-dp(8));needle.lineTo(cx+dp(4),cy-dp(8));needle.close();c.drawPath(needle,paint);c.restoreToCount(saved);}
    }
}
