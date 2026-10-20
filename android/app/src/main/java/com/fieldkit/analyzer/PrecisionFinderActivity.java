package com.fieldkit.analyzer;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.*;
import android.graphics.drawable.GradientDrawable;
import android.os.*;
import android.view.*;
import android.widget.*;
import java.util.Locale;

/** Foreground UWB finder. Unsupported devices never construct or request access to the UWB backend. */
public final class PrecisionFinderActivity extends Activity {
    private static final String PERMISSION="android.permission.UWB_RANGING";
    private static final int REQUEST_UWB=520;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private ThemePalette palette;
    private Store store;
    private LinearLayout content,setup,roleChoices,codeActions;
    private TextView status,capability,distance,direction,age,codeHint;
    private EditText incoming;
    private Button importButton,startButton,stopButton;
    private BearingView bearing;
    private PrecisionUwb backend;
    private PrecisionUwb.Capabilities capabilities;
    private UwbPairing.Invite invite;
    private UwbPairing.Reply reply;
    private byte[] localAddress,peerAddress;
    private int channel,preamble,generation;
    private boolean controller,prepared,running,scopeUsed,resumed,legacy;
    private PrecisionReading latest;
    private String outgoing="";
    private final Runnable tick=new Runnable(){public void run(){
        if(!resumed)return;
        if(running)drawMeasurement();
        if(prepared&&!running&&invite!=null&&System.currentTimeMillis()>invite.expiresAtWall){endSession("Pairing code expired. Pair again to create a new private code.");}
        if(prepared||running)handler.postDelayed(this,running?500:1000);
    }};

    @Override public void onCreate(Bundle state){
        store=new Store(this);palette=ThemePalette.load(this,store.prefs);
        setTheme(ThemePalette.style(palette.dark,store.prefs.getString("accent","Blue")));super.onCreate(state);
        getWindow().setStatusBarColor(palette.toolbar);getWindow().setNavigationBarColor(palette.background);
        getWindow().getDecorView().setSystemUiVisibility(palette.dark?0:View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR|View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        build();checkPhone();
    }
    private void build(){
        LinearLayout root=column();root.setBackgroundColor(palette.background);
        root.setOnApplyWindowInsetsListener((view,insets)->{if(Build.VERSION.SDK_INT>=30){android.graphics.Insets bars=insets.getInsets(WindowInsets.Type.systemBars()|WindowInsets.Type.displayCutout());view.setPadding(bars.left,bars.top,bars.right,bars.bottom);}else view.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());return insets;});setContentView(root);root.requestApplyInsets();
        LinearLayout toolbar=row();toolbar.setPadding(dp(8),0,dp(8),0);toolbar.setBackgroundColor(palette.toolbar);root.addView(toolbar,new LinearLayout.LayoutParams(-1,dp(56)));
        ImageButton back=new ImageButton(this);back.setImageDrawable(new ToolIcon("back",palette.foreground,getResources().getDisplayMetrics().density));back.setContentDescription("Back");back.setBackgroundColor(Color.TRANSPARENT);back.setOnClickListener(v->finish());toolbar.addView(back,new LinearLayout.LayoutParams(dp(44),dp(44)));
        TextView title=text("Precision finder",20,palette.foreground);title.setTypeface(null,Typeface.BOLD);toolbar.addView(title,new LinearLayout.LayoutParams(0,-2,1));
        Button help=button("Help",v->help());toolbar.addView(help,new LinearLayout.LayoutParams(dp(60),dp(44)));
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));content=column();content.setPadding(dp(12),dp(12),dp(12),dp(20));scroll.addView(content);
        LinearLayout card=card();content.addView(card);
        TextView label=text("UWB PRECISION FINDING",11,palette.accent);label.setLetterSpacing(.08f);card.addView(label);
        status=text("Checking this phone…",19,palette.foreground);status.setTypeface(null,Typeface.BOLD);status.setPadding(0,dp(10),0,dp(6));card.addView(status);
        capability=text("",13,palette.muted);card.addView(capability);
        bearing=new BearingView();card.addView(bearing,new LinearLayout.LayoutParams(-1,dp(154)));
        distance=text("—",38,palette.foreground);distance.setGravity(Gravity.CENTER);distance.setTypeface(null,Typeface.BOLD);card.addView(distance);
        direction=text("",18,palette.foreground);direction.setGravity(Gravity.CENTER);direction.setPadding(0,dp(4),0,dp(4));card.addView(direction);
        age=text("",12,palette.muted);age.setGravity(Gravity.CENTER);card.addView(age);
        setup=column();LinearLayout.LayoutParams setupParams=new LinearLayout.LayoutParams(-1,-2);setupParams.topMargin=dp(12);content.addView(setup,setupParams);
        roleChoices=column();setup.addView(roleChoices);
        add(roleChoices,button("Find another phone",v->prepare(true)),true);
        add(roleChoices,button("Be found by another phone",v->prepare(false)),false);
        TextView explanation=text("Use two compatible phones with FieldKit open. Private pairing codes connect only the phones you choose.",13,palette.muted);explanation.setPadding(dp(4),dp(12),dp(4),dp(6));roleChoices.addView(explanation);
        stopButton=button("Stop finding",v->endSession("Finding stopped. Pair again when ready."));add(content,stopButton,false);stopButton.setVisibility(View.GONE);
    }
    private void checkPhone(){
        boolean hardware=getPackageManager().hasSystemFeature("android.hardware.uwb");
        if(!PrecisionReading.hardwareSupported(Build.VERSION.SDK_INT,hardware)){
            status.setText("Unsupported on this phone");capability.setText(Build.VERSION.SDK_INT<31?"Precision finding requires Android 12 or later and UWB hardware.":"This phone does not report UWB ranging hardware. Signal finding is still available.");
            roleChoices.setVisibility(View.GONE);bearing.setVisibility(View.GONE);distance.setVisibility(View.GONE);direction.setText("Wi-Fi and Bluetooth signal finding still work.");
            add(setup,button("Back to signal finder",v->openSignalFinder()),true);return;
        }
        bearing.setVisibility(View.VISIBLE);distance.setVisibility(View.VISIBLE);
        status.setText("UWB hardware detected");capability.setText("Choose whether to find another phone or let it find this phone. We check usable distance and direction support before pairing.");
        direction.setText("Choose a finding mode");roleChoices.setVisibility(View.VISIBLE);
    }
    private boolean permission(){return Build.VERSION.SDK_INT>=31&&checkSelfPermission(PERMISSION)==PackageManager.PERMISSION_GRANTED;}
    private void prepare(boolean asController){
        controller=asController;
        if(!permission()){status.setText("Allow nearby ranging");capability.setText("Android needs your permission to use this phone’s UWB radio.");requestPermissions(new String[]{PERMISSION},REQUEST_UWB);return;}
        resetBackend();final int currentGeneration=++generation;
        setup.removeAllViews();status.setText("Checking UWB availability…");capability.setText("Keep UWB enabled in system settings.");direction.setText("Preparing a private session");
        try{
            backend=new PrecisionUwb(this,controller,new PrecisionUwb.Listener(){
                public void ready(PrecisionUwb.Capabilities caps,byte[] address,int actualChannel,int actualPreamble){if(currentGeneration!=generation)return;capabilities=caps;localAddress=address;channel=actualChannel;preamble=actualPreamble;prepared=true;handler.removeCallbacks(tick);handler.post(tick);
                    if(!caps.distance){endSession("UWB distance measurements are unsupported on this phone.");return;}
                    status.setText(controller?"Ready to pair · finder":"Ready to pair · target");capability.setText(caps.azimuth?"Distance and direction supported. Pair with the other phone to start.":"Distance supported. Direction is unavailable on this phone.");pairingForm();
                }
                public void measurement(Float meters,Float azimuth,Float elevation,long nanos){if(currentGeneration!=generation||!running)return;PrecisionReading next=PrecisionReading.from(meters,capabilities.azimuth?azimuth:null,capabilities.elevation?elevation:null,nanos,SystemClock.elapsedRealtimeNanos());if(next!=null&&(latest==null||next.elapsedNanos>=latest.elapsedNanos)){latest=next;status.setText("Finding · live UWB");drawMeasurement();}}
                public void status(String message){if(currentGeneration==generation)status.setText(message);}
                public void failed(String message){if(currentGeneration!=generation)return;endSession(message);}
                public void disconnected(String message){if(currentGeneration!=generation)return;endSession(message);}
            });backend.prepare();
        }catch(RuntimeException|LinkageError unavailable){endSession("The UWB service could not start on this phone. Check system UWB settings and retry.");}
    }
    private void pairingForm(){
        setup.removeAllViews();LinearLayout card=card();setup.addView(card);
        TextView steps=text(controller?"1. Send your code to the target phone.\n2. Paste its reply below.\n3. Start finding on both phones.":"1. Paste the finder phone’s code.\n2. Send your reply back.\n3. Tap Start target and keep FieldKit open.",14,palette.foreground);card.addView(steps);
        if(controller&&capabilities.configs.contains(1)&&capabilities.configs.contains(4)){
            CheckBox older=new CheckBox(this);older.setText("Compatibility mode for older UWB phones");older.setTextSize(12);older.setTextColor(palette.muted);older.setChecked(legacy);older.setOnCheckedChangeListener((view,checked)->{legacy=checked;makeInvite();});card.addView(older);
        }
        codeHint=text("",12,palette.muted);codeHint.setPadding(0,dp(10),0,0);card.addView(codeHint);
        codeActions=row();card.addView(codeActions);Button copy=button("Copy code",v->copyCode());codeActions.addView(copy,new LinearLayout.LayoutParams(0,dp(44),1));Button share=button("Share code",v->shareCode());codeActions.addView(share,new LinearLayout.LayoutParams(0,dp(44),1));
        incoming=new EditText(this);incoming.setHint(controller?"Paste target’s reply code":"Paste finder’s pairing code");incoming.setTextColor(palette.foreground);incoming.setHintTextColor(palette.muted);incoming.setTextSize(13);incoming.setMaxLines(3);incoming.setSingleLine(false);incoming.setInputType(android.text.InputType.TYPE_CLASS_TEXT|android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS|android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE);incoming.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);incoming.setSaveEnabled(false);card.addView(incoming,new LinearLayout.LayoutParams(-1,dp(90)));
        importButton=button(controller?"Use target’s reply":"Use finder’s code",v->importCode());add(card,importButton,false);
        startButton=button(controller?"Start finding":"Start target",v->startFinding());add(card,startButton,true);startButton.setEnabled(false);
        add(card,button("Pair again",v->prepare(controller)),false);
        TextView privateCode=text("Keep pairing codes private. They expire after five minutes and are not saved to history.",11,palette.muted);privateCode.setPadding(0,dp(8),0,0);card.addView(privateCode);
        if(controller)makeInvite();else{codeHint.setText("Your reply appears after you import the finder’s code.");codeActions.setVisibility(View.GONE);}
    }
    private void makeInvite(){
        if(!prepared||codeHint==null)return;
        int config=!legacy&&capabilities.configs.contains(4)?4:capabilities.configs.contains(1)?1:0;
        if(config==0){endSession("This phone does not support a compatible one-to-one ranging profile.");return;}
        try{invite=UwbPairing.createInvite(localAddress,channel,preamble,config,phoneName(),capabilities.distance,capabilities.azimuth,System.currentTimeMillis());reply=null;peerAddress=null;outgoing=invite.code();codeHint.setText(config==4?"Your private pairing code is ready · secure ranging":"Your private pairing code is ready · legacy compatibility");codeActions.setVisibility(View.VISIBLE);if(startButton!=null)startButton.setEnabled(false);}
        catch(IllegalArgumentException error){endSession(error.getMessage());}
    }
    private void importCode(){
        if(!prepared)return;
        try{
            long now=System.currentTimeMillis();String code=incoming.getText().toString().trim();
            if(controller){reply=UwbPairing.parseReply(code,invite,now);if(!reply.distance)throw new IllegalArgumentException("The target does not support distance ranging.");peerAddress=reply.responderAddress();status.setText("Paired with "+reply.name);codeHint.setText("Target reply accepted. Tap Start finding when the target is ready.");}
            else{UwbPairing.Invite candidate=UwbPairing.parseInvite(code,now);if(!candidate.distance)throw new IllegalArgumentException("The finder does not support distance ranging.");if(!capabilities.configs.contains(candidate.configId))throw new IllegalArgumentException("This ranging profile is unsupported. Ask the finder to enable compatibility mode and send a new code.");if(!capabilities.channels.contains(candidate.channel))throw new IllegalArgumentException("The finder’s UWB channel is unavailable on this phone.");invite=candidate;reply=UwbPairing.createReply(invite,localAddress,phoneName(),capabilities.distance,capabilities.azimuth,now);peerAddress=invite.controllerAddress();outgoing=reply.code();codeHint.setText("Your reply is ready. Send it back, then tap Start target.");codeActions.setVisibility(View.VISIBLE);status.setText("Paired with "+invite.name);}
            incoming.setText("");startButton.setEnabled(true);dismissKeyboard();
        }catch(IllegalArgumentException error){new AlertDialog.Builder(this).setTitle("Pairing code not accepted").setMessage(error.getMessage()).setPositiveButton("OK",null).show();}
    }
    private void startFinding(){
        if(!prepared||backend==null||invite==null||peerAddress==null||scopeUsed)return;
        if(System.currentTimeMillis()>invite.expiresAtWall){endSession("Pairing code expired. Pair again.");return;}
        running=true;scopeUsed=true;latest=null;setup.setVisibility(View.GONE);stopButton.setVisibility(View.VISIBLE);status.setText(controller?"Connecting to target…":"Ready for the finder…");capability.setText(capabilities.azimuth?"Hold the phone upright. Aim the back of your phone toward the other device.":"This phone supplies distance only. Keep the other phone nearby with FieldKit open.");direction.setText("Waiting for a UWB measurement");drawMeasurement();backend.start(invite,peerAddress);
    }
    private void endSession(String message){
        resetBackend();generation++;status.setText(message==null?"Finding stopped":message);capability.setText("A new pairing session is needed to continue. UWB must be enabled on both phones.");latest=null;drawMeasurement();direction.setText("Pair again to continue");setup.setVisibility(View.VISIBLE);setup.removeAllViews();add(setup,button("Pair again",v->prepare(controller)),true);add(setup,button("UWB settings",v->openUwbSettings()),false);add(setup,button("Use signal finder",v->openSignalFinder()),false);stopButton.setVisibility(View.GONE);
    }
    private void resetBackend(){if(backend!=null){backend.stop();backend=null;}prepared=false;running=false;scopeUsed=false;invite=null;reply=null;peerAddress=null;outgoing="";}
    private void drawMeasurement(){
        if(bearing==null)return;long now=SystemClock.elapsedRealtimeNanos();boolean fresh=running&&latest!=null&&latest.fresh(now);
        bearing.angle=fresh&&latest.azimuthDegrees!=null?latest.azimuthDegrees:null;bearing.invalidate();
        if(fresh){updateText(distance,latest.distanceMeters==null?"—":String.format(Locale.getDefault(),"%.2f m",latest.distanceMeters));updateText(direction,latest.direction(now));updateText(age,"Live UWB measurement");}
        else{updateText(distance,"—");if(running){updateText(direction,"Waiting for a fresh measurement");updateText(age,latest==null?"Keep both phones nearby with FieldKit open.":"Last measurement is older than five seconds.");}else{updateText(age,"");if(scopeUsed||latest!=null)updateText(direction,"Finding paused");}}
    }
    private void copyCode(){if(outgoing.isEmpty())return;android.content.ClipboardManager clipboard=(android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE);ClipData clip=ClipData.newPlainText("Private FieldKit UWB pairing code",outgoing);if(Build.VERSION.SDK_INT>=33){PersistableBundle extras=new PersistableBundle();extras.putBoolean("android.content.extra.IS_SENSITIVE",true);clip.getDescription().setExtras(extras);}clipboard.setPrimaryClip(clip);Toast.makeText(this,"Pairing code copied",Toast.LENGTH_SHORT).show();}
    private void shareCode(){if(outgoing.isEmpty())return;Intent share=new Intent(Intent.ACTION_SEND);share.setType("text/plain");share.putExtra(Intent.EXTRA_TEXT,outgoing);startActivity(Intent.createChooser(share,"Send privately to the other phone"));}
    private String phoneName(){String model=Build.MODEL==null?"Android phone":Build.MODEL;return model.length()>40?model.substring(0,40):model;}
    private void openUwbSettings(){Intent intent=new Intent("android.settings.UWB_SETTINGS");if(intent.resolveActivity(getPackageManager())==null)intent=new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS);try{startActivity(intent);}catch(ActivityNotFoundException error){Toast.makeText(this,"Open system settings and enable UWB",Toast.LENGTH_LONG).show();}}
    private void openSignalFinder(){startActivity(new Intent(this,NearbyActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP|Intent.FLAG_ACTIVITY_SINGLE_TOP));finish();}
    private void dismissKeyboard(){android.view.inputmethod.InputMethodManager keyboard=(android.view.inputmethod.InputMethodManager)getSystemService(INPUT_METHOD_SERVICE);if(keyboard!=null)keyboard.hideSoftInputFromWindow(incoming.getWindowToken(),0);}
    private void help(){new AlertDialog.Builder(this).setTitle("Precision finding").setMessage("This checks your phone before pairing. UWB hardware, permission, an available ranging service and compatible peer are required.\n\nUse Find another phone on the finder, and Be found on the target. Exchange private pairing and reply codes, then start both phones. Codes expire after five minutes.\n\nDistance and direction come only from actual UWB reports. Aim the BACK of the upright phone toward the target. Some phones provide distance without direction. No arrow appears without a fresh measured angle.\n\nThis mode connects two compatible phones running FieldKit. It does not pair with Apple AirTags, Samsung SmartTags or tracking networks.\n\nLeaving an active session stops ranging. Pair again to restart. Setup codes stay only in memory and are never saved to diagnostic history.").setPositiveButton("Got it",null).show();}
    @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] results){super.onRequestPermissionsResult(request,permissions,results);if(request!=REQUEST_UWB)return;if(permission())prepare(controller);else{status.setText("UWB access was not allowed");capability.setText("Precision finding needs Nearby devices permission. You can retry or use signal finding.");}}
    @Override protected void onResume(){super.onResume();resumed=true;handler.removeCallbacks(tick);handler.post(tick);}
    @Override protected void onPause(){resumed=false;handler.removeCallbacks(tick);if(running)endSession("Finding paused while this screen is inactive. Pair again to continue.");super.onPause();}
    @Override protected void onDestroy(){resetBackend();handler.removeCallbacksAndMessages(null);if(store!=null)store.close();super.onDestroy();}
    private LinearLayout column(){LinearLayout view=new LinearLayout(this);view.setOrientation(LinearLayout.VERTICAL);return view;}
    private LinearLayout row(){LinearLayout view=new LinearLayout(this);view.setGravity(Gravity.CENTER_VERTICAL);return view;}
    private TextView text(String value,int size,int color){TextView view=new TextView(this);view.setText(value);view.setTextSize(size);view.setTextColor(color);return view;}
    private void updateText(TextView view,String value){if(!android.text.TextUtils.equals(view.getText(),value))view.setText(value);}
    private LinearLayout card(){LinearLayout view=column();view.setPadding(dp(16),dp(14),dp(16),dp(16));GradientDrawable background=new GradientDrawable();background.setColor(palette.surface);background.setCornerRadius(dp(14));background.setStroke(dp(1),palette.border);view.setBackground(background);return view;}
    private Button button(String title,View.OnClickListener listener){Button view=new Button(this);view.setText(title);view.setTextSize(14);view.setAllCaps(false);view.setTextColor(palette.accent);view.setOnClickListener(listener);return view;}
    private void add(LinearLayout parent,Button button,boolean primary){LinearLayout.LayoutParams params=new LinearLayout.LayoutParams(-1,dp(48));params.topMargin=dp(8);if(primary){GradientDrawable background=new GradientDrawable();background.setColor(palette.accent);background.setCornerRadius(dp(8));button.setBackground(background);button.setTextColor(palette.dark?Color.BLACK:Color.WHITE);}parent.addView(button,params);}
    private int dp(float value){return Math.round(value*getResources().getDisplayMetrics().density);}
    private final class BearingView extends View {
        Float angle;private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        BearingView(){super(PrecisionFinderActivity.this);setContentDescription("UWB target direction. No arrow until a real angle is measured.");}
        @Override protected void onDraw(Canvas canvas){super.onDraw(canvas);float x=getWidth()/2f,y=getHeight()/2f,r=Math.min(getWidth(),getHeight())*.38f;paint.setStyle(Paint.Style.STROKE);paint.setStrokeWidth(dp(2));paint.setColor(palette.border);canvas.drawCircle(x,y,r,paint);
            if(angle==null){paint.setColor(palette.muted);paint.setTextSize(dp(14));paint.setTextAlign(Paint.Align.CENTER);paint.setStyle(Paint.Style.FILL);canvas.drawText("Direction unavailable",x,y+dp(5),paint);return;}
            int save=canvas.save();canvas.rotate(angle,x,y);paint.setColor(palette.accent);paint.setStyle(Paint.Style.FILL);Path arrow=new Path();arrow.moveTo(x,y-r*.78f);arrow.lineTo(x+r*.45f,y-r*.12f);arrow.lineTo(x+r*.16f,y-r*.12f);arrow.lineTo(x+r*.16f,y+r*.65f);arrow.lineTo(x-r*.16f,y+r*.65f);arrow.lineTo(x-r*.16f,y-r*.12f);arrow.lineTo(x-r*.45f,y-r*.12f);arrow.close();canvas.drawPath(arrow,paint);canvas.restoreToCount(save);
        }
    }
}
