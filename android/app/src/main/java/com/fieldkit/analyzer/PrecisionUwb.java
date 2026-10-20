package com.fieldkit.analyzer;

import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import androidx.core.uwb.RangingCapabilities;
import androidx.core.uwb.RangingMeasurement;
import androidx.core.uwb.RangingParameters;
import androidx.core.uwb.RangingPosition;
import androidx.core.uwb.RangingResult;
import androidx.core.uwb.UwbAvailabilityCallback;
import androidx.core.uwb.UwbClientSessionScope;
import androidx.core.uwb.UwbComplexChannel;
import androidx.core.uwb.UwbControllerSessionScope;
import androidx.core.uwb.UwbDevice;
import androidx.core.uwb.UwbManager;
import androidx.core.uwb.exceptions.UwbHardwareNotAvailableException;
import androidx.core.uwb.exceptions.UwbServiceNotAvailableException;
import androidx.core.uwb.rxjava3.UwbClientSessionScopeRx;
import androidx.core.uwb.rxjava3.UwbManagerRx;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.disposables.CompositeDisposable;
import io.reactivex.rxjava3.schedulers.Schedulers;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Real UWB ranging only. Call from the foreground after the UWB hardware and permission checks. */
public final class PrecisionUwb {
    private static UwbManager applicationManager;
    private static PrecisionUwb availabilityOwner;

    public static final class Capabilities {
        public final boolean distance, azimuth, elevation;
        public final Set<Integer> configs, channels;

        private Capabilities(RangingCapabilities value) {
            distance = value.isDistanceSupported();
            azimuth = value.isAzimuthalAngleSupported();
            elevation = value.isElevationAngleSupported();
            configs = Collections.unmodifiableSet(new HashSet<Integer>(value.getSupportedConfigIds()));
            channels = Collections.unmodifiableSet(new HashSet<Integer>(value.getSupportedChannels()));
        }
    }

    public interface Listener {
        void ready(Capabilities caps, byte[] localAddress, int channel, int preamble);
        void measurement(Float distanceMeters, Float azimuthDegrees, Float elevationDegrees, long elapsedNanos);
        void status(String message);
        void failed(String message);
        void disconnected(String message);
    }

    private final Context context;
    private final boolean controller;
    private final Listener listener;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final CompositeDisposable subscriptions = new CompositeDisposable();
    private UwbManager manager;
    private UwbClientSessionScope scope;
    private Capabilities capabilities;
    private byte[] localAddress, peerAddress;
    private int channel, preamble;
    private int generation;
    private boolean preparing, used, ranging;
    private long lastMeasurementNanos;

    public PrecisionUwb(Context context, boolean controller, Listener listener) {
        if (context == null || listener == null) throw new IllegalArgumentException("Context and listener are required.");
        this.context = context.getApplicationContext();
        this.controller = controller;
        this.listener = listener;
    }

    /** Allocates a new one-session address asynchronously, without blocking the main thread. */
    public void prepare() {
        onMain(() -> {
            if (preparing || scope != null) return;
            if (Build.VERSION.SDK_INT < 31 || !context.getPackageManager().hasSystemFeature("android.hardware.uwb")) {
                listener.failed("Precision finding is unsupported on this phone. UWB hardware and Android 12 or later are required.");
                return;
            }
            final int request = ++generation;
            preparing = true;
            used = false;
            ranging = false;
            capabilities = null;
            localAddress = peerAddress = null;
            lastMeasurementNanos = 0;
            listener.status("Checking UWB availability and ranging capabilities…");
            try {
                // Stable AndroidX 1.0 has no close API. One application manager avoids accumulating
                // backend service bindings whenever the user visits this screen or pairs again.
                if (manager == null) manager = applicationManager(context);
                Single<? extends UwbClientSessionScope> allocation = controller
                        ? UwbManagerRx.controllerSessionScopeSingle(manager)
                        : UwbManagerRx.controleeSessionScopeSingle(manager);
                subscriptions.add(allocation.subscribeOn(Schedulers.io())
                        .timeout(10, TimeUnit.SECONDS)
                        .subscribe(value -> onMain(request, () -> allocated(request, value)),
                                error -> onMain(request, () -> fail(request, describe(error)))));
            } catch (Throwable error) {
                rethrowFatal(error);
                fail(request, describe(error));
            }
        });
    }

    private void allocated(int request, UwbClientSessionScope value) {
        try {
            Capabilities caps = new Capabilities(value.getRangingCapabilities());
            byte[] address = value.getLocalAddress().getAddress();
            if (!validAddress(address)) {
                fail(request, "The phone did not provide a usable UWB session address. Try again.");
                return;
            }
            int allocatedChannel = 0, allocatedPreamble = 0;
            if (controller) {
                UwbComplexChannel complex = ((UwbControllerSessionScope) value).getUwbComplexChannel();
                allocatedChannel = complex.getChannel();
                allocatedPreamble = complex.getPreambleIndex();
                if (!caps.channels.contains(allocatedChannel)) {
                    fail(request, "The UWB service selected an unsupported channel. Try again.");
                    return;
                }
            }
            scope = value;
            capabilities = caps;
            localAddress = address.clone();
            channel = allocatedChannel;
            preamble = allocatedPreamble;
            preparing = false;
            // The optional AOSP backend may still be binding when the manager is constructed.
            // Register after scope allocation so its service is ready to accept the observer.
            synchronized (PrecisionUwb.class) {
                availabilityOwner = this;
                manager.setUwbAvailabilityCallback(command -> main.post(command), (available, reason) -> {
                    if (request != generation || available || scope == null) return;
                    fail(request, reason == UwbAvailabilityCallback.STATE_CHANGE_REASON_COUNTRY_CODE_ERROR
                            ? "UWB is unavailable in the current region or the phone has no country setting."
                            : "UWB became unavailable. Turn on UWB, leave airplane mode, and try again.");
                });
            }
            listener.ready(caps, address.clone(), channel, preamble);
        } catch (Throwable error) {
            rethrowFatal(error);
            fail(request, describe(error));
        }
    }

    /** Starts a single-use session with parameters exchanged directly with the other device. */
    public void start(UwbPairing.Invite invite, byte[] address) {
        final byte[] requestedPeer = address == null ? null : address.clone();
        onMain(() -> {
            final int request = generation;
            if (scope == null || preparing) {
                listener.failed("Check UWB support and prepare a pairing before starting.");
                return;
            }
            if (used) {
                listener.failed("This UWB pairing has already been used. Create a new pairing to restart.");
                return;
            }
            try {
                if (invite == null || !validAddress(requestedPeer)) {
                    fail(request, "The other device's UWB pairing address is invalid.");
                    return;
                }
                if (Arrays.equals(localAddress, requestedPeer)) {
                    fail(request, "Choose a different UWB device. A phone cannot range to its own address.");
                    return;
                }
                if (!capabilities.distance) {
                    fail(request, "Distance ranging is unsupported by this phone's UWB service.");
                    return;
                }
                if ((invite.configId != RangingParameters.CONFIG_UNICAST_DS_TWR
                        && invite.configId != RangingParameters.CONFIG_PROVISIONED_UNICAST_DS_TWR)
                        || !capabilities.configs.contains(invite.configId)) {
                    fail(request, "This phone does not support the pairing's UWB ranging profile. Create a compatible pairing.");
                    return;
                }
                if (!capabilities.channels.contains(invite.channel)) {
                    fail(request, "This phone does not support the other device's UWB channel.");
                    return;
                }
                if (invite.expiresAtWall <= System.currentTimeMillis()) {
                    fail(request, "This UWB pairing has expired. Create a new pairing on the finding phone.");
                    return;
                }
                if (controller && (invite.channel != channel || invite.preambleIndex != preamble
                        || !Arrays.equals(invite.controllerAddress(), localAddress))) {
                    fail(request, "This pairing belongs to an earlier UWB session. Create a new pairing.");
                    return;
                }
                if (!controller && !Arrays.equals(invite.controllerAddress(), requestedPeer)) {
                    fail(request, "The UWB address does not match the finding phone's pairing.");
                    return;
                }
                byte[] key = invite.sessionKey();
                int expectedKeyLength = invite.configId == RangingParameters.CONFIG_PROVISIONED_UNICAST_DS_TWR ? 16 : 8;
                if (key == null || key.length != expectedKeyLength) {
                    fail(request, "The UWB pairing key is invalid. Exchange a new pairing directly with the other device.");
                    return;
                }
                RangingParameters parameters = new RangingParameters(invite.configId, invite.sessionId, 0,
                        key, null, new UwbComplexChannel(invite.channel, invite.preambleIndex),
                        Collections.singletonList(UwbDevice.createForAddress(requestedPeer)),
                        RangingParameters.RANGING_UPDATE_RATE_AUTOMATIC);
                peerAddress = requestedPeer;
                used = true;
                ranging = true;
                lastMeasurementNanos = 0;
                listener.status("Connecting to the paired UWB device…");
                subscriptions.add(UwbClientSessionScopeRx.rangingResultsObservable(scope, parameters)
                        .subscribeOn(Schedulers.io())
                        .subscribe(result -> onMain(request, () -> result(request, result)),
                                error -> onMain(request, () -> fail(request, describe(error))),
                                () -> onMain(request, () -> disconnect(request, "UWB ranging ended. Create a new pairing to reconnect."))));
            } catch (Throwable error) {
                rethrowFatal(error);
                fail(request, describe(error));
            }
        });
    }

    private void result(int request, RangingResult result) {
        if (!ranging || result == null) return;
        try {
            if (result instanceof RangingResult.RangingResultFailure) {
                fail(request, reason(((RangingResult.RangingResultFailure) result).getReason()));
                return;
            }
            if (result.getDevice() == null || result.getDevice().getAddress() == null
                    || !Arrays.equals(peerAddress, result.getDevice().getAddress().getAddress())) return;
            if (result instanceof RangingResult.RangingResultPeerDisconnected) {
                disconnect(request, reason(((RangingResult.RangingResultPeerDisconnected) result).getReason()));
            } else if (result instanceof RangingResult.RangingResultInitialized) {
                listener.status("Connected. Waiting for a UWB position measurement…");
            } else if (result instanceof RangingResult.RangingResultPosition) {
                RangingPosition position = ((RangingResult.RangingResultPosition) result).getPosition();
                if (position == null) return;
                long timestamp = position.getElapsedRealtimeNanos();
                long now = SystemClock.elapsedRealtimeNanos();
                // Reject old, reordered, or invalid observations instead of displaying an old arrow as live.
                if (timestamp <= lastMeasurementNanos || timestamp <= 0 || timestamp > now
                        || now - timestamp > TimeUnit.SECONDS.toNanos(5)) return;
                Float distance = measurement(position.getDistance(), 0, Float.MAX_VALUE);
                Float azimuth = capabilities.azimuth ? measurement(position.getAzimuth(), -180, 180) : null;
                Float elevation = capabilities.elevation ? measurement(position.getElevation(), -90, 90) : null;
                if (distance == null && azimuth == null && elevation == null) return;
                lastMeasurementNanos = timestamp;
                listener.measurement(distance, azimuth, elevation, timestamp);
            }
        } catch (Throwable error) {
            rethrowFatal(error);
            fail(request, describe(error));
        }
    }

    /** Cancels allocation or ranging. This also invalidates the one-session pairing address. */
    public void stop() {
        onMain(() -> {
            ++generation;
            reset();
        });
    }

    private void reset() {
        preparing = false;
        ranging = false;
        used = true;
        scope = null;
        capabilities = null;
        localAddress = peerAddress = null;
        try { subscriptions.clear(); }
        catch (Throwable error) { rethrowFatal(error); }
        synchronized (PrecisionUwb.class) {
            // A stopped older screen must not unregister a newer screen's observer.
            if (manager != null && availabilityOwner == this) {
                availabilityOwner = null;
                try { manager.clearUwbAvailabilityCallback(); }
                catch (Throwable error) { rethrowFatal(error); }
            }
        }
    }

    private static synchronized UwbManager applicationManager(Context context) {
        if (applicationManager == null) applicationManager = UwbManager.createInstance(context);
        return applicationManager;
    }

    private void fail(int request, String message) {
        if (request != generation) return;
        ++generation;
        reset();
        listener.failed(message);
    }

    private void disconnect(int request, String message) {
        if (request != generation) return;
        ++generation;
        reset();
        listener.disconnected(message);
    }

    private void onMain(Runnable action) {
        if (Looper.myLooper() == main.getLooper()) action.run();
        else main.post(action);
    }

    private void onMain(int request, Runnable action) {
        onMain(() -> { if (request == generation) action.run(); });
    }

    private static boolean validAddress(byte[] value) { return value != null && (value.length == 2 || value.length == 8); }

    private static Float measurement(RangingMeasurement value, float min, float max) {
        if (value == null) return null;
        float number = value.getValue();
        return Float.isNaN(number) || Float.isInfinite(number) || number < min || number > max ? null : number;
    }

    private static String reason(int value) {
        switch (value) {
            case RangingResult.RANGING_FAILURE_REASON_BAD_PARAMETERS:
                return "The devices rejected the UWB parameters. Create a new compatible pairing.";
            case RangingResult.RANGING_FAILURE_REASON_FAILED_TO_START:
                return "UWB could not start. Keep both apps open, check UWB is on, and create a new pairing.";
            case RangingResult.RANGING_FAILURE_REASON_STOPPED_BY_PEER:
                return "The other device stopped UWB ranging. Create a new pairing to reconnect.";
            case RangingResult.RANGING_FAILURE_REASON_STOPPED_BY_LOCAL:
                return "UWB ranging stopped on this phone.";
            case RangingResult.RANGING_FAILURE_REASON_SYSTEM_POLICY:
                return "Android stopped UWB ranging. Check UWB settings and keep both apps in the foreground.";
            case RangingResult.RANGING_FAILURE_REASON_MAX_RR_RETRY_REACHED:
                return "The paired device stopped responding. Move closer and create a new pairing.";
            default:
                return "UWB ranging stopped. Check both devices are ready and create a new pairing.";
        }
    }

    private static String describe(Throwable error) {
        Throwable cause = error;
        for (int i = 0; cause != null && i < 10; i++, cause = cause.getCause()) {
            if (cause instanceof SecurityException) return "UWB access was denied. Allow Nearby devices in app settings and try again.";
            if (cause instanceof UwbHardwareNotAvailableException) return "Precision finding is unsupported on this phone. No usable UWB hardware was found.";
            if (cause instanceof UwbServiceNotAvailableException) return "UWB is unavailable. Turn on UWB, leave airplane mode, and check your phone's regional support.";
            if (cause instanceof TimeoutException) return "The UWB service did not respond. Check that UWB is enabled and try again.";
            if (cause instanceof LinkageError) return "The phone's UWB service is incompatible with this ranging library. Check Android and Google Play services updates.";
            if (cause instanceof IllegalArgumentException) return "The UWB service rejected the pairing parameters. Create a new compatible pairing.";
        }
        // Do not expose pairing keys, addresses, or raw backend exception messages in errors or logs.
        return "UWB could not start or continue. Check that UWB is enabled and both devices are ready, then create a new pairing.";
    }

    private static void rethrowFatal(Throwable error) {
        if (error instanceof VirtualMachineError) throw (VirtualMachineError) error;
        if (error instanceof ThreadDeath) throw (ThreadDeath) error;
    }
}
