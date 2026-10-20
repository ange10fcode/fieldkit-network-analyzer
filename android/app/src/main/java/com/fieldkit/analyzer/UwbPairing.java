package com.fieldkit.analyzer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashSet;
import java.util.Iterator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONException;
import org.json.JSONObject;

/** Short-lived, explicitly shared connection parameters for one UWB peer. Never persisted here. */
public final class UwbPairing {
    public static final String PREFIX = "FKUWB1:";
    public static final long INVITE_LIFETIME_MILLIS = 5 * 60 * 1000L;
    public static final long MAX_LIFETIME_MILLIS = 10 * 60 * 1000L;
    public static final int MAX_CODE_CHARS = 2048;
    private static final long CLOCK_SKEW_MILLIS = 30 * 1000L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String INVITE_FIELDS = "|version|type|role|sessionId|nonce|controllerAddress|channel|preambleIndex|configId|sessionKey|createdAtWall|expiresAtWall|name|distance|azimuth|";
    private static final String REPLY_FIELDS = "|version|type|role|sessionId|nonce|controllerAddress|responderAddress|channel|preambleIndex|configId|createdAtWall|expiresAtWall|name|distance|azimuth|proof|";

    private UwbPairing() {}

    public static final class Invite {
        public final int sessionId, channel, preambleIndex, configId;
        public final String nonce, controllerAddressHex, sessionKeyHex, name;
        public final long createdAtWall, expiresAtWall;
        public final boolean distance, azimuth;

        private Invite(int sessionId, String nonce, String address, int channel, int preamble,
                       int config, String key, long created, long expires, String name,
                       boolean distance, boolean azimuth) {
            this.sessionId = sessionId; this.nonce = nonce; controllerAddressHex = address;
            this.channel = channel; preambleIndex = preamble; configId = config;
            sessionKeyHex = key; createdAtWall = created; expiresAtWall = expires;
            this.name = name; this.distance = distance; this.azimuth = azimuth;
        }
        public byte[] controllerAddress() { return fromHex(controllerAddressHex); }
        public byte[] sessionKey() { return fromHex(sessionKeyHex); }
        public String code() { return encodeInvite(this); }
        @Override public String toString() { return "UWB invitation (connection details hidden)"; }
    }

    public static final class Reply {
        public final int sessionId, channel, preambleIndex, configId;
        public final String nonce, controllerAddressHex, responderAddressHex, name, proofHex;
        public final long createdAtWall, expiresAtWall;
        public final boolean distance, azimuth;

        private Reply(int session, String nonce, String controller, String responder, int channel,
                      int preamble, int config, long created, long expires, String name,
                      boolean distance, boolean azimuth, String proof) {
            sessionId = session; this.nonce = nonce; controllerAddressHex = controller;
            responderAddressHex = responder; this.channel = channel; preambleIndex = preamble;
            configId = config; createdAtWall = created; expiresAtWall = expires;
            this.name = name; this.distance = distance; this.azimuth = azimuth; proofHex = proof;
        }
        public byte[] responderAddress() { return fromHex(responderAddressHex); }
        public String code() { return encodeReply(this); }
        @Override public String toString() { return "UWB reply (connection details hidden)"; }
    }

    public static Invite createInvite(byte[] controllerAddress, int channel, int preambleIndex,
                                      int configId, String name, boolean distance, boolean azimuth,
                                      long nowWall) {
        String address = addressHex(controllerAddress);
        validateRadio(channel, preambleIndex, configId);
        validateName(name);
        if (nowWall <= 0 || nowWall > Long.MAX_VALUE - INVITE_LIFETIME_MILLIS)
            throw invalid("The phone clock is invalid.");
        int sessionId;
        do { sessionId = RANDOM.nextInt(); } while (sessionId == 0);
        byte[] nonce = new byte[16], key = new byte[configId == 1 ? 8 : 16];
        RANDOM.nextBytes(nonce); RANDOM.nextBytes(key);
        return new Invite(sessionId, hex(nonce), address, channel, preambleIndex, configId,
                hex(key), nowWall, nowWall + INVITE_LIFETIME_MILLIS, name, distance, azimuth);
    }

    public static Invite parseInvite(String code, long nowWall) {
        try {
            JSONObject json = decode(code);
            validateEnvelope(json, "invite", "controller", INVITE_FIELDS);
            int session = integer(json, "sessionId");
            if (session == 0) throw invalid("The session ID is invalid.");
            String nonce = fixedHex(string(json, "nonce"), 16, "Invitation identifier");
            String address = addressHex(fromHex(string(json, "controllerAddress")));
            int channel = integer(json, "channel"), preamble = integer(json, "preambleIndex"), config = integer(json, "configId");
            validateRadio(channel, preamble, config);
            String key = fixedHex(string(json, "sessionKey"), config == 1 ? 8 : 16, "Session key");
            long created = longInteger(json, "createdAtWall"), expires = longInteger(json, "expiresAtWall");
            validateTime(created, expires, nowWall);
            String name = string(json, "name"); validateName(name);
            return new Invite(session, nonce, address, channel, preamble, config, key, created,
                    expires, name, capability(json, "distance"), capability(json, "azimuth"));
        } catch (JSONException e) { throw invalid("The invitation is incomplete or malformed."); }
    }

    public static Reply createReply(Invite invite, byte[] responderAddress, String name,
                                    boolean distance, boolean azimuth, long nowWall) {
        if (invite == null) throw invalid("An invitation is required.");
        validateTime(invite.createdAtWall, invite.expiresAtWall, nowWall);
        validateTime(nowWall, invite.expiresAtWall, nowWall);
        String responder = addressHex(responderAddress); validateName(name);
        if (responder.equals(invite.controllerAddressHex))
            throw invalid("The two UWB devices must have different addresses.");
        Reply reply = new Reply(invite.sessionId, invite.nonce, invite.controllerAddressHex, responder,
                invite.channel, invite.preambleIndex, invite.configId, nowWall,
                invite.expiresAtWall, name, distance, azimuth, "");
        return new Reply(reply.sessionId, reply.nonce, reply.controllerAddressHex, responder,
                reply.channel, reply.preambleIndex, reply.configId, nowWall, reply.expiresAtWall,
                name, distance, azimuth, hex(replyProof(invite, reply)));
    }

    public static Reply parseReply(String code, Invite invite, long nowWall) {
        if (invite == null) throw invalid("Create an invitation before accepting a reply.");
        validateTime(invite.createdAtWall, invite.expiresAtWall, nowWall);
        try {
            JSONObject json = decode(code);
            validateEnvelope(json, "reply", "responder", REPLY_FIELDS);
            int session = integer(json, "sessionId");
            String nonce = fixedHex(string(json, "nonce"), 16, "Invitation identifier");
            String controller = addressHex(fromHex(string(json, "controllerAddress")));
            int channel = integer(json, "channel"), preamble = integer(json, "preambleIndex"), config = integer(json, "configId");
            validateRadio(channel, preamble, config);
            long created = longInteger(json, "createdAtWall"), expires = longInteger(json, "expiresAtWall");
            validateTime(created, expires, nowWall);
            if (session != invite.sessionId || !nonce.equals(invite.nonce)
                    || !controller.equals(invite.controllerAddressHex) || expires != invite.expiresAtWall
                    || channel != invite.channel || preamble != invite.preambleIndex || config != invite.configId
                    || created < invite.createdAtWall - CLOCK_SKEW_MILLIS)
                throw invalid("This reply belongs to a different invitation.");
            String responder = addressHex(fromHex(string(json, "responderAddress")));
            if (responder.equals(controller)) throw invalid("The two UWB devices must have different addresses.");
            String name = string(json, "name"); validateName(name);
            String proof = fixedHex(string(json, "proof"), 32, "Reply verification");
            Reply reply = new Reply(session, nonce, controller, responder, channel, preamble, config,
                    created, expires, name, capability(json, "distance"), capability(json, "azimuth"), proof);
            if (!MessageDigest.isEqual(fromHex(proof), replyProof(invite, reply)))
                throw invalid("The reply does not match the invitation or was changed. Ask for a new reply.");
            return reply;
        } catch (JSONException e) { throw invalid("The reply is incomplete or malformed."); }
    }

    public static String encodeInvite(Invite invite) {
        if (invite == null) throw invalid("An invitation is required.");
        try {
            return encode(common("invite", "controller", invite.sessionId, invite.nonce,
                    invite.controllerAddressHex, invite.channel, invite.preambleIndex, invite.configId,
                    invite.createdAtWall, invite.expiresAtWall, invite.name, invite.distance, invite.azimuth)
                    .put("sessionKey", invite.sessionKeyHex));
        } catch (JSONException e) { throw invalid("Could not create an invitation."); }
    }

    public static String encodeReply(Reply reply) {
        if (reply == null) throw invalid("A reply is required.");
        try {
            return encode(common("reply", "responder", reply.sessionId, reply.nonce,
                    reply.controllerAddressHex, reply.channel, reply.preambleIndex, reply.configId,
                    reply.createdAtWall, reply.expiresAtWall, reply.name, reply.distance, reply.azimuth)
                    .put("responderAddress", reply.responderAddressHex).put("proof", reply.proofHex));
        } catch (JSONException e) { throw invalid("Could not create a reply."); }
    }

    private static JSONObject common(String type, String role, int session, String nonce,
                                     String controller, int channel, int preamble, int config,
                                     long created, long expires, String name, boolean distance,
                                     boolean azimuth) throws JSONException {
        return new JSONObject().put("version", 1).put("type", type).put("role", role)
                .put("sessionId", session).put("nonce", nonce).put("controllerAddress", controller)
                .put("channel", channel).put("preambleIndex", preamble).put("configId", config)
                .put("createdAtWall", created).put("expiresAtWall", expires).put("name", name)
                .put("distance", distance).put("azimuth", azimuth);
    }

    private static String encode(JSONObject json) {
        String code = PREFIX + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.toString().getBytes(StandardCharsets.UTF_8));
        if (code.length() > MAX_CODE_CHARS) throw invalid("The connection code is too long.");
        return code;
    }

    private static JSONObject decode(String code) throws JSONException {
        if (code == null || !code.startsWith(PREFIX) || code.length() > MAX_CODE_CHARS
                || code.length() == PREFIX.length()) throw invalid("Paste a valid FieldKit UWB connection code.");
        String payload = code.substring(PREFIX.length());
        if (!payload.matches("[A-Za-z0-9_-]+")) throw invalid("The connection code is malformed.");
        byte[] raw;
        try { raw = Base64.getUrlDecoder().decode(payload); }
        catch (IllegalArgumentException e) { throw invalid("The connection code is malformed."); }
        if (raw.length > 1536 || !Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(payload))
            throw invalid("The connection code is malformed.");
        try {
            String json = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
            validateFlatJson(json);
            return new JSONObject(json);
        } catch (CharacterCodingException e) { throw invalid("The connection code contains invalid text."); }
    }

    // Android's JSONObject accepts some non-JSON syntax and duplicate fields. Keep this wire
    // format to a small, flat object so every supported Android version reads identical values.
    private static void validateFlatJson(String json) {
        int at = whitespace(json, 0);
        if (at >= json.length() || json.charAt(at++) != '{') throw malformedJson();
        HashSet<String> keys = new HashSet<>();
        at = whitespace(json, at);
        if (at < json.length() && json.charAt(at) == '}') {
            if (whitespace(json, at + 1) != json.length()) throw malformedJson();
            return;
        }
        while (at < json.length()) {
            if (json.charAt(at++) != '"') throw malformedJson();
            int start = at;
            while (at < json.length() && ((json.charAt(at) >= 'a' && json.charAt(at) <= 'z')
                    || (json.charAt(at) >= 'A' && json.charAt(at) <= 'Z'))) at++;
            if (at == start || at >= json.length() || json.charAt(at) != '"'
                    || !keys.add(json.substring(start, at)) || keys.size() > 20) throw malformedJson();
            at = whitespace(json, at + 1);
            if (at >= json.length() || json.charAt(at++) != ':') throw malformedJson();
            at = whitespace(json, at);
            if (at >= json.length()) throw malformedJson();
            if (json.charAt(at) == '"') at = jsonStringEnd(json, at + 1);
            else if (json.startsWith("true", at)) at += 4;
            else if (json.startsWith("false", at)) at += 5;
            else {
                if (json.charAt(at) == '-') at++;
                if (at >= json.length() || json.charAt(at) < '0' || json.charAt(at) > '9') throw malformedJson();
                if (json.charAt(at) == '0') at++;
                else while (at < json.length() && json.charAt(at) >= '0' && json.charAt(at) <= '9') at++;
            }
            at = whitespace(json, at);
            if (at >= json.length()) throw malformedJson();
            char next = json.charAt(at++);
            if (next == '}') {
                if (whitespace(json, at) != json.length()) throw malformedJson();
                return;
            }
            if (next != ',') throw malformedJson();
            at = whitespace(json, at);
        }
        throw malformedJson();
    }
    private static int jsonStringEnd(String json, int at) {
        while (at < json.length()) {
            char value = json.charAt(at++);
            if (value == '"') return at;
            if (value < 32) throw malformedJson();
            if (value == '\\') {
                if (at >= json.length()) throw malformedJson();
                char escape = json.charAt(at++);
                if (escape == 'u') {
                    if (at + 4 > json.length()) throw malformedJson();
                    for (int i = 0; i < 4; i++) if (asciiHex(json.charAt(at++)) < 0) throw malformedJson();
                } else if ("\"\\/bfnrt".indexOf(escape) < 0) throw malformedJson();
            }
        }
        throw malformedJson();
    }
    private static int whitespace(String json, int at) {
        while (at < json.length() && " \t\r\n".indexOf(json.charAt(at)) >= 0) at++;
        return at;
    }
    private static IllegalArgumentException malformedJson() { return invalid("The connection code contains malformed connection details."); }

    private static void validateEnvelope(JSONObject json, String type, String role, String fields) throws JSONException {
        if (integer(json, "version") != 1) throw invalid("This connection code version is unsupported.");
        if (!type.equals(string(json, "type")) || !role.equals(string(json, "role")))
            throw invalid("Use the correct invitation or reply code for this step.");
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (key.indexOf('|') >= 0 || !fields.contains("|" + key + "|")) throw invalid("The connection code contains unsupported fields.");
        }
    }

    private static int integer(JSONObject json, String key) throws JSONException {
        long value = longInteger(json, key);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) throw invalid("The connection code contains an invalid number.");
        return (int) value;
    }
    private static long longInteger(JSONObject json, String key) throws JSONException {
        Object value = json.get(key);
        if (!(value instanceof Integer) && !(value instanceof Long)) throw invalid("The connection code contains an invalid number.");
        return ((Number) value).longValue();
    }
    private static String string(JSONObject json, String key) throws JSONException {
        Object value = json.get(key);
        if (!(value instanceof String)) throw invalid("The connection code contains invalid text.");
        return (String) value;
    }
    private static boolean capability(JSONObject json, String key) throws JSONException {
        if (!json.has(key)) return false;
        Object value = json.get(key);
        if (!(value instanceof Boolean)) throw invalid("The connection code contains invalid capabilities.");
        return (Boolean) value;
    }
    private static void validateRadio(int channel, int preamble, int config) {
        if (channel != 5 && channel != 9) throw invalid("This UWB channel is unsupported.");
        if (preamble < 9 || preamble > 12) throw invalid("This UWB preamble is unsupported.");
        if (config != 1 && config != 4) throw invalid("This UWB session configuration is unsupported.");
    }
    private static void validateTime(long created, long expires, long now) {
        if (now <= 0 || created <= 0 || expires <= created || expires - created > MAX_LIFETIME_MILLIS)
            throw invalid("The connection code has invalid dates.");
        if (created > now && created - now > CLOCK_SKEW_MILLIS)
            throw invalid("Check the clocks on both phones and create a new invitation.");
        if (now >= expires) throw invalid("This connection code expired. Create a new invitation.");
    }
    private static void validateName(String name) {
        if (name == null || name.isEmpty() || name.codePointCount(0, name.length()) > 48)
            throw invalid("Use a device name of 1 to 48 characters.");
        for (int i = 0; i < name.length();) {
            int cp = name.codePointAt(i), type = Character.getType(cp);
            if (Character.isISOControl(cp) || type == Character.FORMAT || type == Character.SURROGATE
                    || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR)
                throw invalid("Device names cannot contain hidden or control characters.");
            i += Character.charCount(cp);
        }
        if (name.trim().isEmpty()) throw invalid("Enter a device name.");
    }
    private static String fixedHex(String value, int bytes, String label) {
        byte[] decoded = fromHex(value);
        if (decoded.length != bytes) throw invalid(label + " has the wrong length.");
        return hex(decoded);
    }
    /** Every reply parameter is bound to this invitation's session key, including capabilities. */
    private static byte[] replyProof(Invite invite, Reply reply) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream data = new DataOutputStream(bytes);
            data.writeInt(1); writeText(data, "reply"); writeText(data, "responder");
            data.writeInt(reply.sessionId); writeText(data, reply.nonce);
            writeText(data, reply.controllerAddressHex); writeText(data, reply.responderAddressHex);
            data.writeInt(reply.channel); data.writeInt(reply.preambleIndex); data.writeInt(reply.configId);
            data.writeLong(reply.createdAtWall); data.writeLong(reply.expiresAtWall);
            writeText(data, reply.name); data.writeBoolean(reply.distance); data.writeBoolean(reply.azimuth);
            data.flush();
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(invite.sessionKey(), "HmacSHA256"));
            return mac.doFinal(bytes.toByteArray());
        } catch (IOException | GeneralSecurityException e) {
            throw invalid("This phone could not verify the UWB connection details.");
        }
    }
    private static void writeText(DataOutputStream data, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        data.writeInt(bytes.length); data.write(bytes);
    }
    private static String addressHex(byte[] address) {
        if (address == null || (address.length != 2 && address.length != 8))
            throw invalid("UWB addresses must contain 2 or 8 bytes.");
        return hex(address);
    }
    public static String hex(byte[] bytes) {
        if (bytes == null || bytes.length == 0 || bytes.length > 64) throw invalid("Invalid binary connection details.");
        char[] out = new char[bytes.length * 2]; String chars = "0123456789ABCDEF";
        for (int i = 0; i < bytes.length; i++) { int value = bytes[i] & 255; out[2*i] = chars.charAt(value >>> 4); out[2*i+1] = chars.charAt(value & 15); }
        return new String(out);
    }
    public static byte[] fromHex(String value) {
        if (value == null || value.isEmpty() || value.length() > 128 || (value.length() & 1) != 0)
            throw invalid("The connection code contains invalid hexadecimal data.");
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            char a = value.charAt(2*i), b = value.charAt(2*i+1);
            int high = asciiHex(a), low = asciiHex(b);
            if (high < 0 || low < 0) throw invalid("The connection code contains invalid hexadecimal data.");
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }
    private static int asciiHex(char value) {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        return -1;
    }
    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}
