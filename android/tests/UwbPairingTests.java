package com.fieldkit.analyzer;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import org.json.JSONObject;

/** Exercises the actual shared-code boundary, expiry rules and authenticated peer binding. */
public final class UwbPairingTests {
    private static int checks;
    private static final long NOW = 1800000000000L;
    private static final byte[] HOST = { 0x12, 0x34 }, PEER = { 0x56, 0x78 };
    private interface Checked { void run() throws Exception; }
    private static void check(boolean value, String label) { checks++; if (!value) throw new AssertionError(label); }
    private static void bad(Checked action, String label) throws Exception {
        checks++;
        try { action.run(); } catch (IllegalArgumentException expected) { return; }
        throw new AssertionError(label + " was accepted");
    }
    private static JSONObject json(String code) throws Exception {
        return new JSONObject(new String(Base64.getUrlDecoder().decode(code.substring(UwbPairing.PREFIX.length())), StandardCharsets.UTF_8));
    }
    private static String code(JSONObject value) { return raw(value.toString()); }
    private static String raw(String value) {
        return UwbPairing.PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
    private static String change(String code, String field, Object value) throws Exception { return code(json(code).put(field, value)); }
    private static UwbPairing.Invite invite(int config) { return UwbPairing.createInvite(HOST, 9, 10, config, "Workshop phone", true, true, NOW); }

    public static void main(String[] args) throws Exception {
        UwbPairing.Invite host = invite(4), restored = UwbPairing.parseInvite(host.code(), NOW + 1000);
        check(host.code().startsWith("FKUWB1:"), "Versioned connection prefix");
        check(host.sessionId != 0, "Random session is not the reserved unset value");
        check(restored.sessionId == host.sessionId && restored.nonce.equals(host.nonce), "Host session survives code sharing");
        check(restored.channel == 9 && restored.preambleIndex == 10 && restored.configId == 4, "Radio profile survives sharing");
        check(restored.name.equals("Workshop phone") && restored.distance && restored.azimuth, "Real host capabilities and name survive sharing");
        check(Arrays.equals(restored.controllerAddress(), HOST), "Binary UWB address survives sharing");
        check(host.sessionKey().length == 16 && host.nonce.length() == 32, "Provisioned STS key and independent nonce have required sizes");
        check(host.expiresAtWall - host.createdAtWall == 300000, "New session invites expire after five minutes");
        check(host.code().length() < UwbPairing.MAX_CODE_CHARS, "Invitation stays inside input size bound");
        UwbPairing.Invite second = invite(4);
        check(!host.nonce.equals(second.nonce) && !host.sessionKeyHex.equals(second.sessionKeyHex), "Fresh sessions use independent random credentials");
        byte[] copy = host.sessionKey(); copy[0] ^= 127;
        check(!Arrays.equals(copy, host.sessionKey()), "Returned key array cannot corrupt host session");
        byte[] addressCopy = host.controllerAddress(); addressCopy[0] = 0;
        check(host.controllerAddress()[0] == 0x12, "Returned address array cannot corrupt host session");
        check(!host.toString().contains(host.sessionKeyHex) && !host.toString().contains(host.nonce), "Incidental logging does not reveal invitation credentials");
        UwbPairing.Invite legacy = invite(1);
        check(legacy.sessionKey().length == 8 && UwbPairing.parseInvite(legacy.code(), NOW).configId == 1, "Explicit legacy static STS uses eight bytes");
        UwbPairing.Invite longAddress = UwbPairing.createInvite(UwbPairing.fromHex("0123456789abcdef"), 5, 12, 4, "Phone \uD83D\uDCF1", true, false, NOW);
        check(longAddress.controllerAddressHex.equals("0123456789ABCDEF"), "Extended UWB addresses normalize without changing bytes");
        check(UwbPairing.parseInvite(longAddress.code(), NOW).name.equals("Phone \uD83D\uDCF1"), "Printable Unicode names round-trip");
        check(UwbPairing.parseInvite(change(host.code(), "controllerAddress", "abcd"), NOW).controllerAddressHex.equals("ABCD"), "Hex case is semantically normalized");
        JSONObject capabilitiesOmitted = json(host.code()); capabilitiesOmitted.remove("distance"); capabilitiesOmitted.remove("azimuth");
        check(!UwbPairing.parseInvite(code(capabilitiesOmitted), NOW).distance, "Omitted capabilities are never assumed available");
        check(!UwbPairing.parseInvite(code(capabilitiesOmitted), NOW).azimuth, "Omitted angle support is unknown rather than true");

        UwbPairing.Reply reply = UwbPairing.createReply(restored, PEER, "Target phone", true, false, NOW + 1000);
        UwbPairing.Reply accepted = UwbPairing.parseReply(reply.code(), host, NOW + 2000);
        check(Arrays.equals(accepted.responderAddress(), PEER) && accepted.name.equals("Target phone"), "Authenticated responder details survive sharing");
        check(accepted.distance && !accepted.azimuth, "Distance-only responder does not invent azimuth support");
        check(accepted.expiresAtWall == host.expiresAtWall && accepted.proofHex.length() == 64, "Reply retains invitation deadline and SHA-256 proof");
        check(!json(reply.code()).has("sessionKey"), "Responder reply never republishes the host session key");
        check(!reply.toString().contains(reply.nonce) && !reply.toString().contains(reply.proofHex), "Incidental reply logging hides connection details");
        byte[] peerCopy = reply.responderAddress(); peerCopy[0] = 0;
        check(reply.responderAddress()[0] == 0x56, "Returned peer address is defensive");
        UwbPairing.Reply staticReply = UwbPairing.createReply(legacy, PEER, "Legacy peer", true, true, NOW + 1000);
        check(UwbPairing.parseReply(staticReply.code(), legacy, NOW + 2000).configId == 1, "Legacy sessions also authenticate reply parameters");
        bad(() -> UwbPairing.parseReply(reply.code(), second, NOW + 2000), "Reply from another invitation");
        UwbPairing.Invite sameSessionWrongKey = UwbPairing.parseInvite(change(host.code(), "sessionKey", "000102030405060708090A0B0C0D0E0F"), NOW);
        bad(() -> UwbPairing.parseReply(reply.code(), sameSessionWrongKey, NOW + 2000), "Reply authenticated with another key");
        for (String field : new String[]{"sessionId", "nonce", "controllerAddress", "responderAddress", "channel", "preambleIndex", "configId", "createdAtWall", "expiresAtWall", "name", "distance", "azimuth", "proof"}) {
            Object replacement;
            switch (field) {
                case "sessionId": replacement = host.sessionId == Integer.MAX_VALUE ? 1 : host.sessionId + 1; break;
                case "nonce": replacement = "00000000000000000000000000000000"; break;
                case "controllerAddress": replacement = "1235"; break;
                case "responderAddress": replacement = "5679"; break;
                case "channel": replacement = 5; break;
                case "preambleIndex": replacement = 11; break;
                case "configId": replacement = 1; break;
                case "createdAtWall": replacement = NOW + 1100; break;
                case "expiresAtWall": replacement = host.expiresAtWall - 1; break;
                case "name": replacement = "Changed peer"; break;
                case "distance": replacement = false; break;
                case "azimuth": replacement = true; break;
                default: replacement = "0000000000000000000000000000000000000000000000000000000000000000";
            }
            final String modified = change(reply.code(), field, replacement);
            bad(() -> UwbPairing.parseReply(modified, host, NOW + 2000), "Changed authenticated field " + field);
        }
        bad(() -> UwbPairing.parseReply(change(reply.code(), "sessionKey", host.sessionKeyHex), host, NOW + 2000), "Reply that includes a secret field");
        JSONObject missingProof = json(reply.code()); missingProof.remove("proof");
        bad(() -> UwbPairing.parseReply(code(missingProof), host, NOW + 2000), "Unsigned responder reply");
        bad(() -> UwbPairing.createReply(host, HOST, "Self", true, true, NOW + 1000), "Controller and responder with same address");
        bad(() -> UwbPairing.parseReply(change(reply.code(), "responderAddress", host.controllerAddressHex), host, NOW + 2000), "Reply falsely identifying the controller as its peer");
        bad(() -> UwbPairing.parseReply(reply.code(), null, NOW), "Reply accepted without a pending invitation");
        bad(() -> UwbPairing.parseInvite(reply.code(), NOW), "Reply passed as invitation");
        bad(() -> UwbPairing.parseReply(host.code(), host, NOW), "Invitation passed as reply");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "version", 2), NOW), "Unknown version");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "role", "responder"), NOW), "Wrong role");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "sessionId", 0), NOW), "Reserved session ID");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "sessionId", 2147483648L), NOW), "Session ID outside 32-bit range");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "sessionId", "1"), NOW), "Coerced session ID string");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "channel", 9.5), NOW), "Fractional channel");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "channel", 6), NOW), "Unsupported channel");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "preambleIndex", 8), NOW), "Unsupported preamble");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "configId", 3), NOW), "Unsupported profile");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "sessionKey", legacy.sessionKeyHex), NOW), "Wrong provisioned key length");
        bad(() -> UwbPairing.parseInvite(change(legacy.code(), "sessionKey", host.sessionKeyHex), NOW), "Wrong static key length");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "nonce", "aabb"), NOW), "Short invitation nonce");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "controllerAddress", "112233"), NOW), "Invalid three-byte UWB address");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "controllerAddress", "0x1234"), NOW), "Address with hexadecimal prefix");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "distance", "true"), NOW), "Coerced capability string");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "name", JSONObject.NULL), NOW), "Null device name");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "name", "Target\nForged status"), NOW), "Control characters in device name");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "name", "Target\u202Eabc"), NOW), "Bidirectional display control in device name");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "name", repeat('x', 49)), NOW), "Overlong device name");
        bad(() -> UwbPairing.createInvite(HOST, 9, 10, 4, "\uD800", true, true, NOW), "Unpaired surrogate in name");
        bad(() -> UwbPairing.createInvite(HOST, 9, 10, 4, "   ", true, true, NOW), "Blank device name");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "unexpected", true), NOW), "Unknown field");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "version|type", true), NOW), "Field name resembling allowed field separator");
        JSONObject missing = json(host.code()); missing.remove("sessionKey");
        bad(() -> UwbPairing.parseInvite(code(missing), NOW), "Missing session key");

        check(UwbPairing.parseInvite(host.code(), host.expiresAtWall - 1).sessionId == host.sessionId, "Invitation remains valid immediately before expiry");
        bad(() -> UwbPairing.parseInvite(host.code(), host.expiresAtWall), "Exact expiry boundary");
        bad(() -> UwbPairing.createReply(host, PEER, "Target", true, true, host.expiresAtWall), "Reply created after invitation expires");
        bad(() -> UwbPairing.parseReply(reply.code(), host, host.expiresAtWall), "Old authenticated reply replayed after expiry");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "expiresAtWall", NOW + 600001), NOW), "Invitation lifetime over ten minutes");
        check(UwbPairing.parseInvite(change(host.code(), "expiresAtWall", NOW + 600000), NOW).expiresAtWall == NOW + 600000, "Maximum allowed invitation lifetime");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "expiresAtWall", NOW - 1), NOW), "Reversed deadline");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "createdAtWall", 0), NOW), "Missing creation date");
        bad(() -> UwbPairing.parseInvite(change(host.code(), "expiresAtWall", Long.MAX_VALUE), NOW), "Overflow-scale expiry");
        bad(() -> UwbPairing.createInvite(HOST, 9, 10, 4, "Phone", true, true, Long.MAX_VALUE - 1), "Creation clock overflow");
        bad(() -> UwbPairing.parseInvite(host.code(), 0), "Invalid current phone clock");
        bad(() -> UwbPairing.parseInvite(host.code(), NOW - 30001), "Clock too far behind invitation");
        check(UwbPairing.parseInvite(host.code(), NOW - 30000).sessionId == host.sessionId, "Small inter-phone clock difference tolerated");
        bad(() -> UwbPairing.parseInvite(null, NOW), "Missing code");
        bad(() -> UwbPairing.parseInvite("FKUWB1:", NOW), "Empty code payload");
        bad(() -> UwbPairing.parseInvite("FKUWB2:" + host.code().substring(7), NOW), "Unknown code prefix");
        bad(() -> UwbPairing.parseInvite(host.code() + "=", NOW), "Noncanonical padded base64");
        bad(() -> UwbPairing.parseInvite(host.code() + "\n", NOW), "Unexpected trailing line break");
        bad(() -> UwbPairing.parseInvite("FKUWB1:" + repeat('A', 2048), NOW), "Oversize code");
        bad(() -> UwbPairing.parseInvite("FKUWB1:A", NOW), "Truncated base64 quantum");
        bad(() -> UwbPairing.parseInvite("FKUWB1:_w", NOW), "Malformed UTF-8");
        bad(() -> UwbPairing.parseInvite(raw("[]"), NOW), "Non-object JSON");
        bad(() -> UwbPairing.parseInvite(raw("{\"version\":"), NOW), "Truncated JSON");
        String wire = json(host.code()).toString();
        bad(() -> UwbPairing.parseInvite(raw(wire + " true"), NOW), "Trailing JSON value");
        bad(() -> UwbPairing.parseInvite(raw(wire.substring(0, wire.length() - 1) + ",\"version\":1}"), NOW), "Duplicate JSON key");
        bad(() -> UwbPairing.parseInvite(raw(wire.replace("\"version\"", "version")), NOW), "Unquoted JSON key");
        bad(() -> UwbPairing.parseInvite(raw(wire.replace("\"version\"", "'version'")), NOW), "Single-quoted JSON key");
        bad(() -> UwbPairing.parseInvite(raw(wire.replace("\"version\":1", "\"version\":01")), NOW), "Leading-zero JSON number");
        bad(() -> UwbPairing.parseInvite(raw(wire.replace("\"version\":1", "\"version\":1e0")), NOW), "Alternate numeric encoding");
        bad(() -> UwbPairing.parseInvite(raw(wire.replace("\"version\":1", "\"version\":{\"nested\":1}")), NOW), "Nested value instead of flat connection field");
        bad(() -> UwbPairing.parseInvite(raw(wire.substring(0, wire.length() - 1) + ",}"), NOW), "Trailing object comma");
        bad(() -> UwbPairing.parseInvite(raw(wire.replace("Workshop phone", "Workshop\\qphone")), NOW), "Unknown string escape");
        check(UwbPairing.parseInvite(raw(" \n" + wire + "\t"), NOW).sessionId == host.sessionId, "Standard JSON whitespace around bounded object");
        UwbPairing.Invite punctuation = UwbPairing.createInvite(HOST, 9, 10, 4, "Workshop \\\"A\\\" / target", true, true, NOW);
        check(UwbPairing.parseInvite(punctuation.code(), NOW).name.equals(punctuation.name), "JSON-escaped printable names remain readable");
        check(UwbPairing.hex(UwbPairing.fromHex("00aBFF")).equals("00ABFF"), "Hex conversion preserves leading zeroes and signed bytes");
        bad(() -> UwbPairing.fromHex("１２"), "Unicode digits in hexadecimal data");
        bad(() -> UwbPairing.fromHex("123"), "Odd-length hexadecimal data");
        bad(() -> UwbPairing.fromHex(""), "Empty binary data");
        bad(() -> UwbPairing.createInvite(new byte[0], 9, 10, 4, "Phone", true, true, NOW), "Empty radio address");
        System.out.println("UwbPairingTests: " + checks + " checks passed");
    }
    private static String repeat(char value, int count) { char[] chars = new char[count]; Arrays.fill(chars, value); return new String(chars); }
}
