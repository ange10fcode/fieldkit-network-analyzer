package com.fieldkit.analyzer;

import org.json.JSONObject;

/** Durable last-result envelope. Report payloads keep their original observation timestamps. */
public final class SnapshotDocument {
    private SnapshotDocument() {}

    public static String slot(String key) {
        if (key == null || !key.matches("[a-z][a-z0-9_-]{0,47}"))
            throw new IllegalArgumentException("Invalid saved-result key.");
        return key;
    }

    public static JSONObject create(Report report, JSONObject cfg, long savedAt) {
        if (report == null) throw new IllegalArgumentException("A result is required.");
        try {
            return new JSONObject().put("snapshotVersion",1).put("savedAt",savedAt)
                    .put("report",report.json()).put("cfg",cfg==null?new JSONObject():new JSONObject(cfg.toString()));
        } catch (org.json.JSONException invalid) { throw new IllegalArgumentException("Could not save this result.",invalid); }
    }

    public static JSONObject read(String json) {
        try {
            JSONObject body = new JSONObject(json);
            if (body.optInt("snapshotVersion",0)!=1 || body.optJSONObject("report")==null ||
                    body.optLong("savedAt",0)<=0) return new JSONObject();
            // Validate the report shape before presenting a retained result to the user.
            JSONObject report=body.getJSONObject("report");
            if (report.optJSONArray("columns")==null || report.optJSONArray("rows")==null) return new JSONObject();
            return body;
        } catch (Exception invalid) { return new JSONObject(); }
    }
}
