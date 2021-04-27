package com.mastercard.developer.encryption.jwe;

import com.mastercard.developer.json.JsonEngine;
import net.minidev.json.JSONObject;

import java.util.LinkedHashMap;

public final class JWEHeader {
    private final String enc;
    private final String kid;
    private final String alg;
    private final String cty;

    public JWEHeader(String alg, String enc, String kid, String cty) {
        this.alg = alg;
        this.enc = enc;
        this.kid = kid;
        this.cty = cty;
    }

    public JSONObject toJSONObject() {
        JSONObject obj = new JSONObject();
        if(this.kid != null) {
            obj.put("kid", this.kid);
        }
        if(this.cty != null) {
            obj.put("cty", this.cty);
        }
        if(this.enc != null) {
            obj.put("enc", this.enc);
        }
        if(this.alg != null) {
            obj.put("alg", this.alg);
        }
        return obj;
    }

    public static JWEHeader parseJweHeader(String encodedHeader, JsonEngine jsonEngine) {
        LinkedHashMap headerObj = (LinkedHashMap) jsonEngine.parse(new String(Base64Codec.decode(encodedHeader)));
        return new JWEHeader(
                headerObj.get("alg").toString(),
                headerObj.get("enc").toString(),
                headerObj.get("kid").toString(),
                headerObj.get("cty") != null ? headerObj.get("cty").toString() : null);
    }
}
