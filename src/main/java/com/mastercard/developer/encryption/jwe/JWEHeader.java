package com.mastercard.developer.encryption.jwe;

import com.mastercard.developer.json.JsonEngine;
import com.mastercard.developer.utils.EncodingUtils;

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

    String toJson() {
        JsonEngine engine = JsonEngine.getDefault();
        Object obj = engine.parse("{}");

        if(this.kid != null) {
            engine.addProperty(obj, "kid", this.kid);
        }
        if(this.cty != null) {
            engine.addProperty(obj, "cty", this.cty);
        }
        if(this.enc != null) {
            engine.addProperty(obj, "enc", this.enc);
        }
        if(this.alg != null) {
            engine.addProperty(obj, "alg", this.alg);
        }
        return engine.toJsonString(obj);
    }

    static JWEHeader parseJweHeader(String encodedHeader, JsonEngine jsonEngine) {
        LinkedHashMap headerObj = (LinkedHashMap) jsonEngine.parse(new String(EncodingUtils.base64Decode(encodedHeader)));
        return new JWEHeader(
                headerObj.get("alg").toString(),
                headerObj.get("enc").toString(),
                headerObj.get("kid").toString(),
                headerObj.get("cty") != null ? headerObj.get("cty").toString() : null);
    }

    String getEnc() { return enc; }
    String getAlg() { return alg; }
    String getKid() { return kid; }
    String getCty() { return cty; }
}
