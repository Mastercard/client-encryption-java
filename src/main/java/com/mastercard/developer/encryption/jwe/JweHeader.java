package com.mastercard.developer.encryption.jwe;

import com.jayway.jsonpath.spi.json.JsonProvider;
import com.mastercard.developer.json.JsonEngine;
import com.mastercard.developer.utils.EncodingUtils;

public final class JweHeader {
    private final String enc;
    private final String kid;
    private final String alg;
    private final String cty;

    public JweHeader(String alg, String enc, String kid, String cty) {
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

    static JweHeader parseJweHeader(String encodedHeader, JsonEngine jsonEngine) {
        Object headerObj = jsonEngine.parse(new String(EncodingUtils.base64Decode(encodedHeader)));
        JsonProvider jsonProvider = jsonEngine.getJsonProvider();
        String alg = jsonProvider.getMapValue(headerObj, "alg").toString();
        String enc = jsonProvider.getMapValue(headerObj, "enc").toString();
        String kid = jsonProvider.getMapValue(headerObj, "kid").toString();
        Object cty = jsonProvider.getMapValue(headerObj, "cty");
        return new JweHeader(alg, enc, kid, cty != null ? cty.toString() : null);
    }

    String getEnc() { return enc; }
    String getAlg() { return alg; }
    String getKid() { return kid; }
    String getCty() { return cty; }
}
