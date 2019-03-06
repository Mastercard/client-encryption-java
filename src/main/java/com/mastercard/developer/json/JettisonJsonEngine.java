package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.JettisonProvider;
import com.jayway.jsonpath.spi.json.JsonProvider;

public class JettisonJsonEngine extends JsonEngine {

    @Override
    public JsonProvider getJsonProvider() {
        return new JettisonProvider();
    }
}
