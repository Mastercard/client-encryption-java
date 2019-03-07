package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.JettisonProvider;
import com.jayway.jsonpath.spi.json.JsonProvider;

public class JettisonJsonEngine extends JsonEngine {

    private static final JsonProvider jsonProvider = new JettisonProvider();

    @Override
    public JsonProvider getJsonProvider() {
        return jsonProvider;
    }

    @Override
    public Object parse(String string) {
        try {
            return jsonProvider.parse(string);
        } catch (IllegalStateException e) {
            // Jettison refuses to parse primitive types
            return asPrimitiveValue(string);
        }
    }
}
