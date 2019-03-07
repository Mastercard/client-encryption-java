package com.mastercard.developer.json;

import com.jayway.jsonpath.InvalidJsonException;
import com.jayway.jsonpath.spi.json.JacksonJsonProvider;
import com.jayway.jsonpath.spi.json.JsonProvider;

public class JacksonJsonEngine extends JsonEngine {

    private static final JsonProvider jsonProvider = new JacksonJsonProvider();

    @Override
    public JsonProvider getJsonProvider() {
        return jsonProvider;
    }

    @Override
    public Object parse(String string) {
        try {
            return jsonProvider.parse(string);
        } catch (InvalidJsonException e) {
            // Jackson refuses to parse primitive types
            return asPrimitiveValue(string);
        }
    }
}
