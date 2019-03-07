package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.GsonJsonProvider;
import com.jayway.jsonpath.spi.json.JsonProvider;

public class GsonJsonEngine extends JsonEngine {

    private static final JsonProvider jsonProvider = new GsonJsonProvider();

    @Override
    public JsonProvider getJsonProvider() {
        return jsonProvider;
    }

    @Override
    public Object parse(String string) {
        return jsonProvider.parse(string);
    }
}
