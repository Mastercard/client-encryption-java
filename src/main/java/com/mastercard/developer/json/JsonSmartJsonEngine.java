package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.JsonProvider;
import com.jayway.jsonpath.spi.json.JsonSmartJsonProvider;

public class JsonSmartJsonEngine extends JsonEngine {

    private static final JsonProvider jsonProvider = new JsonSmartJsonProvider();

    @Override
    public JsonProvider getJsonProvider() {
        return jsonProvider;
    }

    @Override
    public Object parse(String string) {
        return jsonProvider.parse(string);
    }
}
