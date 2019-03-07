package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.JsonOrgJsonProvider;
import com.jayway.jsonpath.spi.json.JsonProvider;

public class JsonOrgJsonEngine extends JsonEngine {

    private static final JsonProvider jsonProvider = new JsonOrgJsonProvider();

    @Override
    public JsonProvider getJsonProvider() {
        return jsonProvider;
    }

    @Override
    public Object parse(String string) {
        return jsonProvider.parse(string);
    }
}
