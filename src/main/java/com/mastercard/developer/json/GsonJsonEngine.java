package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.GsonJsonProvider;
import com.jayway.jsonpath.spi.json.JsonProvider;

public class GsonJsonEngine extends JsonEngine {

    @Override
    public JsonProvider getJsonProvider() {
        return new GsonJsonProvider();
    }
}
