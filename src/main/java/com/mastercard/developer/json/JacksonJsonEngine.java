package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.JacksonJsonProvider;
import com.jayway.jsonpath.spi.json.JsonProvider;

public class JacksonJsonEngine extends JsonEngine {

    @Override
    public JsonProvider getJsonProvider() {
        return new JacksonJsonProvider();
    }
}
