package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.JsonProvider;
import com.jayway.jsonpath.spi.json.JsonSmartJsonProvider;

public class JsonSmartJsonEngine extends JsonEngine {

    @Override
    public JsonProvider getJsonProvider() {
        return new JsonSmartJsonProvider();
    }
}
