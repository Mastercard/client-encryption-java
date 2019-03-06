package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.JsonOrgJsonProvider;
import com.jayway.jsonpath.spi.json.JsonProvider;

public class JsonOrgJsonEngine extends JsonEngine {

    @Override
    public JsonProvider getJsonProvider() {
        return new JsonOrgJsonProvider();
    }
}
