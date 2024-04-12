package com.mastercard.developer.encryption;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import org.junit.Test;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;

public class JsonParserTest {

    @Test
    public void testDeleteIfExists_shouldDeleteIfElementExists() {
        final String key = "dummyKey";
        JsonObject dummyObject = new JsonObject();
        dummyObject.addProperty(key, "dummyValue");

        DocumentContext context = JsonPath.parse(new Gson().toJson(dummyObject), JsonParser.jsonPathConfig);

        JsonParser.deleteIfExists(context, key);

        Object value = context.read(key);

        assertNull(value);
    }

    @Test
    public void testDeleteIfExists_doNothingIfElementDoesNotExist() {
        final String key = "dummyKey";
        JsonObject dummyObject = new JsonObject();
        dummyObject.addProperty(key, "dummyValue");

        DocumentContext context = JsonPath.parse(new Gson().toJson(dummyObject), JsonParser.jsonPathConfig);

        JsonParser.deleteIfExists(context, "keyWhichDoesNotExist");

        Object value = context.read(key);
        assertNotNull(value);
    }
}
