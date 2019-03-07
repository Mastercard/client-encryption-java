package com.mastercard.developer.json;

import com.jayway.jsonpath.spi.json.JsonProvider;

public abstract class JsonEngine {

    public abstract JsonProvider getJsonProvider();
    public abstract Object parse(String string);

    public static JsonEngine getDefault() {
        try {
            Class.forName("com.fasterxml.jackson.databind.ObjectMapper");
            return new JacksonJsonEngine();
        } catch (ClassNotFoundException e) {
            // Do nothing.
        }

        try {
            Class.forName("org.codehaus.jettison.json.JSONObject");
            return new JettisonJsonEngine();
        } catch (ClassNotFoundException e) {
            // Do nothing.
        }

        try {
            Class.forName("org.json.JSONObject");
            return new JsonOrgJsonEngine();
        } catch (ClassNotFoundException e) {
            // Do nothing.
        }

        try {
            Class.forName("net.minidev.json.parser.JSONParser");
            return new JsonSmartJsonEngine();
        } catch (ClassNotFoundException e) {
            // Do nothing.
        }

        try {
            Class.forName("com.google.gson.Gson");
            return new GsonJsonEngine();
        } catch (ClassNotFoundException e) {
            // Do nothing.
        }

        String message = "At least one of the following JSON library must be added to your classpath:\n" +
                "* com.fasterxml.jackson.core:jackson-databind\n" +
                "* net.minidev:json-smart\n" +
                "* org.codehaus.jettison:jettison\n" +
                "* org.json:json\n" +
                "* com.google.code.gson:gson";
        throw new IllegalStateException(message);
    }

    protected Object asPrimitiveValue(String string) {
       // Boolean?
        if ("true".equals(string) || "false".equals(string)) {
            return Boolean.valueOf(string);
        }

        // Numeric?
        try {
            return Long.valueOf(string);
        } catch (NumberFormatException e) {
            // Do nothing
        }

        // String
        return string;
    }
}
