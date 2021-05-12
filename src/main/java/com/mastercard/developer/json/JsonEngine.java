package com.mastercard.developer.json;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.spi.json.JsonProvider;

import java.util.Collection;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;

public abstract class JsonEngine {

    private static final Pattern LAST_ELEMENT_IN_PATH_PATTERN = Pattern.compile(".*(\\['.*'\\])"); // Returns "['obj2']" for "$['obj1']['obj2']"

    public abstract JsonProvider getJsonProvider();
    public abstract Object parse(String string);

    public static JsonEngine getDefault() {
        if (isClassFound("com.fasterxml.jackson.databind.ObjectMapper")) {
            return new JacksonJsonEngine();
        }

        if (isClassFound("org.codehaus.jettison.json.JSONObject")) {
            return new JettisonJsonEngine();
        }

        if (isClassFound("org.json.JSONObject")) {
            return new JsonOrgJsonEngine();
        }

        if (isClassFound("net.minidev.json.parser.JSONParser")) {
            return new JsonSmartJsonEngine();
        }

        if (isClassFound("com.google.gson.Gson")) {
            return new GsonJsonEngine();
        }

        String message = "At least one of the following JSON library must be added to your classpath:\n" +
                "* com.fasterxml.jackson.core:jackson-databind\n" +
                "* net.minidev:json-smart\n" +
                "* org.codehaus.jettison:jettison\n" +
                "* org.json:json\n" +
                "* com.google.code.gson:gson";
        throw new IllegalStateException(message);
    }


    public void addProperty(Object obj, String key, Object val) {
        getJsonProvider().setProperty(obj, key, val);
    }

    private static boolean isClassFound(String className) {
        try {
            Class.forName(className);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    protected static Object asPrimitiveValue(String string) {
       // Boolean?
        if ("true".equals(string) || "false".equals(string)) {
            return Boolean.valueOf(string);
        }

        // Numeric?
        try {
            return Long.valueOf(string);
        } catch (NumberFormatException e) {
            // Not a number, do nothing
        }

        // String
        return string;
    }

    public String toJsonString(Object object) {
        if (null == object) {
            throw new IllegalStateException("Can't get a JSON string from a null object!");
        }
        if (isJsonPrimitive(object)) {
            return object.toString();
        }
        return getJsonProvider().toJson(object);
    }

    protected boolean isJsonPrimitive(Object jsonElement) {
        JsonProvider jsonProvider = getJsonProvider();
        return !jsonProvider.isMap(jsonElement) && !jsonProvider.isArray(jsonElement);
    }

    public boolean isJsonObject(Object jsonElement) {
        return getJsonProvider().isMap(jsonElement);
    }

    public boolean isNullOrEmptyJson(Object jsonElement) {
        return jsonElement == null
                || isNullOrEmpty(toJsonString(jsonElement))
                || "{}".equals(toJsonString(jsonElement))
                || Object.class.equals(jsonElement.getClass());
    }

    public Collection<String> getPropertyKeys(Object jsonElement) {
        if (isNullOrEmptyJson(jsonElement)) {
            return Collections.emptyList();
        }
        return getJsonProvider().getPropertyKeys(jsonElement);
    }

    /**
     * Get JSON path to the parent of the object at the given JSON path.
     */
    public static String getParentJsonPath(String jsonPathString) {
        JsonPath jsonPath = JsonPath.compile(jsonPathString);
        String compiledPath = jsonPath.getPath();
        Matcher matcher = LAST_ELEMENT_IN_PATH_PATTERN.matcher(compiledPath);
        if (matcher.find()) {
            return compiledPath.replace(matcher.group(1), "");
        }
        throw new IllegalStateException(String.format("Unable to find parent for '%s'", jsonPathString));
    }

    /**
     * Get object key at the given JSON path.
     */
    public static String getJsonElementKey(String jsonPathString) {
        JsonPath jsonPath = JsonPath.compile(jsonPathString);
        String compiledPath = jsonPath.getPath();
        Matcher matcher = LAST_ELEMENT_IN_PATH_PATTERN.matcher(compiledPath);
        if (matcher.find()) {
            return matcher.group(1).replace("['", "").replace("']", "");
        }
        throw new IllegalStateException(String.format("Unable to find object key for '%s'", jsonPathString));
    }
}
