package com.mastercard.developer.encryption;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.spi.json.JsonProvider;
import com.mastercard.developer.json.JsonEngine;

import java.util.Collection;
import java.util.Collections;

public final class JsonParser {

    private JsonParser() {
        // Nothing to do here
    }

    static JsonEngine jsonEngine;
    static Configuration jsonPathConfig = withJsonEngine(JsonEngine.getDefault());

    /**
     * Specify the JSON engine to be used.
     *
     * @param jsonEngine A {@link com.mastercard.developer.json.JsonEngine} instance
     */
   public static synchronized Configuration withJsonEngine(JsonEngine jsonEngine) {
        JsonParser.jsonEngine = jsonEngine;
        JsonParser.jsonPathConfig = new Configuration.ConfigurationBuilder()
                .jsonProvider(jsonEngine.getJsonProvider())
                .options(Option.SUPPRESS_EXCEPTIONS)
                .build();
        return jsonPathConfig;
    }

    static void addDecryptedDataToPayload(DocumentContext payloadContext, String decryptedValue, String jsonPathOut) {
        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        Object decryptedValueJsonElement = jsonEngine.parse(decryptedValue);

        if (!jsonEngine.isJsonObject(decryptedValueJsonElement)) {
            // Array or primitive: overwrite
            payloadContext.set(jsonPathOut, decryptedValueJsonElement);
            return;
        }

        // Object: merge
        int length = jsonProvider.length(decryptedValueJsonElement);
        Collection<String> propertyKeys = (0 == length) ? Collections.emptyList() : jsonProvider.getPropertyKeys(decryptedValueJsonElement);
        for (String key : propertyKeys) {
            payloadContext.delete(jsonPathOut + "." + key);
            payloadContext.put(jsonPathOut, key, jsonProvider.getMapValue(decryptedValueJsonElement, key));
        }
    }

    static void checkOrCreateOutObject(DocumentContext context, String jsonPathOutString) {
        Object outJsonObject = readJsonObject(context, jsonPathOutString);
        if (null != outJsonObject) {
            // Object already exists
            return;
        }

        // Path does not exist: if parent exists then we create a new object under the parent
        String parentJsonPath = JsonEngine.getParentJsonPath(jsonPathOutString);
        Object parentJsonObject = readJsonObject(context, parentJsonPath);
        if (parentJsonObject == null) {
            throw new IllegalArgumentException(String.format("Parent path not found in payload: '%s'!", parentJsonPath));
        }
        outJsonObject = jsonPathConfig.jsonProvider().createMap();
        String elementKey = JsonEngine.getJsonElementKey(jsonPathOutString);
        context.put(parentJsonPath, elementKey, outJsonObject);
    }

    static Object readJsonElement(DocumentContext context, String jsonPathString) {
        Object payloadJsonObject = context.json();
        JsonPath jsonPath = JsonPath.compile(jsonPathString);
        return jsonPath.read(payloadJsonObject, jsonPathConfig);
    }

    static Object readJsonObject(DocumentContext context, String jsonPathString) {
        Object jsonElement = readJsonElement(context, jsonPathString);
        if (jsonElement == null) {
            return null;
        }
        if (!jsonEngine.isJsonObject(jsonElement)) {
            throw new IllegalArgumentException(String.format("JSON object expected at path: '%s'!", jsonPathString));
        }
        return jsonElement;
    }
}
