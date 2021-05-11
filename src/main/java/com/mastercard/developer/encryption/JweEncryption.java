package com.mastercard.developer.encryption;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.mastercard.developer.encryption.jwe.JWEHeader;
import com.mastercard.developer.encryption.jwe.JWEObject;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import static com.mastercard.developer.encryption.JsonParser.*;
import static com.mastercard.developer.utils.EncryptionUtils.sanitizeJson;

public class JweEncryption {

    private static final String ALGORITHM = "RSA-OAEP-256";
    private static final String ENCRYPTION = "A256GCM";
    private static final String CONTENT_TYPE = "application/json";

    public static String encryptPayload(String payload, JweConfig config) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, JsonParser.jsonPathConfig);

            // Perform encryption
            for (Map.Entry<String, String> entry : config.getEncryptionPaths().entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                encryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (Exception e) {
            throw new EncryptionException("Payload encryption failed!", e);
        }
    }

    public static String decryptPayload(String payload, JweConfig config) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, JsonParser.jsonPathConfig);

            // Perform decryption
            for (Map.Entry<String, String> entry : config.getDecryptionPaths().entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                decryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (Exception e) {
            throw new EncryptionException("Payload decryption failed!", e);
        }
    }

    private static void encryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut, JweConfig config) throws EncryptionException, GeneralSecurityException {
        Object inJsonElement = readJsonElement(payloadContext, jsonPathIn);
        if (inJsonElement == null) {
            // Nothing to encrypt
            return;
        }

        String inJsonString = sanitizeJson(jsonEngine.toJsonString(inJsonElement));
        JWEHeader myHeader = new JWEHeader(ALGORITHM, ENCRYPTION, config.encryptionKeyFingerprint, CONTENT_TYPE);
        String payload = JWEObject.encrypt(config, inJsonString, myHeader);

        // Delete data in clear
        if (!"$".equals(jsonPathIn)) {
            payloadContext.delete(jsonPathIn);
        } else {
            // Delete keys one by one
            Collection<String> propertyKeys = new ArrayList<>(jsonEngine.getPropertyKeys(inJsonElement));
            for (String key : propertyKeys) {
                payloadContext.delete(jsonPathIn + "." + key);
            }
        }

        // Add encrypted data and encryption fields at the given JSON path
        checkOrCreateOutObject(payloadContext, jsonPathOut);
        payloadContext.put(jsonPathOut, config.encryptedValueFieldName, payload);
    }

    private static void decryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut, JweConfig config) throws EncryptionException, GeneralSecurityException {

        Object inJsonObject = readJsonObject(payloadContext, jsonPathIn);
        if (inJsonObject == null) {
            // Nothing to decrypt
            return;
        }

        // Read and remove encrypted data and encryption fields at the given JSON path
        Object encryptedValueJsonElement = readAndDeleteJsonKey(payloadContext, inJsonObject, config.encryptedValueFieldName);
        if (jsonEngine.isNullOrEmptyJson(encryptedValueJsonElement)) {
            // Nothing to decrypt
            return;
        }

        String encryptedValue = jsonEngine.toJsonString(encryptedValueJsonElement).replace("\"", "");
        JWEObject jweObject = JWEObject.parse(encryptedValue, jsonEngine);
        String payload = jweObject.decrypt(config);

        // Add decrypted data at the given JSON path
        checkOrCreateOutObject(payloadContext, jsonPathOut);
        JsonParser.addDecryptedDataToPayload(payloadContext, payload, jsonPathOut);

        // Remove the input
        payloadContext.delete(jsonPathIn);
    }

    private static Object readAndDeleteJsonKey(DocumentContext context, Object object, String key) {
        context.delete(key);
        return object;
    }

    private static Object readJsonObject(DocumentContext context, String jsonPathString) {
        Object jsonElement = readJsonElement(context, jsonPathString);
        if (jsonElement == null) {
            return null;
        }
        return jsonElement;
    }
}
