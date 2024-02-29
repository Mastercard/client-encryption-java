package com.mastercard.developer.encryption;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.mastercard.developer.encryption.jwe.JweHeader;
import com.mastercard.developer.encryption.jwe.JweObject;

import java.security.GeneralSecurityException;
import java.util.Map;

import static com.mastercard.developer.encryption.JsonParser.*;
import static com.mastercard.developer.utils.EncryptionUtils.sanitizeJson;

public class JweEncryption {

    private JweEncryption() {
        // Nothing to do here
    }

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
                if(!jsonPathIn.contains("[*]")){
                    payloadContext = encryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
                }else {
                    String getFieldLength = jsonPathIn.split("\\[.*?\\]")[0].concat(".length()");
                    Integer length = JsonPath.read(payload, getFieldLength);
                    for (Integer i = 0; i < length; i++) {
                        String newJsonPathIn = jsonPathIn.replace("*", i.toString());
                        String newJsonPathOut = jsonPathOut.replace("*", i.toString());
                        payloadContext = encryptPayloadPath(payloadContext, newJsonPathIn, newJsonPathOut, config);
                    }
                }
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
                if(!jsonPathIn.contains("[*]")){
                    payloadContext = decryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
                }else {
                    String getFieldLength = jsonPathIn.split("\\[.*?\\]")[0].concat(".length()");
                    Integer length = JsonPath.read(payload, getFieldLength);
                    for (Integer i = 0; i < length; i++) {
                        String newJsonPathIn = jsonPathIn.replace("*", i.toString());
                        String newJsonPathOut = jsonPathOut.replace("*", i.toString());
                        payloadContext = decryptPayloadPath(payloadContext, newJsonPathIn, newJsonPathOut, config);
                    }
                }
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (Exception e) {
            throw new EncryptionException("Payload decryption failed!", e);
        }
    }

    private static DocumentContext encryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut, JweConfig config) throws EncryptionException, GeneralSecurityException {
        Object inJsonElement = readJsonElement(payloadContext, jsonPathIn);
        if (inJsonElement == null) {
            // Nothing to encrypt
            return payloadContext;
        }

        String inJsonString = sanitizeJson(jsonEngine.toJsonString(inJsonElement));
        JweHeader myHeader = new JweHeader(ALGORITHM, ENCRYPTION, config.encryptionKeyFingerprint, CONTENT_TYPE);
        String payload = JweObject.encrypt(config, inJsonString, myHeader);

        // Delete data in clear
        if (!"$".equals(jsonPathIn)) {
            payloadContext.delete(jsonPathIn);
        } else {
            // We can't reuse the same DocumentContext. We have to create a new DocumentContext
            // with the appropriate internal representation (JSON object).
            payloadContext = JsonPath.parse("{}", JsonParser.jsonPathConfig);
        }

        // Add encrypted data and encryption fields at the given JSON path
        checkOrCreateOutObject(payloadContext, jsonPathOut);
        payloadContext.put(jsonPathOut, config.encryptedValueFieldName, payload);
        return payloadContext;
    }

    private static DocumentContext decryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut, JweConfig config) throws EncryptionException, GeneralSecurityException {

        Object inJsonObject = readJsonObject(payloadContext, jsonPathIn);
        if (inJsonObject == null) {
            // Nothing to decrypt
            return payloadContext;
        }

        // Read and remove encrypted data and encryption fields at the given JSON path
        Object encryptedValueJsonElement = readAndDeleteJsonKey(payloadContext, inJsonObject, config.encryptedValueFieldName);
        if (jsonEngine.isNullOrEmptyJson(encryptedValueJsonElement)) {
            // Nothing to decrypt
            return payloadContext;
        }

        String encryptedValue = jsonEngine.toJsonString(encryptedValueJsonElement).replace("\"", "");
        JweObject jweObject = JweObject.parse(encryptedValue, jsonEngine);
        String decryptedValue = jweObject.decrypt(config);

        // Add decrypted data at the given JSON path
        if ("$".equals(jsonPathOut)) {
            // We can't reuse the same DocumentContext. We have to create a new DocumentContext
            // with the appropriate internal representation (JSON object or JSON array).
            payloadContext = JsonPath.parse(decryptedValue, JsonParser.jsonPathConfig);
        } else {
            checkOrCreateOutObject(payloadContext, jsonPathOut);
            JsonParser.addDecryptedDataToPayload(payloadContext, decryptedValue, jsonPathOut);
        }

        // Remove the input
        payloadContext.delete(jsonPathIn);
        return payloadContext;
    }

    private static Object readAndDeleteJsonKey(DocumentContext context, Object object, String key) {
        context.delete(key);
        return object;
    }

    private static Object readJsonObject(DocumentContext context, String jsonPathString) {
        return readJsonElement(context, jsonPathString);
    }
}
