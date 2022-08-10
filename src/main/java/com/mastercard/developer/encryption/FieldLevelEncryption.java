package com.mastercard.developer.encryption;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.spi.json.JsonProvider;
import com.mastercard.developer.encryption.aes.AESCBC;

import javax.crypto.Cipher;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map.Entry;

import static com.mastercard.developer.utils.EncodingUtils.decodeValue;
import static com.mastercard.developer.utils.EncodingUtils.encodeBytes;
import static com.mastercard.developer.utils.EncryptionUtils.sanitizeJson;
import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;

/**
 * Performs field level encryption on HTTP payloads.
 */
public class FieldLevelEncryption {

    private FieldLevelEncryption() {
        // Nothing to do here
    }

    public static String encryptPayload(String payload, FieldLevelEncryptionConfig config) throws EncryptionException {
        return encryptPayload(payload, config, null);
    }

    public static String encryptPayload(String payload, FieldLevelEncryptionConfig config, Object params) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, JsonParser.jsonPathConfig);

            // Perform encryption (if needed)
            for (Entry<String, String> entry : config.encryptionPaths.entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                if(!jsonPathIn.contains("[*]")){
                    payloadContext = encryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config, (FieldLevelEncryptionParams) params);
                }else {
                    String getFieldLength = jsonPathIn.split("\\[.*?\\]")[0].concat(".length()");
                    Integer length = JsonPath.read(payload, getFieldLength);
                    for (Integer i = 0; i < length; i++) {
                        String newJsonPathIn = jsonPathIn.replace("*", i.toString());
                        String newJsonPathOut = jsonPathOut.replace("*", i.toString());
                        payloadContext = encryptPayloadPath(payloadContext, newJsonPathIn, newJsonPathOut, config, (FieldLevelEncryptionParams) params);
                    }
                }
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Payload encryption failed!", e);
        }
    }

    public static String decryptPayload(String payload, FieldLevelEncryptionConfig config) throws EncryptionException {
        return decryptPayload(payload, config, null);
    }

    public static String decryptPayload(String payload, FieldLevelEncryptionConfig config, Object params) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, JsonParser.jsonPathConfig);

            // Perform decryption (if needed)
            for (Entry<String, String> entry : config.decryptionPaths.entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                if(!jsonPathIn.contains("[*]")){
                    payloadContext = decryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config, (FieldLevelEncryptionParams) params);
                }else {
                    String getFieldLength = jsonPathIn.split("\\[.*?\\]")[0].concat(".length()");
                    Integer length = JsonPath.read(payload, getFieldLength);
                    for (Integer i = 0; i < length; i++) {
                        String newJsonPathIn = jsonPathIn.replace("*", i.toString());
                        String newJsonPathOut = jsonPathOut.replace("*", i.toString());
                        payloadContext = decryptPayloadPath(payloadContext, newJsonPathIn, newJsonPathOut, config, (FieldLevelEncryptionParams) params);
                    }
                }
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Payload decryption failed!", e);
        }
    }

    private static DocumentContext encryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut,
                                           FieldLevelEncryptionConfig config, FieldLevelEncryptionParams params) throws GeneralSecurityException, EncryptionException {

        Object inJsonElement = JsonParser.readJsonElement(payloadContext, jsonPathIn);
        if (inJsonElement == null) {
            // Nothing to encrypt
            return payloadContext;
        }

        if (params == null) {
            // Generate encryption params
            params = FieldLevelEncryptionParams.generate(config);
        }

        // Encrypt data at the given JSON path
        String inJsonString = sanitizeJson(JsonParser.jsonEngine.toJsonString(inJsonElement));
        byte[] inJsonBytes = null;
        try {
            inJsonBytes = inJsonString.getBytes(StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            // Should not happen
        }
        byte[] encryptedValueBytes = AESCBC.cipher(params.getSecretKey(), params.getIvSpec(), inJsonBytes, Cipher.ENCRYPT_MODE);
        String encryptedValue = encodeBytes(encryptedValueBytes, config.fieldValueEncoding);

        // Delete data in clear
        if (!"$".equals(jsonPathIn)) {
            payloadContext.delete(jsonPathIn);
        } else {
            // We can't reuse the same DocumentContext. We have to create a new DocumentContext
            // with the appropriate internal representation (JSON object).
            payloadContext = JsonPath.parse("{}", JsonParser.jsonPathConfig);
        }

        // Add encrypted data and encryption fields at the given JSON path
        JsonParser.checkOrCreateOutObject(payloadContext, jsonPathOut);
        payloadContext.put(jsonPathOut, config.encryptedValueFieldName, encryptedValue);
        if (!isNullOrEmpty(config.ivFieldName)) {
            payloadContext.put(jsonPathOut, config.ivFieldName, params.getIvValue());
        }
        if (!isNullOrEmpty(config.encryptedKeyFieldName)) {
            payloadContext.put(jsonPathOut, config.encryptedKeyFieldName, params.getEncryptedKeyValue());
        }
        if (!isNullOrEmpty(config.encryptionCertificateFingerprintFieldName)) {
            payloadContext.put(jsonPathOut, config.encryptionCertificateFingerprintFieldName, config.encryptionCertificateFingerprint);
        }
        if (!isNullOrEmpty(config.encryptionKeyFingerprintFieldName)) {
            payloadContext.put(jsonPathOut, config.encryptionKeyFingerprintFieldName, config.encryptionKeyFingerprint);
        }
        if (!isNullOrEmpty(config.oaepPaddingDigestAlgorithmFieldName)) {
            payloadContext.put(jsonPathOut, config.oaepPaddingDigestAlgorithmFieldName, params.getOaepPaddingDigestAlgorithmValue());
        }
        return payloadContext;
    }

    private static DocumentContext decryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut,
                                           FieldLevelEncryptionConfig config, FieldLevelEncryptionParams params) throws GeneralSecurityException, EncryptionException {

        JsonProvider jsonProvider = JsonParser.jsonPathConfig.jsonProvider();
        Object inJsonObject = JsonParser.readJsonObject(payloadContext, jsonPathIn);
        if (inJsonObject == null) {
            // Nothing to decrypt
            return payloadContext;
        }

        // Read and remove encrypted data and encryption fields at the given JSON path
        Object encryptedValueJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptedValueFieldName);
        if (JsonParser.jsonEngine.isNullOrEmptyJson(encryptedValueJsonElement)) {
            // Nothing to decrypt
            return payloadContext;
        }

        if (!config.useHttpPayloads() && params == null) {
            throw new IllegalStateException("Encryption params have to be set when not stored in HTTP payloads!");
        }

        if (params == null) {
            // Read encryption params from the payload
            Object oaepDigestAlgorithmJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.oaepPaddingDigestAlgorithmFieldName);
            String oaepDigestAlgorithm = JsonParser.jsonEngine.isNullOrEmptyJson(oaepDigestAlgorithmJsonElement) ? config.oaepPaddingDigestAlgorithm : JsonParser.jsonEngine.toJsonString(oaepDigestAlgorithmJsonElement);
            Object encryptedKeyJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptedKeyFieldName);
            Object ivJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.ivFieldName);
            readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptionCertificateFingerprintFieldName);
            readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptionKeyFingerprintFieldName);
            params = new FieldLevelEncryptionParams(JsonParser.jsonEngine.toJsonString(ivJsonElement), JsonParser.jsonEngine.toJsonString(encryptedKeyJsonElement), oaepDigestAlgorithm, config);
        }

        // Decrypt data
        byte[] encryptedValueBytes = decodeValue(JsonParser.jsonEngine.toJsonString(encryptedValueJsonElement), config.fieldValueEncoding);
        byte[] decryptedValueBytes = AESCBC.cipher(params.getSecretKey(), params.getIvSpec(), encryptedValueBytes, Cipher.DECRYPT_MODE);

        // Add decrypted data at the given JSON path
        String decryptedValue = new String(decryptedValueBytes, StandardCharsets.UTF_8);
        decryptedValue = sanitizeJson(decryptedValue);
        if ("$".equals(jsonPathOut)) {
            // We can't reuse the same DocumentContext. We have to create a new DocumentContext
            // with the appropriate internal representation (JSON object or JSON array).
            payloadContext = JsonPath.parse(decryptedValue, JsonParser.jsonPathConfig);
        } else {
            JsonParser.checkOrCreateOutObject(payloadContext, jsonPathOut);
            JsonParser.addDecryptedDataToPayload(payloadContext, decryptedValue, jsonPathOut);

            // Remove the input if now empty
            Object inJsonElement  = JsonParser.readJsonElement(payloadContext, jsonPathIn);
            if (0 == jsonProvider.length(inJsonElement)) {
                payloadContext.delete(jsonPathIn);
            }
        }

        return payloadContext;
    }

    private static Object readAndDeleteJsonKey(DocumentContext context, String objectPath, Object object, String key) {
        if (null == key) {
            // Do nothing
            return null;
        }
        JsonProvider jsonProvider = JsonParser.jsonPathConfig.jsonProvider();
        Object value = jsonProvider.getMapValue(object, key);
        context.delete(objectPath + "." + key);
        return value;
    }
}
