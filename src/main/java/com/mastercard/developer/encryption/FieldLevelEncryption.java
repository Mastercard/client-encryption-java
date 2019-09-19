package com.mastercard.developer.encryption;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.spi.json.JsonProvider;
import com.mastercard.developer.json.JsonEngine;

import javax.crypto.Cipher;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map.Entry;

import static com.mastercard.developer.utils.EncodingUtils.decodeValue;
import static com.mastercard.developer.utils.EncodingUtils.encodeBytes;
import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;

/**
 * Performs field level encryption on HTTP payloads.
 */
public class FieldLevelEncryption {

    private static final String SYMMETRIC_CYPHER = "AES/CBC/PKCS5Padding";

    private static JsonEngine jsonEngine;
    private static Configuration jsonPathConfig = withJsonEngine(JsonEngine.getDefault());

    private FieldLevelEncryption() {
    }

    /**
     * Specify the JSON engine to be used.
     * @param jsonEngine A {@link com.mastercard.developer.json.JsonEngine} instance
     */
    public static synchronized Configuration withJsonEngine(JsonEngine jsonEngine) {
        FieldLevelEncryption.jsonEngine = jsonEngine;
        FieldLevelEncryption.jsonPathConfig = new Configuration.ConfigurationBuilder()
                .jsonProvider(jsonEngine.getJsonProvider())
                .options(Option.SUPPRESS_EXCEPTIONS)
                .build();
        return jsonPathConfig;
    }

    /**
     * Encrypt parts of a JSON payload using the given configuration.
     * @param payload A JSON string
     * @param config A {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig} instance
     * @return The updated payload
     * @throws EncryptionException
     */
    public static String encryptPayload(String payload, FieldLevelEncryptionConfig config) throws EncryptionException {
        return encryptPayload(payload, config, null);
    }

    /**
     * Encrypt parts of a JSON payload using the given parameters and configuration.
     * @param payload A JSON string
     * @param config A {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig} instance
     * @param params A {@link FieldLevelEncryptionParams} instance
     * @return The updated payload
     * @throws EncryptionException
     */
    public static String encryptPayload(String payload, FieldLevelEncryptionConfig config, FieldLevelEncryptionParams params) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, jsonPathConfig);

            // Perform encryption (if needed)
            for (Entry<String, String> entry : config.encryptionPaths.entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                encryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config, params);
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Payload encryption failed!", e);
        }
    }

    /**
     * Decrypt parts of a JSON payload using the given configuration.
     * @param payload A JSON string
     * @param config A {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig} instance
     * @return The updated payload
     * @throws EncryptionException
     */
    public static String decryptPayload(String payload, FieldLevelEncryptionConfig config) throws EncryptionException {
        return decryptPayload(payload, config, null);
    }

    /**
     * Decrypt parts of a JSON payload using the given parameters and configuration.
     * @param payload A JSON string
     * @param config A {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig} instance
     * @param params A {@link FieldLevelEncryptionParams} instance
     * @return The updated payload
     * @throws EncryptionException
     */
    public static String decryptPayload(String payload, FieldLevelEncryptionConfig config, FieldLevelEncryptionParams params) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, jsonPathConfig);

            // Perform decryption (if needed)
            for (Entry<String, String> entry : config.decryptionPaths.entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                decryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config, params);
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Payload decryption failed!", e);
        }
    }

    private static void encryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut,
                                           FieldLevelEncryptionConfig config, FieldLevelEncryptionParams params) throws GeneralSecurityException, EncryptionException {

        Object inJsonElement = readJsonElement(payloadContext, jsonPathIn);
        if (inJsonElement == null) {
            // Nothing to encrypt
            return;
        }

        if (params == null) {
            // Generate encryption params
            params = FieldLevelEncryptionParams.generate(config);
        }

        // Encrypt data at the given JSON path
        String inJsonString = sanitizeJson(jsonEngine.toJsonString(inJsonElement));
        byte[] inJsonBytes = null;
        try {
            inJsonBytes = inJsonString.getBytes(StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            // Should not happen
        }
        byte[] encryptedValueBytes = encryptBytes(params.getSecretKey(), params.getIvSpec(), inJsonBytes);
        String encryptedValue = encodeBytes(encryptedValueBytes, config.fieldValueEncoding);

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
    }

    private static void decryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut,
                                           FieldLevelEncryptionConfig config, FieldLevelEncryptionParams params) throws GeneralSecurityException, EncryptionException {

        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        Object inJsonObject = readJsonObject(payloadContext, jsonPathIn);
        if (inJsonObject == null) {
            // Nothing to decrypt
            return;
        }

        // Read and remove encrypted data and encryption fields at the given JSON path
        Object encryptedValueJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptedValueFieldName);
        if (jsonEngine.isNullOrEmptyJson(encryptedValueJsonElement)) {
            // Nothing to decrypt
            return;
        }

        if (!config.useHttpPayloads() && params == null) {
            throw new IllegalStateException("Encryption params have to be set when not stored in HTTP payloads!");
        }

        if (params == null) {
            // Read encryption params from the payload
            Object oaepDigestAlgorithmJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.oaepPaddingDigestAlgorithmFieldName);
            String oaepDigestAlgorithm = jsonEngine.isNullOrEmptyJson(oaepDigestAlgorithmJsonElement) ? config.oaepPaddingDigestAlgorithm : jsonEngine.toJsonString(oaepDigestAlgorithmJsonElement);
            Object encryptedKeyJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptedKeyFieldName);
            Object ivJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.ivFieldName);
            readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptionCertificateFingerprintFieldName);
            readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptionKeyFingerprintFieldName);
            params = new FieldLevelEncryptionParams(jsonEngine.toJsonString(ivJsonElement), jsonEngine.toJsonString(encryptedKeyJsonElement), oaepDigestAlgorithm, config);
        }

        // Decrypt data
        byte[] encryptedValueBytes = decodeValue(jsonEngine.toJsonString(encryptedValueJsonElement), config.fieldValueEncoding);
        byte[] decryptedValueBytes = decryptBytes(params.getSecretKey(), params.getIvSpec(), encryptedValueBytes);

        // Add decrypted data at the given JSON path
        String decryptedValue = new String(decryptedValueBytes, StandardCharsets.UTF_8);
        decryptedValue = sanitizeJson(decryptedValue);
        checkOrCreateOutObject(payloadContext, jsonPathOut);
        addDecryptedDataToPayload(payloadContext, decryptedValue, jsonPathOut);

        // Remove the input if now empty
        Object inJsonElement  = readJsonElement(payloadContext, jsonPathIn);
        if (0 == jsonProvider.length(inJsonElement) && !"$".equals(jsonPathIn)) {
            payloadContext.delete(jsonPathIn);
        }
    }

    private static void addDecryptedDataToPayload(DocumentContext payloadContext, String decryptedValue, String jsonPathOut) {
        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        Object decryptedValueJsonElement = jsonEngine.parse(decryptedValue);

        if (!jsonEngine.isJsonObject(decryptedValueJsonElement)) {
            // Array or primitive: overwrite
            payloadContext.set(jsonPathOut, decryptedValueJsonElement);
            return;
        }

        // Object: merge
        int length = jsonProvider.length(decryptedValueJsonElement);
        Collection<String> propertyKeys = (0 == length) ? Collections.<String>emptyList() : jsonProvider.getPropertyKeys(decryptedValueJsonElement);
        for (String key : propertyKeys) {
            payloadContext.delete(jsonPathOut + "." + key);
            payloadContext.put(jsonPathOut, key, jsonProvider.getMapValue(decryptedValueJsonElement, key));
        }
    }

    private static void checkOrCreateOutObject(DocumentContext context, String jsonPathOutString) {
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

    private static Object readJsonElement(DocumentContext context, String jsonPathString) {
        Object payloadJsonObject = context.json();
        JsonPath jsonPath = JsonPath.compile(jsonPathString);
        return jsonPath.read(payloadJsonObject, jsonPathConfig);
    }

    private static Object readJsonObject(DocumentContext context, String jsonPathString) {
        Object jsonElement = readJsonElement(context, jsonPathString);
        if (jsonElement == null) {
            return null;
        }
        if (!jsonEngine.isJsonObject(jsonElement)) {
            throw new IllegalArgumentException(String.format("JSON object expected at path: '%s'!", jsonPathString));
        }
        return jsonElement;
    }

    private static Object readAndDeleteJsonKey(DocumentContext context, String objectPath, Object object, String key) {
        if (null == key) {
            // Do nothing
            return null;
        }
        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        Object value = jsonProvider.getMapValue(object, key);
        context.delete(objectPath + "." + key);
        return value;
    }

    private static String sanitizeJson(String json) {
        return json.replaceAll("\n", "")
                .replaceAll("\r", "")
                .replaceAll("\t", "");
    }

    protected static byte[] encryptBytes(Key key, AlgorithmParameterSpec iv, byte[] bytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_CYPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(bytes);
    }

    protected static byte[] decryptBytes(Key key, AlgorithmParameterSpec iv, byte[] bytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_CYPHER);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(bytes);
    }
}
