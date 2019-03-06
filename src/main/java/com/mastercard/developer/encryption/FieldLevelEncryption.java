package com.mastercard.developer.encryption;

import com.jayway.jsonpath.*;
import com.jayway.jsonpath.spi.json.JsonProvider;
import com.mastercard.developer.json.JsonEngine;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;
import java.util.Collections;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.mastercard.developer.encryption.FieldLevelEncryptionConfig.FieldValueEncoding;

/**
 * Performs field level encryption on HTTP payloads.
 */
public class FieldLevelEncryption {

    private static final String SUN_JCE = "SunJCE";
    private static final Integer SYMMETRIC_KEY_SIZE = 128;
    private static final String SYMMETRIC_KEY_TYPE = "AES";
    private static final String SYMMETRIC_CYPHER = "AES/CBC/PKCS5Padding";
    private static final String ASYMMETRIC_CYPHER = "RSA/ECB/OAEPWith{ALG}AndMGF1Padding";
    private static final Pattern LAST_ELEMENT_IN_PATH_PATTERN = Pattern.compile(".*(\\['.*'\\])"); // Returns "['obj2']" for "$['obj1']['obj2']"

    private static Configuration jsonPathConfig = withJsonEngine(JsonEngine.getDefault());

    private FieldLevelEncryption() {
    }

    /**
     * Specify the JSON engine to be used.
     * @param jsonEngine A {@link com.mastercard.developer.json.JsonEngine} object
     */
    public static synchronized Configuration withJsonEngine(JsonEngine jsonEngine) {
        jsonPathConfig = new Configuration.ConfigurationBuilder()
                .jsonProvider(jsonEngine.getJsonProvider())
                .options(Option.SUPPRESS_EXCEPTIONS)
                .build();
        return jsonPathConfig;
    }

    /**
     * Encrypt parts of a JSON payload according to the given configuration.
     * @param payload A JSON string
     * @param config A {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig} object
     * @return The updated payload
     */
    public static String encryptPayload(String payload, FieldLevelEncryptionConfig config) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, jsonPathConfig);

            // Perform encryption (if needed)
            for (Entry<String, String> entry : config.encryptionPaths.entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                encryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Payload encryption failed!", e);
        }
    }

    /**
     * Decrypt parts of a JSON payload according to the given configuration.
     * @param payload A JSON string
     * @param config A {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig} object
     * @return The updated payload
     */
    public static String decryptPayload(String payload, FieldLevelEncryptionConfig config) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, jsonPathConfig);

            // Perform decryption (if needed)
            for (Entry<String, String> entry : config.decryptionPaths.entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                decryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (GeneralSecurityException | DecoderException e) {
            throw new EncryptionException("Payload decryption failed!", e);
        }
    }

    private static void encryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut,
                                           FieldLevelEncryptionConfig config) throws GeneralSecurityException {

        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        Object inJsonElement = readJsonElement(payloadContext, jsonPathIn);
        if (inJsonElement == null) {
            // Nothing to encrypt
            return;
        }

        // Generate a random IV
        IvParameterSpec iv = generateIv();
        String ivValue = encodeBytes(iv.getIV(), config.fieldValueEncoding);

        // Generate an AES secret key
        SecretKey secretKey = generateSecretKey();

        // Encrypt the secret key
        byte[] encryptedSecretKeyBytes = wrapSecretKey(config, secretKey);
        String encryptedKeyValue = encodeBytes(encryptedSecretKeyBytes, config.fieldValueEncoding);

        // Encrypt data at the given JSON path
        String inJsonString = sanitizeJson(inJsonElement.toString());
        if (isJsonPrimitive(inJsonElement) && inJsonString.startsWith("\"")) {
            // "value" => value
            inJsonString = inJsonString.substring(1, inJsonString.length() - 1);
        }
        byte[] inJsonBytes = null;
        try {
            inJsonBytes = inJsonString.getBytes(StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            // Should not happen
        }
        byte[] encryptedValueBytes = encryptBytes(secretKey, iv, inJsonBytes);
        String encryptedValue = encodeBytes(encryptedValueBytes, config.fieldValueEncoding);

        // Delete data in clear
        payloadContext.delete(jsonPathIn);

        // Add encrypted data and encryption fields at the given JSON path
        Object outJsonObject = readOrCreateOutObject(payloadContext, jsonPathOut);
        jsonProvider.setProperty(outJsonObject, config.ivFieldName, ivValue);
        jsonProvider.setProperty(outJsonObject, config.encryptedKeyFieldName, encryptedKeyValue);
        jsonProvider.setProperty(outJsonObject, config.encryptedValueFieldName, encryptedValue);
        addEncryptionCertificateFingerprint(outJsonObject, config);
        addEncryptionKeyFingerprint(outJsonObject, config);
        addOaepPaddingDigestAlgorithm(outJsonObject, config);
        payloadContext.set(jsonPathOut, outJsonObject);
    }

    private static void decryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut,
                                           FieldLevelEncryptionConfig config) throws GeneralSecurityException, DecoderException {

        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        Object inJsonObject = readJsonObject(payloadContext, jsonPathIn);
        if (inJsonObject == null) {
            // Nothing to decrypt
            return;
        }

        // Read and remove encrypted data and encryption fields at the given JSON path
        Object encryptedValueJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptedValueFieldName);
        if (isNullOrEmptyJson(encryptedValueJsonElement)) {
            // Nothing to decrypt
            return;
        }
        Object encryptedKeyJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptedKeyFieldName);
        Object ivJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.ivFieldName);
        Object oaepDigestAlgorithmJsonElement = readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.oaepPaddingDigestAlgorithmFieldName);
        readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptionCertificateFingerprintFieldName);
        readAndDeleteJsonKey(payloadContext, jsonPathIn, inJsonObject, config.encryptionKeyFingerprintFieldName);

        // Decrypt the AES secret key
        byte[] encryptedSecretKeyBytes = decodeValue(jsonProvider.unwrap(encryptedKeyJsonElement).toString(), config.fieldValueEncoding);
        String oaepDigestAlgorithm = isNullOrEmptyJson(oaepDigestAlgorithmJsonElement) ? config.oaepPaddingDigestAlgorithm : jsonProvider.unwrap(oaepDigestAlgorithmJsonElement).toString();
        Key secretKey = unwrapSecretKey(config, encryptedSecretKeyBytes, oaepDigestAlgorithm);

        // Decode the IV
        byte[] ivByteArray = decodeValue(jsonProvider.unwrap(ivJsonElement).toString(), config.fieldValueEncoding);
        IvParameterSpec iv = new IvParameterSpec(ivByteArray);

        // Decrypt data
        byte[] encryptedValueBytes = decodeValue(jsonProvider.unwrap(encryptedValueJsonElement).toString(), config.fieldValueEncoding);
        byte[] decryptedValueBytes = decryptBytes(secretKey, iv, encryptedValueBytes);

        // Add decrypted data at the given JSON path
        String decryptedValue = new String(decryptedValueBytes, StandardCharsets.UTF_8);
        decryptedValue = sanitizeJson(decryptedValue);
        readOrCreateOutObject(payloadContext, jsonPathOut);
        addDecryptedDataToPayload(payloadContext, decryptedValue, jsonPathOut);

        // Remove the input object if now empty
        inJsonObject = readJsonObject(payloadContext, jsonPathIn);
        if (inJsonObject != null && 0 == jsonProvider.length(inJsonObject) && !"$".equals(jsonPathIn)) {
            payloadContext.delete(jsonPathIn);
        }
    }

    private static Object readOrCreateOutObject(DocumentContext context, String jsonPathOutString) {
        Object outJsonObject = readJsonObject(context, jsonPathOutString);
        if (null != outJsonObject) {
            // Return the existing object
            return outJsonObject;
        }

        // Path does not exist: if parent exists we create a new object under the parent
        String parentJsonPath = getParentJsonPath(jsonPathOutString);
        Object parentJsonObject = readJsonObject(context, parentJsonPath);
        if (parentJsonObject == null) {
            throw new IllegalArgumentException(String.format("Parent path not found in payload: '%s'!", parentJsonPath));
        }
        outJsonObject = jsonPathConfig.jsonProvider().createMap();
        String elementKey = getJsonElementKey(jsonPathOutString);
        context.put(parentJsonPath, elementKey, outJsonObject);
        return outJsonObject;
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
        if (!isJsonObject(jsonElement)) {
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

    private static void addDecryptedDataToPayload(DocumentContext payloadContext, String decryptedValue, String jsonPathOut) {
        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        boolean isPrimitiveType = false;
        Object decryptedValueJsonElement = null;

        try {
            decryptedValueJsonElement = jsonProvider.parse(decryptedValue);
        } catch (InvalidJsonException | IllegalStateException e) {
            // Primitive type that can't be parsed by some JSON implementations
            isPrimitiveType = true;
        }

        if (isPrimitiveType) {
            if (decryptedValue.startsWith("\"")) {
                // "value" => value
                decryptedValue = decryptedValue.substring(1, decryptedValue.length() - 1);
            }
            payloadContext.set(jsonPathOut, decryptedValue);
            return;
        }

        if (!isJsonObject(decryptedValueJsonElement)) {
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

    private static boolean isJsonPrimitive(Object jsonElement) {
        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        return !jsonProvider.isMap(jsonElement) && !jsonProvider.isArray(jsonElement);
    }

    private static boolean isJsonObject(Object jsonElement) {
        return jsonPathConfig.jsonProvider().isMap(jsonElement);
    }

    private static boolean isNullOrEmptyJson(Object jsonElement) {
        return jsonElement == null
                || "".equals(jsonElement.toString())
                || 0 == jsonElement.getClass().getFields().length;
    }

    /**
     * Get JSON path to the parent of the object at the given JSON path.
     * Examples:
     * - "$['obj1']['obj2']" will return "$['obj1']"
     * - "$.obj1.obj2" will return "$['obj1']"
     * - "obj1.obj2" will return "$['obj1']"
     */
    private static String getParentJsonPath(String jsonPathString) {
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
     * Examples:
     * - "$['obj1']['obj2']" will return "obj2"
     * - "$.obj1.obj2" will return "obj2"
     * - "obj1.obj2" will return "obj2"
     */
    private static String getJsonElementKey(String jsonPathString) {
        JsonPath jsonPath = JsonPath.compile(jsonPathString);
        String compiledPath = jsonPath.getPath();
        Matcher matcher = LAST_ELEMENT_IN_PATH_PATTERN.matcher(compiledPath);
        if (matcher.find()) {
            return matcher.group(1).replace("['", "").replace("']", "");
        }
        throw new IllegalStateException(String.format("Unable to find object key for '%s'", jsonPathString));
    }

    private static void addEncryptionCertificateFingerprint(Object jsonObject, FieldLevelEncryptionConfig config) throws GeneralSecurityException {
        if (isNullOrEmpty(config.encryptionCertificateFingerprintFieldName)) {
            // Nothing to add
            return;
        }
        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        String providedCertificateFingerprintValue = config.encryptionCertificateFingerprint;
        if (!isNullOrEmpty(providedCertificateFingerprintValue)) {
            jsonProvider.setProperty(jsonObject, config.encryptionCertificateFingerprintFieldName, providedCertificateFingerprintValue);
        } else {
            byte[] certificateFingerprintBytes = sha256digestBytes(config.encryptionCertificate.getEncoded());
            String certificateFingerprintValue = encodeBytes(certificateFingerprintBytes, config.fieldValueEncoding);
            jsonProvider.setProperty(jsonObject, config.encryptionCertificateFingerprintFieldName, certificateFingerprintValue);
        }
    }

    private static void addEncryptionKeyFingerprint(Object jsonObject, FieldLevelEncryptionConfig config) throws GeneralSecurityException {
        if (isNullOrEmpty(config.encryptionKeyFingerprintFieldName)) {
            // Nothing to add
            return;
        }
        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        String providedKeyFingerprintValue = config.encryptionKeyFingerprint;
        if (!isNullOrEmpty(providedKeyFingerprintValue)) {
            jsonProvider.setProperty(jsonObject, config.encryptionKeyFingerprintFieldName, providedKeyFingerprintValue);
        } else {
            byte[] keyFingerprintBytes = sha256digestBytes(config.encryptionCertificate.getPublicKey().getEncoded());
            String keyFingerprintValue = encodeBytes(keyFingerprintBytes, config.fieldValueEncoding);
            jsonProvider.setProperty(jsonObject, config.encryptionKeyFingerprintFieldName, keyFingerprintValue);
        }
    }

    private static void addOaepPaddingDigestAlgorithm(Object jsonObject, FieldLevelEncryptionConfig config) {
        if (isNullOrEmpty(config.oaepPaddingDigestAlgorithmFieldName)) {
            // Nothing to add
            return;
        }
        JsonProvider jsonProvider = jsonPathConfig.jsonProvider();
        String oaepDigestAlgorithm = config.oaepPaddingDigestAlgorithm.replace("-", "");
        jsonProvider.setProperty(jsonObject, config.oaepPaddingDigestAlgorithmFieldName, oaepDigestAlgorithm);
    }

    private static IvParameterSpec generateIv() throws GeneralSecurityException {
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    private static SecretKey generateSecretKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance(SYMMETRIC_KEY_TYPE, SUN_JCE);
        generator.init(SYMMETRIC_KEY_SIZE);
        return generator.generateKey();
    }

    private static byte[] wrapSecretKey(FieldLevelEncryptionConfig config, Key key) throws GeneralSecurityException {
        Key publicEncryptionKey = config.encryptionCertificate.getPublicKey();
        MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec(config.oaepPaddingDigestAlgorithm);
        String asymmetricCipher = ASYMMETRIC_CYPHER.replace("{ALG}", mgf1ParameterSpec.getDigestAlgorithm());
        Cipher cipher = Cipher.getInstance(asymmetricCipher, SUN_JCE);
        cipher.init(Cipher.WRAP_MODE, publicEncryptionKey, getOaepParameterSpec(mgf1ParameterSpec));
        return cipher.wrap(key);
    }

    private static Key unwrapSecretKey(FieldLevelEncryptionConfig config, byte[] keyBytes, String oaepDigestAlgorithm) throws GeneralSecurityException {
        if (!oaepDigestAlgorithm.contains("-")) {
            oaepDigestAlgorithm = oaepDigestAlgorithm.replace("SHA", "SHA-");
        }
        MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec(oaepDigestAlgorithm);
        Key key = config.decryptionKey;
        String asymmetricCipher = ASYMMETRIC_CYPHER.replace("{ALG}", mgf1ParameterSpec.getDigestAlgorithm());
        Cipher cipher = Cipher.getInstance(asymmetricCipher, SUN_JCE);
        cipher.init(Cipher.UNWRAP_MODE, key, getOaepParameterSpec(mgf1ParameterSpec));
        return cipher.unwrap(keyBytes, SYMMETRIC_KEY_TYPE, Cipher.SECRET_KEY);
    }

    private static OAEPParameterSpec getOaepParameterSpec(MGF1ParameterSpec mgf1ParameterSpec) {
        return new OAEPParameterSpec(mgf1ParameterSpec.getDigestAlgorithm(), "MGF1", mgf1ParameterSpec, PSource.PSpecified.DEFAULT);
    }

    private static byte[] encryptBytes(Key key, AlgorithmParameterSpec iv, byte[] bytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_CYPHER, SUN_JCE);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(bytes);
    }

    private static byte[] decryptBytes(Key key, AlgorithmParameterSpec iv, byte[] bytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_CYPHER, SUN_JCE);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(bytes);
    }

    private static byte[] sha256digestBytes(byte[] bytes) throws GeneralSecurityException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes);
        return messageDigest.digest();
    }

    private static String sanitizeJson(String json) {
        return json.replaceAll("\n", "")
                .replaceAll("\r", "")
                .replaceAll("\t", "");
    }

    private static String encodeBytes(byte[] bytes, FieldValueEncoding encoding) {
        return encoding == FieldValueEncoding.HEX ? new String(Hex.encodeHex(bytes)) : Base64.encodeBase64String(bytes);
    }

    private static byte[] decodeValue(String value, FieldValueEncoding encoding) throws DecoderException {
        return encoding == FieldValueEncoding.HEX ? Hex.decodeHex(value.toCharArray()) : Base64.decodeBase64(value);
    }

    private static boolean isNullOrEmpty(String str) {
        return null == str || str.length() == 0;
    }
}
