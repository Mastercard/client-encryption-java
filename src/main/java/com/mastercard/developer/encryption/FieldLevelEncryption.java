package com.mastercard.developer.encryption;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.spi.json.GsonJsonProvider;
import com.jayway.jsonpath.spi.mapper.GsonMappingProvider;
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
    private static final Pattern LAST_ELEMENT_IN_PATH = Pattern.compile(".*(\\['.*'\\])"); // Returns "['obj2']" for "$['obj1']['obj2']"

    private static final Configuration jsonPathConfig = new Configuration.ConfigurationBuilder()
            .jsonProvider(new GsonJsonProvider())
            .mappingProvider(new GsonMappingProvider())
            .options(Option.SUPPRESS_EXCEPTIONS)
            .build();

    private FieldLevelEncryption() {
    }

    /**
     * Encrypt parts of a JSON payload according to the given configuration.
     * @param payload A JSON string
     * @param config A {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig} object
     * @return The updated payload
     */
    public static String encryptPayload(String payload, FieldLevelEncryptionConfig config) throws GeneralSecurityException {

        // Parse the given payload
        DocumentContext payloadContext = JsonPath.parse(payload, jsonPathConfig);

        // Perform encryption (if needed)
        for (Entry<String, String> entry : config.encryptionPaths.entrySet()) {
            String jsonPathIn = entry.getKey();
            String jsonPathOut = entry.getValue();
            encryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
        }

        // Return the updated payload
        return payloadContext.json().toString();
    }

    /**
     * Decrypt parts of a JSON payload according to the given configuration.
     * @param payload A JSON string
     * @param config A {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig} object
     * @return The updated payload
     */
    public static String decryptPayload(String payload, FieldLevelEncryptionConfig config) throws GeneralSecurityException, DecoderException {

        // Parse the given payload
        DocumentContext payloadContext = JsonPath.parse(payload, jsonPathConfig);

        // Perform decryption (if needed)
        for (Entry<String, String> entry : config.decryptionPaths.entrySet()) {
            String jsonPathIn = entry.getKey();
            String jsonPathOut = entry.getValue();
            decryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
        }

        // Return the updated payload
        return payloadContext.json().toString();
    }

    private static void encryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut,
                                           FieldLevelEncryptionConfig config) throws GeneralSecurityException {

        JsonElement inJsonElement = readJsonElement(payloadContext, jsonPathIn, jsonPathConfig);
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
        byte[] inJsonBytes = null;
        try {
            inJsonBytes = inJsonString.getBytes(StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            // Should not happen
        }
        byte[] encryptedValueBytes = encryptBytes(secretKey, iv, inJsonBytes);
        String encryptedValue = encodeBytes(encryptedValueBytes, config.fieldValueEncoding);

        // Add encrypted data and encryption fields at the given JSON path
        JsonObject outJsonObject = readOrCreateOutObject(payloadContext, jsonPathOut);
        outJsonObject.addProperty(config.ivFieldName, ivValue);
        outJsonObject.addProperty(config.encryptedKeyFieldName, encryptedKeyValue);
        outJsonObject.addProperty(config.encryptedValueFieldName, encryptedValue);
        addEncryptionCertificateFingerprint(outJsonObject, config);
        addEncryptionKeyFingerprint(outJsonObject, config);
        addOaepDigestAlgorithm(outJsonObject, config);

        // Update the original JSON payload
        payloadContext.delete(jsonPathIn);
        payloadContext.set(jsonPathOut, outJsonObject);
    }

    private static void decryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut,
                                           FieldLevelEncryptionConfig config) throws GeneralSecurityException, DecoderException {

        JsonObject inJsonObject = readJsonObject(payloadContext, jsonPathIn, jsonPathConfig);
        if (inJsonObject == null) {
            // Nothing to decrypt
            return;
        }

        // Read and remove encrypted data and encryption fields at the given JSON path
        JsonElement encryptedValueJsonElement = inJsonObject.remove(config.encryptedValueFieldName);
        JsonElement encryptedKeyJsonElement = inJsonObject.remove(config.encryptedKeyFieldName);
        JsonElement ivJsonElement = inJsonObject.remove(config.ivFieldName);
        JsonElement oaepDigestAlgorithmJsonElement = null;
        if (config.oaepDigestAlgorithmFieldName != null) {
            oaepDigestAlgorithmJsonElement = inJsonObject.remove(config.oaepDigestAlgorithmFieldName);
        }
        if (config.encryptionCertificateFingerprintFieldName != null) {
            inJsonObject.remove(config.encryptionCertificateFingerprintFieldName);
        }
        if (config.encryptionKeyFingerprintFieldName != null) {
            inJsonObject.remove(config.encryptionKeyFingerprintFieldName);
        }
        if (inJsonObject.keySet().isEmpty()) {
            // We don't have to keep the object
            payloadContext.delete(jsonPathIn);
        } else {
            // Update the payload
            payloadContext.set(jsonPathIn, inJsonObject);
        }

        // Decrypt the AES secret key
        byte[] encryptedSecretKeyBytes = decodeValue(encryptedKeyJsonElement.getAsString(), config.fieldValueEncoding);
        String oaepDigestAlgorithm = null != oaepDigestAlgorithmJsonElement ? oaepDigestAlgorithmJsonElement.getAsString() : config.mgf1ParameterSpec.getDigestAlgorithm();
        Key secretKey = unwrapSecretKey(config, encryptedSecretKeyBytes, oaepDigestAlgorithm);

        // Decode the IV
        byte[] ivByteArray = decodeValue(ivJsonElement.getAsString(), config.fieldValueEncoding);
        IvParameterSpec iv = new IvParameterSpec(ivByteArray);

        // Decrypt data
        byte[] encryptedValueBytes = decodeValue(encryptedValueJsonElement.getAsString(), config.fieldValueEncoding);
        byte[] decryptedValueBytes = decryptBytes(secretKey, iv, encryptedValueBytes);

        // Add decrypted data at the given JSON path
        String decryptedValue = new String(decryptedValueBytes, StandardCharsets.UTF_8);
        decryptedValue = sanitizeJson(decryptedValue);
        JsonElement decryptedValueJsonElement = new Gson().fromJson(decryptedValue, JsonElement.class);
        JsonObject outJsonObject = readOrCreateOutObject(payloadContext, jsonPathOut);
        if (!decryptedValueJsonElement.isJsonObject()) {
            // Primitive type
            payloadContext.set(jsonPathOut, decryptedValueJsonElement);
        } else {
            // Add decrypted data to the existing object
            for (Entry<String, JsonElement> entry : ((JsonObject)decryptedValueJsonElement).entrySet()) {
                outJsonObject.remove(entry.getKey());
                outJsonObject.add(entry.getKey(), entry.getValue());
            }
            payloadContext.set(jsonPathOut, outJsonObject);
        }
    }

    private static JsonObject readOrCreateOutObject(DocumentContext context, String jsonPathOutString) {
        JsonObject outJsonObject = readJsonObject(context, jsonPathOutString, jsonPathConfig);
        if (null != outJsonObject) {
            // Return the existing object
            return outJsonObject;
        }

        // Path does not exist: if parent exists we create a new object under the parent
        String parentJsonPath = getParentJsonPath(jsonPathOutString);
        JsonObject parentJsonObject = readJsonObject(context, parentJsonPath, jsonPathConfig);
        if (parentJsonObject == null) {
            throw new IllegalArgumentException(String.format("Parent path not found in payload: '%s'!", parentJsonPath));
        }
        outJsonObject = new JsonObject();
        String elementKey = getJsonElementKey(jsonPathOutString);
        context.put(parentJsonPath, elementKey, outJsonObject);
        return outJsonObject;
    }

    private static JsonElement readJsonElement(DocumentContext context, String jsonPathString, Configuration config) {
        JsonObject payloadJsonObject = context.json();
        JsonPath jsonPath = JsonPath.compile(jsonPathString);
        return jsonPath.read(payloadJsonObject, config);
    }

    private static JsonObject readJsonObject(DocumentContext context, String jsonPathString, Configuration config) {
        JsonElement jsonElement = readJsonElement(context, jsonPathString, config);
        if (jsonElement == null) {
            return null;
        }
        if (!jsonElement.isJsonObject()) {
            throw new IllegalArgumentException(String.format("JSON object expected at path: '%s'!", jsonPathString));
        }
        return (JsonObject)jsonElement;
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
        Matcher matcher = LAST_ELEMENT_IN_PATH.matcher(compiledPath);
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
        Matcher matcher = LAST_ELEMENT_IN_PATH.matcher(compiledPath);
        if (matcher.find()) {
            return matcher.group(1).replace("['", "").replace("']", "");
        }
        throw new IllegalStateException(String.format("Unable to find object key for '%s'", jsonPathString));
    }

    private static void addEncryptionCertificateFingerprint(JsonObject jsonObject, FieldLevelEncryptionConfig config) throws GeneralSecurityException {
        if (isNullOrEmpty(config.encryptionCertificateFingerprintFieldName)) {
            // Nothing to add
            return;
        }
        String providedCertificateFingerprintValue = config.encryptionCertificateFingerprint;
        if (!isNullOrEmpty(providedCertificateFingerprintValue)) {
            jsonObject.addProperty(config.encryptionCertificateFingerprintFieldName, providedCertificateFingerprintValue);
        } else {
            byte[] certificateFingerprintBytes = sha256digestBytes(config.encryptionCertificate.getEncoded());
            String certificateFingerprintValue = encodeBytes(certificateFingerprintBytes, config.fieldValueEncoding);
            jsonObject.addProperty(config.encryptionCertificateFingerprintFieldName, certificateFingerprintValue);
        }
    }

    private static void addEncryptionKeyFingerprint(JsonObject jsonObject, FieldLevelEncryptionConfig config) throws GeneralSecurityException {
        if (isNullOrEmpty(config.encryptionKeyFingerprintFieldName)) {
            // Nothing to add
            return;
        }
        String providedKeyFingerprintValue = config.encryptionKeyFingerprint;
        if (!isNullOrEmpty(providedKeyFingerprintValue)) {
            jsonObject.addProperty(config.encryptionKeyFingerprintFieldName, providedKeyFingerprintValue);
        } else {
            byte[] keyFingerprintBytes = sha256digestBytes(config.encryptionCertificate.getPublicKey().getEncoded());
            String keyFingerprintValue = encodeBytes(keyFingerprintBytes, config.fieldValueEncoding);
            jsonObject.addProperty(config.encryptionKeyFingerprintFieldName, keyFingerprintValue);
        }
    }

    private static void addOaepDigestAlgorithm(JsonObject jsonObject, FieldLevelEncryptionConfig config) {
        MGF1ParameterSpec mgf1ParameterSpec = config.mgf1ParameterSpec;
        String oaepDigestAlgorithm = mgf1ParameterSpec.getDigestAlgorithm();
        oaepDigestAlgorithm = oaepDigestAlgorithm.replace("-", "");
        jsonObject.addProperty(config.oaepDigestAlgorithmFieldName, oaepDigestAlgorithm);
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
        MGF1ParameterSpec mgf1ParameterSpec = config.mgf1ParameterSpec;
        String asymmetricCipher = ASYMMETRIC_CYPHER.replace("{ALG}", mgf1ParameterSpec.getDigestAlgorithm());
        Cipher cipher = Cipher.getInstance(asymmetricCipher, SUN_JCE);
        cipher.init(Cipher.WRAP_MODE, publicEncryptionKey, getOaepParameterSpec(mgf1ParameterSpec));
        return cipher.wrap(key);
    }

    public static Key unwrapSecretKey(FieldLevelEncryptionConfig config, byte[] keyBytes, String oaepDigestAlgorithm) throws GeneralSecurityException {
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
                .replaceAll("\t", "")
                .replaceAll(" ", "");
    }

    private static String encodeBytes(byte[] bytes, FieldValueEncoding encoding) {
        return encoding == FieldValueEncoding.HEX ? new String(Hex.encodeHex(bytes)) : Base64.encodeBase64String(bytes);
    }

    public static byte[] decodeValue(String value, FieldValueEncoding encoding) throws DecoderException {
        return encoding == FieldValueEncoding.HEX ? Hex.decodeHex(value.toCharArray()) : Base64.decodeBase64(value);
    }

    private static boolean isNullOrEmpty(String str) {
        return null == str || str.length() == 0;
    }
}
