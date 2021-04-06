package com.mastercard.developer.encryption;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import static com.mastercard.developer.utils.EncryptionUtils.sanitizeJson;

public class JweEncryption extends CryptoProvider {

    public static String encryptPayload(String payload, JweConfig config) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, jsonPathConfig);

            // Perform encryption
            for (Map.Entry<String, String> entry : config.getEncryptionPaths().entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                encryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (JOSEException e) {
            throw new EncryptionException("Payload encryption failed!", e);
        }
    }

    public static String decryptPayload(String payload, JweConfig config) throws EncryptionException {
        try {
            // Parse the given payload
            DocumentContext payloadContext = JsonPath.parse(payload, jsonPathConfig);

            // Perform decryption
            for (Map.Entry<String, String> entry : config.getDecryptionPaths().entrySet()) {
                String jsonPathIn = entry.getKey();
                String jsonPathOut = entry.getValue();
                decryptPayloadPath(payloadContext, jsonPathIn, jsonPathOut, config);
            }

            // Return the updated payload
            return payloadContext.jsonString();
        } catch (ParseException | JOSEException e) {
            throw new EncryptionException("Payload decryption failed!", e);
        }
    }

    private static void encryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut, JweConfig config) throws JOSEException {

        Object inJsonElement = readJsonElement(payloadContext, jsonPathIn);
        if (inJsonElement == null) {
            // Nothing to encrypt
            return;
        }

        String inJsonString = sanitizeJson(jsonEngine.toJsonString(inJsonElement));
        RSAPublicKey rsaPublicKey = (RSAPublicKey) config.getEncryptionCertificate().getPublicKey();
        JWEEncrypter jweEncrypter = new RSAEncrypter(rsaPublicKey);

        JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(config.getEncryptionKeyFingerprint())
                .contentType("application/json")
                .build();
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(inJsonString));
        jweObject.encrypt(jweEncrypter);
        String encryptedValue = jweObject.serialize();

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
    }

    private static void decryptPayloadPath(DocumentContext payloadContext, String jsonPathIn, String jsonPathOut, JweConfig config) throws ParseException, JOSEException {

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

        JWEDecrypter jweDecrypter = new RSADecrypter(config.getDecryptionKey());
        JWEObject jweObject = JWEObject.parse(jsonEngine.toJsonString(encryptedValueJsonElement));

        // Decrypt data
        jweObject.decrypt(jweDecrypter);
        String decryptedValue = sanitizeJson(jweObject.getPayload().toString());

        // Add decrypted data at the given JSON path
        checkOrCreateOutObject(payloadContext, jsonPathOut);
        addDecryptedDataToPayload(payloadContext, decryptedValue, jsonPathOut);

        // Remove the input if now empty
        Object inJsonElement = readJsonElement(payloadContext, jsonPathIn);
        if (inJsonElement != null && 0 == jsonPathConfig.jsonProvider().length(inJsonElement) && !"$".equals(jsonPathIn)) {
            payloadContext.delete(jsonPathIn);
        }
    }

    private static Object readAndDeleteJsonKey(DocumentContext context, Object object, String key) {
        context.delete(key);
        return object;
    }

    protected static Object readJsonObject(DocumentContext context, String jsonPathString) {
        Object jsonElement = readJsonElement(context, jsonPathString);
        if (jsonElement == null) {
            return null;
        }
        return jsonElement;
    }
}
