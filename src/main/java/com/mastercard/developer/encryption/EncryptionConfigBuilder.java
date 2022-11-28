package com.mastercard.developer.encryption;

import com.jayway.jsonpath.JsonPath;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;

import static com.mastercard.developer.utils.EncodingUtils.encodeBytes;
import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;

abstract class EncryptionConfigBuilder {

    protected Certificate encryptionCertificate;
    protected PublicKey encryptionKey;
    protected String encryptionKeyFingerprint;
    protected PrivateKey decryptionKey;
    protected Map<String, String> encryptionPaths = new HashMap<>();
    protected Map<String, String> decryptionPaths = new HashMap<>();
    protected String encryptedValueFieldName;

    void computeEncryptionKeyFingerprintWhenNeeded() throws EncryptionException {
        try {
            if ((encryptionCertificate == null && encryptionKey == null) || !isNullOrEmpty(encryptionKeyFingerprint)) {
                // No encryption certificate / encryption key set or key fingerprint already provided
                return;
            }
            if (encryptionKey != null && encryptionCertificate != null) {
                throw new IllegalArgumentException("You can only supply either an encryption key or an encryption certificate");
            }
            final PublicKey publicKey;
            if (encryptionKey != null) {
                publicKey = encryptionKey;
            } else {
                publicKey = encryptionCertificate.getPublicKey();
            }
            final byte[] keyFingerprintBytes = sha256digestBytes(publicKey.getEncoded());
            encryptionKeyFingerprint = encodeBytes(keyFingerprintBytes, FieldLevelEncryptionConfig.FieldValueEncoding.HEX);
        } catch (Exception e) {
            throw new EncryptionException("Failed to compute encryption key fingerprint!", e);
        }
    }

    static byte[] sha256digestBytes(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes);
        return messageDigest.digest();
    }

    void checkJsonPathParameterValues() {
        for (Map.Entry<String, String> entry : decryptionPaths.entrySet()) {
            if(entry.getKey().contains("[*]") || entry.getValue().contains("[*]")){
                if(!(entry.getKey().contains("[*]") && entry.getValue().contains("[*]"))){
                    throw new IllegalArgumentException("JSON paths for decryption with wildcard must both contain a wildcard!");
                }
                if((entry.getKey().split("[*]", -1).length-1 > 1 || entry.getValue().split("[*]", -1).length-1 > 1)){
                    throw new IllegalArgumentException("JSON paths for decryption with can only contain one wildcard!");
                }
            } else {
                if (!JsonPath.isPathDefinite(entry.getKey()) || !JsonPath.isPathDefinite(entry.getValue())) {
                    throw new IllegalArgumentException("JSON paths for decryption must point to a single item!");
                }
            }
        }

        for (Map.Entry<String, String> entry : encryptionPaths.entrySet()) {
            if(entry.getKey().contains("[*]") || entry.getValue().contains("[*]")){
                if(!(entry.getKey().contains("[*]") && entry.getValue().contains("[*]"))){
                    throw new IllegalArgumentException("JSON paths for encryption with wildcard must both contain a wildcard!");
                }
                if((entry.getKey().split("[*]", -1).length-1 > 1 || entry.getValue().split("[*]", -1).length-1 > 1)){
                    throw new IllegalArgumentException("JSON paths for encryption with can only contain one wildcard!");
                }
            } else {
                if (!JsonPath.isPathDefinite(entry.getKey()) || !JsonPath.isPathDefinite(entry.getValue())) {
                    throw new IllegalArgumentException("JSON paths for encryption must point to a single item!");
                }
            }
        }
    }
}
