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

    protected Integer ivSize = 16;
    protected Boolean enableCbcHmacVerification = false;

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
        decryptionPaths.forEach((key, value) -> validatePaths(key, value, "decryption"));
        encryptionPaths.forEach((key, value) -> validatePaths(key, value, "encryption"));
    }

    private void validatePaths(String key, String value, String action) {
        boolean keyHasWildcard = key.contains("[*]");
        boolean valueHasWildcard = value.contains("[*]");
        if (keyHasWildcard || valueHasWildcard) {
            validateBothOrNoneHasWildcard(keyHasWildcard, valueHasWildcard, action);
            validateSingleWildcardOnly(key, value, action);
        } else {
            validateDefinitePaths(key, value, action);
        }
    }

    private void validateBothOrNoneHasWildcard(boolean keyHasWildcard, boolean valueHasWildcard, String action) {
        if (!(keyHasWildcard && valueHasWildcard)) {
            throw new IllegalArgumentException("JSON paths for " + action + " with wildcard must both contain a wildcard!");
        }
    }

    private void validateSingleWildcardOnly(String key, String value, String action) {
        if (countWildcards(key) > 1 || countWildcards(value) > 1) {
            throw new IllegalArgumentException("JSON paths for " + action + " with can only contain one wildcard!");
        }
    }

    private void validateDefinitePaths(String key, String value, String action) {
        if (!JsonPath.isPathDefinite(key) || !JsonPath.isPathDefinite(value)) {
            throw new IllegalArgumentException("JSON paths for " + action + " must point to a single item!");
        }
    }

    private int countWildcards(String path) {
        return path.split("\\[\\*]", -1).length - 1;
    }
}
