package com.mastercard.developer.encryption;

import com.jayway.jsonpath.JsonPath;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import static com.mastercard.developer.encryption.FieldLevelEncryptionConfig.FieldValueEncoding;
import static com.mastercard.developer.utils.EncodingUtils.encodeBytes;
import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;
import static java.security.spec.MGF1ParameterSpec.SHA256;
import static java.security.spec.MGF1ParameterSpec.SHA512;

/**
 * A builder class for {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig}.
 */
public final class FieldLevelEncryptionConfigBuilder {

    private Certificate encryptionCertificate;
    private String encryptionCertificateFingerprint;
    private String encryptionKeyFingerprint;
    private PrivateKey decryptionKey;
    private Map<String, String> encryptionPaths = new HashMap<>();
    private Map<String, String> decryptionPaths = new HashMap<>();
    private String oaepPaddingDigestAlgorithm;
    private String ivFieldName;
    private String ivHeaderName;
    private String oaepPaddingDigestAlgorithmFieldName;
    private String oaepPaddingDigestAlgorithmHeaderName;
    private String encryptedKeyFieldName;
    private String encryptedKeyHeaderName;
    private String encryptedValueFieldName;
    private String encryptionCertificateFingerprintFieldName;
    private String encryptionCertificateFingerprintHeaderName;
    private String encryptionKeyFingerprintFieldName;
    private String encryptionKeyFingerprintHeaderName;
    private FieldValueEncoding fieldValueEncoding;

    private FieldLevelEncryptionConfigBuilder() {
    }

    /**
     * Get an instance of the builder.
     */
    public static FieldLevelEncryptionConfigBuilder aFieldLevelEncryptionConfig() {
        return new FieldLevelEncryptionConfigBuilder();
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionCertificate}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionCertificate(Certificate encryptionCertificate) {
        this.encryptionCertificate = encryptionCertificate;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionCertificateFingerprint}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionCertificateFingerprint(String encryptionCertificateFingerprint) {
        this.encryptionCertificateFingerprint = encryptionCertificateFingerprint;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionKeyFingerprint}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionKeyFingerprint(String encryptionKeyFingerprint) {
        this.encryptionKeyFingerprint = encryptionKeyFingerprint;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#decryptionKey}.
     */
    public FieldLevelEncryptionConfigBuilder withDecryptionKey(PrivateKey decryptionKey) {
        this.decryptionKey = decryptionKey;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionPaths}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionPath(String jsonPathIn, String jsonPathOut) {
        this.encryptionPaths.put(jsonPathIn, jsonPathOut);
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#decryptionPaths}.
     */
    public FieldLevelEncryptionConfigBuilder withDecryptionPath(String jsonPathIn, String jsonPathOut) {
        this.decryptionPaths.put(jsonPathIn, jsonPathOut);
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#oaepPaddingDigestAlgorithm}.
     */
    public FieldLevelEncryptionConfigBuilder withOaepPaddingDigestAlgorithm(String oaepPaddingDigestAlgorithm) {
        this.oaepPaddingDigestAlgorithm = oaepPaddingDigestAlgorithm;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#ivFieldName}.
     */
    public FieldLevelEncryptionConfigBuilder withIvFieldName(String ivFieldName) {
        this.ivFieldName = ivFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#oaepPaddingDigestAlgorithmFieldName}.
     */
    public FieldLevelEncryptionConfigBuilder withOaepPaddingDigestAlgorithmFieldName(String oaepPaddingDigestAlgorithmFieldName) {
        this.oaepPaddingDigestAlgorithmFieldName = oaepPaddingDigestAlgorithmFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptedKeyFieldName}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptedKeyFieldName(String encryptedKeyFieldName) {
        this.encryptedKeyFieldName = encryptedKeyFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptedValueFieldName}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptedValueFieldName(String encryptedValueFieldName) {
        this.encryptedValueFieldName = encryptedValueFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionCertificateFingerprintFieldName}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionCertificateFingerprintFieldName(String encryptionCertificateFingerprintFieldName) {
        this.encryptionCertificateFingerprintFieldName = encryptionCertificateFingerprintFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionKeyFingerprintFieldName}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionKeyFingerprintFieldName(String encryptionKeyFingerprintFieldName) {
        this.encryptionKeyFingerprintFieldName = encryptionKeyFingerprintFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#fieldValueEncoding}.
     */
    public FieldLevelEncryptionConfigBuilder withFieldValueEncoding(FieldValueEncoding fieldValueEncoding) {
        this.fieldValueEncoding = fieldValueEncoding;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#ivHeaderName}.
     */
    public FieldLevelEncryptionConfigBuilder withIvHeaderName(String ivHeaderName) {
        this.ivHeaderName = ivHeaderName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#oaepPaddingDigestAlgorithmHeaderName}.
     */
    public FieldLevelEncryptionConfigBuilder withOaepPaddingDigestAlgorithmHeaderName(String oaepPaddingDigestAlgorithmHeaderName) {
        this.oaepPaddingDigestAlgorithmHeaderName = oaepPaddingDigestAlgorithmHeaderName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptedKeyHeaderName}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptedKeyHeaderName(String encryptedKeyHeaderName) {
        this.encryptedKeyHeaderName = encryptedKeyHeaderName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionCertificateFingerprintHeaderName}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionCertificateFingerprintHeaderName(String encryptionCertificateFingerprintHeaderName) {
        this.encryptionCertificateFingerprintHeaderName = encryptionCertificateFingerprintHeaderName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionKeyFingerprintHeaderName}.
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionKeyFingerprintHeaderName(String encryptionKeyFingerprintHeaderName) {
        this.encryptionKeyFingerprintHeaderName = encryptionKeyFingerprintHeaderName;
        return this;
    }

    /**
     * Build a {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig}.
     * @throws EncryptionException
     */
    public FieldLevelEncryptionConfig build() throws EncryptionException {

        checkJsonPathParameterValues();
        checkParameterValues();
        checkParameterConsistency();

        computeEncryptionCertificateFingerprintWhenNeeded();
        computeEncryptionKeyFingerprintWhenNeeded();

        FieldLevelEncryptionConfig config = new FieldLevelEncryptionConfig();
        config.encryptionCertificateFingerprintFieldName = this.encryptionCertificateFingerprintFieldName;
        config.encryptionKeyFingerprintFieldName = this.encryptionKeyFingerprintFieldName;
        config.encryptionCertificateFingerprint = this.encryptionCertificateFingerprint;
        config.encryptionKeyFingerprint = this.encryptionKeyFingerprint;
        config.decryptionKey = this.decryptionKey;
        config.encryptionPaths = this.encryptionPaths;
        config.encryptionCertificate = this.encryptionCertificate;
        config.oaepPaddingDigestAlgorithm = this.oaepPaddingDigestAlgorithm;
        config.ivFieldName = this.ivFieldName;
        config.oaepPaddingDigestAlgorithmFieldName = this.oaepPaddingDigestAlgorithmFieldName;
        config.decryptionPaths = this.decryptionPaths;
        config.encryptedKeyFieldName = this.encryptedKeyFieldName;
        config.fieldValueEncoding = this.fieldValueEncoding;
        config.encryptedValueFieldName = this.encryptedValueFieldName;
        config.ivHeaderName = this.ivHeaderName;
        config.oaepPaddingDigestAlgorithmHeaderName = this.oaepPaddingDigestAlgorithmHeaderName;
        config.encryptedKeyHeaderName = this.encryptedKeyHeaderName;
        config.encryptionCertificateFingerprintHeaderName = this.encryptionCertificateFingerprintHeaderName;
        config.encryptionKeyFingerprintHeaderName = this.encryptionKeyFingerprintHeaderName;
        return config;
    }

    private void checkJsonPathParameterValues() {
        for (Entry<String, String> entry : decryptionPaths.entrySet()) {
            if (!JsonPath.isPathDefinite(entry.getKey()) || !JsonPath.isPathDefinite(entry.getValue())) {
                throw new IllegalArgumentException("JSON paths for decryption must point to a single item!");
            }
        }

        for (Entry<String, String> entry : encryptionPaths.entrySet()) {
            if (!JsonPath.isPathDefinite(entry.getKey()) || !JsonPath.isPathDefinite(entry.getValue())) {
                throw new IllegalArgumentException("JSON paths for encryption must point to a single item!");
            }
        }
    }

    private void checkParameterValues() {
        if (oaepPaddingDigestAlgorithm == null) {
            throw new IllegalArgumentException("The digest algorithm for OAEP cannot be null!");
        }

        if (!SHA256.getDigestAlgorithm().equals(oaepPaddingDigestAlgorithm)
                && !SHA512.getDigestAlgorithm().equals(oaepPaddingDigestAlgorithm)) {
            throw new IllegalArgumentException(String.format("Unsupported OAEP digest algorithm: %s!", oaepPaddingDigestAlgorithm));
        }

        if (fieldValueEncoding == null) {
            throw new IllegalArgumentException("Value encoding for fields and headers cannot be null!");
        }

        if (ivFieldName == null && ivHeaderName == null) {
            throw new IllegalArgumentException("At least one of IV field name or IV header name must be set!");
        }

        if (encryptedKeyFieldName == null && encryptedKeyHeaderName == null) {
            throw new IllegalArgumentException("At least one of encrypted key field name or encrypted key header name must be set!");
        }

        if (encryptedValueFieldName == null) {
            throw new IllegalArgumentException("Encrypted value field name cannot be null!");
        }
    }

    private void checkParameterConsistency () {
        if (!decryptionPaths.isEmpty() && decryptionKey == null) {
            throw new IllegalArgumentException("Can't decrypt without decryption key!");
        }

        if (!encryptionPaths.isEmpty() && encryptionCertificate == null) {
            throw new IllegalArgumentException("Can't encrypt without encryption key!");
        }

        if (ivHeaderName != null && encryptedKeyHeaderName == null
                || ivHeaderName == null && encryptedKeyHeaderName != null) {
            throw new IllegalArgumentException("IV header name and encrypted key header name must be both set or both unset!");
        }

        if (ivFieldName != null && encryptedKeyFieldName == null
                || ivFieldName == null && encryptedKeyFieldName != null) {
            throw new IllegalArgumentException("IV field name and encrypted key field name must be both set or both unset!");
        }
    }

    private void computeEncryptionCertificateFingerprintWhenNeeded() throws EncryptionException {
        try {
            if (encryptionCertificate == null || !isNullOrEmpty(encryptionCertificateFingerprint)) {
                // No encryption certificate set or certificate fingerprint already provided
                return;
            }
            byte[] certificateFingerprintBytes = sha256digestBytes(encryptionCertificate.getEncoded());
            encryptionCertificateFingerprint = encodeBytes(certificateFingerprintBytes, FieldValueEncoding.HEX);
        } catch (Exception e) {
            throw new EncryptionException("Failed to compute encryption certificate fingerprint!", e);
        }
    }

    private void computeEncryptionKeyFingerprintWhenNeeded() throws EncryptionException {
        try {
            if (encryptionCertificate == null || !isNullOrEmpty(encryptionKeyFingerprint)) {
                // No encryption certificate set or key fingerprint already provided
                return;
            }
            byte[] keyFingerprintBytes = sha256digestBytes(encryptionCertificate.getPublicKey().getEncoded());
            encryptionKeyFingerprint = encodeBytes(keyFingerprintBytes, FieldValueEncoding.HEX);
        } catch (Exception e) {
            throw new EncryptionException("Failed to compute encryption key fingerprint!", e);
        }
    }

    private static byte[] sha256digestBytes(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes);
        return messageDigest.digest();
    }
}
