package com.mastercard.developer.encryption;

/**
 * A POJO for storing the encryption/decryption configuration.
 */
public class FieldLevelEncryptionConfig extends EncryptionConfig {

    /**
     * The different ways of encoding the field and header values.
     */
    public enum FieldValueEncoding {
        BASE64,
        HEX
    }

    /**
     * The SHA-256 hex-encoded digest of the certificate used for encryption (optional, the digest will be
     * automatically computed if this field is null or empty).
     * Example: "4d9d7540be320429ffc8e6506f054525816e2d0e95a85247d5b58be713f28be0"
     */
    String encryptionCertificateFingerprint;

    /**
     * The digest algorithm to be used for the RSA OAEP padding. Example: "SHA-512".
     */
    String oaepPaddingDigestAlgorithm = null;

    /**
     * The name of the payload field where to write/read the digest algorithm used for
     * the RSA OAEP padding (optional, the field won't be set if the name is null or empty).
     */
    String oaepPaddingDigestAlgorithmFieldName = null;

    /**
     * The name of the HTTP header where to write/read the digest algorithm used for
     * the RSA OAEP padding (optional, the header won't be set if the name is null or empty).
     */
    String oaepPaddingDigestAlgorithmHeaderName = null;

    /**
     * The name of the payload field where to write/read the initialization vector value.
     */
    String ivFieldName = null;

    /**
     * The name of the header where to write/read the initialization vector value.
     */
    String ivHeaderName = null;

    /**
     * The name of the payload field where to write/read the one-time usage encrypted symmetric key.
     */
    String encryptedKeyFieldName = null;

    /**
     * The name of the header where to write/read the one-time usage encrypted symmetric key.
     */
    String encryptedKeyHeaderName = null;

    /**
     * The name of the payload field where to write/read the digest of the encryption
     * certificate (optional, the field won't be set if the name is null or empty).
     */
    String encryptionCertificateFingerprintFieldName = null;

    /**
     * The name of the header where to write/read the digest of the encryption
     * certificate (optional, the header won't be set if the name is null or empty).
     */
    String encryptionCertificateFingerprintHeaderName = null;

    /**
     * The name of the payload field where to write/read the digest of the encryption
     * key (optional, the field won't be set if the name is null or empty).
     */
    String encryptionKeyFingerprintFieldName = null;

    /**
     * The name of the header where to write/read the digest of the encryption
     * key (optional, the header won't be set if the name is null or empty).
     */
    String encryptionKeyFingerprintHeaderName = null;

    /**
     * How the field/header values have to be encoded.
     */
    FieldLevelEncryptionConfig.FieldValueEncoding fieldValueEncoding;

    /**
     * If the encryption parameters must be written to/read from HTTP headers.
     */
    public boolean useHttpHeaders() {
        return encryptedKeyHeaderName != null && ivHeaderName != null;
    }

    /**
     * If the encryption parameters must be written to/read from HTTP payloads.
     */
    boolean useHttpPayloads() {
        return encryptedKeyFieldName != null && ivFieldName != null;
    }

    public String getOaepPaddingDigestAlgorithmHeaderName() {
        return oaepPaddingDigestAlgorithmHeaderName;
    }

    public String getIvHeaderName() {
        return ivHeaderName;
    }

    public String getEncryptedKeyHeaderName() {
        return encryptedKeyHeaderName;
    }

    public String getEncryptionCertificateFingerprintHeaderName() {
        return encryptionCertificateFingerprintHeaderName;
    }

    public String getEncryptionKeyFingerprintHeaderName() {
        return encryptionKeyFingerprintHeaderName;
    }

    public String getEncryptionCertificateFingerprint() {
        return encryptionCertificateFingerprint;
    }
}
