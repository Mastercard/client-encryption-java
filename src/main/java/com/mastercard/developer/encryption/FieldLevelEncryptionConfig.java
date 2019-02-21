package com.mastercard.developer.encryption;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collections;
import java.util.Map;

/**
 * A POJO for storing the encryption/decryption configuration.
 */
public class FieldLevelEncryptionConfig {

    /**
     * The different ways of encoding the field values.
     */
    public enum FieldValueEncoding {
        BASE64,
        HEX
    }

    protected FieldLevelEncryptionConfig() {
    }

    /**
     * A certificate object whose public key will be used for encryption.
     */
    protected Certificate encryptionCertificate;

    /**
     * The SHA-256 digest of the certificate used for encryption (optional, the digest will be
     * automatically computed if this field is null or empty).
     */
    protected String encryptionCertificateFingerprint;

    /**
     * The SHA-256 digest of the key used for encryption (optional, the digest will be
     * automatically computed if this field is null or empty).
     */
    protected String encryptionKeyFingerprint;

    /**
     * A private key object to be used for decryption.
     */
    protected PrivateKey decryptionKey;

    /**
     * A list of JSON paths to encrypt in request payloads.
     * Example:
     * <pre>
     * new HashMap<>() {
     *     {
     *         put("$.path.to.element.to.be.encrypted", "$.path.to.object.where.to.store.encryption.fields");
     *     }
     * }
     * </pre>
     */
    protected Map<String, String> encryptionPaths = Collections.emptyMap();

    /**
     * A list of JSON paths to decrypt in response payloads.
     * Example:
     * <pre>
     * new HashMap<>() {
     *     {
     *         put("$.path.to.object.with.encryption.fields", "$.path.where.to.write.decrypted.element");
     *     }
     * }
     * </pre>
     */
    protected Map<String, String> decryptionPaths = Collections.emptyMap();

    /**
     * The set of parameters to be used in the OAEP padding scheme.
     * Example: MGF1ParameterSpec.SHA512 for "RSA/ECB/OAEPWithSHA-512AndMGF1Padding".
     */
    protected MGF1ParameterSpec mgf1ParameterSpec = null;

    /**
     * The name of the payload field that will contain the OAEP digest algorithm.
     */
    protected String oaepDigestAlgorithmFieldName = null;

    /**
     * The name of the payload field that will contain the initialization vector value.
     */
    protected String ivFieldName = null;

    /**
     * The name of the payload field that will contain the encrypted symmetric key.
     */
    protected String encryptedKeyFieldName = null;

    /**
     * The name of the payload field that will contain the encrypted data value.
     */
    protected String encryptedValueFieldName = null;

    /**
     * The name of the payload field that will contain the digest of the encryption certificate (optional,
     * the field won't be set if the name is null or empty).
     */
    protected String encryptionCertificateFingerprintFieldName = null;

    /**
     * The name of the payload field that will contain the digest of the encryption key (optional,
     * the field won't be set if the name is null or empty).
     */
    protected String encryptionKeyFingerprintFieldName = null;

    /**
     * How the field values have to be encoded.
     */
    protected FieldValueEncoding fieldValueEncoding;
}
