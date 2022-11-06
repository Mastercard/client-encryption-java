package com.mastercard.developer.encryption;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Map;

public abstract class EncryptionConfig {

    protected EncryptionConfig() {
    }

    /**
     * The different methods of encryption
     */
    public enum Scheme {
        LEGACY,
        JWE
    }

    /**
     * The encryption scheme to be used
     */
    Scheme scheme = Scheme.LEGACY;

    /**
     * The SHA-256 hex-encoded digest of the key used for encryption (optional, the digest will be
     * automatically computed if this field is null or empty).
     * Example: "c3f8ef7053c4fb306f7476e7d1956f0aa992ff9dfdd5244b912a1d377ff3a84f"
     */
    String encryptionKeyFingerprint;

    /**
     * A certificate object whose public key will be used for encryption.
     */
    Certificate encryptionCertificate;

    /**
     * A public key will be used for request encryption.
     */
    PublicKey encryptionKey;

    /**
     * A private key object to be used for decryption.
     */
    PrivateKey decryptionKey;

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
    Map<String, String> encryptionPaths = Collections.emptyMap();

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
    Map<String, String> decryptionPaths = Collections.emptyMap();

    /**
     * The name of the payload field where to write/read the encrypted data value.
     */
    String encryptedValueFieldName = null;

    public String getEncryptionKeyFingerprint() { return encryptionKeyFingerprint; }

    public Certificate getEncryptionCertificate() {
        return encryptionCertificate;
    }

    public PublicKey getEncryptionKey() {
        if (encryptionKey != null) {
            return encryptionKey;
        }
        return encryptionCertificate.getPublicKey();
    }

    public PrivateKey getDecryptionKey() {
        return decryptionKey;
    }

    public Scheme getScheme() { return scheme; }

    Map<String, String> getEncryptionPaths() {
        return encryptionPaths;
    }

    Map<String, String> getDecryptionPaths() {
        return decryptionPaths;
    }

    String getEncryptedValueFieldName() {
        return encryptedValueFieldName;
    }
}
