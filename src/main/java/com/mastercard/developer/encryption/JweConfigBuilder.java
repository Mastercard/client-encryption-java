package com.mastercard.developer.encryption;

import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collections;

public class JweConfigBuilder extends EncryptionConfigBuilder {

    /**
     * Get an instance of the builder.
     */
    public static JweConfigBuilder aJweEncryptionConfig() {
        return new JweConfigBuilder();
    }

    /**
     * Build a {@link JweConfig}.
     *
     * @throws EncryptionException
     */
    public JweConfig build() throws EncryptionException {
        checkParameterValues();
        computeEncryptionKeyFingerprintWhenNeeded();
        checkJsonPathParameterValues();

        JweConfig config = new JweConfig();
        config.encryptionCertificate = this.encryptionCertificate;
        config.encryptionKey = this.encryptionKey;
        config.encryptionKeyFingerprint = this.encryptionKeyFingerprint;
        config.decryptionKey = this.decryptionKey;
        config.encryptionPaths = this.encryptionPaths.isEmpty() ? Collections.singletonMap("$", "$") : this.encryptionPaths;
        config.decryptionPaths = this.decryptionPaths.isEmpty() ? Collections.singletonMap("$.encryptedData", "$") : this.decryptionPaths;
        config.encryptedValueFieldName = this.encryptedValueFieldName == null ? "encryptedData" : this.encryptedValueFieldName;
        config.scheme = EncryptionConfig.Scheme.JWE;
        config.ivSize = ivSize;
        config.symmetricKeySpec = this.symmetricKeySpec;
        return config;
    }

    /**
     * See: {@link EncryptionConfig#encryptionCertificate}.
     */
    public JweConfigBuilder withEncryptionCertificate(Certificate encryptionCertificate) {
        if (this.encryptionKey != null) {
            throw new IllegalArgumentException("You have already supplied an encryption key");
        }
        this.encryptionCertificate = encryptionCertificate;
        return this;
    }

    /**
     * See: {@link EncryptionConfig#encryptionKey}.
     */
    public JweConfigBuilder withEncryptionKey(PublicKey encryptionKey) {
        if (this.encryptionCertificate != null) {
            throw new IllegalArgumentException("You have already supplied an encryption certificate");
        }
        this.encryptionKey = encryptionKey;
        return this;
    }

    /**
     * See: {@link EncryptionConfig#decryptionKey}.
     */
    public JweConfigBuilder withDecryptionKey(PrivateKey decryptionKey) {
        this.decryptionKey = decryptionKey;
        return this;
    }

    /**
     * See: {@link EncryptionConfig#encryptionPaths}.
     */
    public JweConfigBuilder withEncryptionPath(String jsonPathIn, String jsonPathOut) {
        this.encryptionPaths.put(jsonPathIn, jsonPathOut);
        return this;
    }

    /**
     * See: {@link EncryptionConfig#decryptionPaths}.
     */
    public JweConfigBuilder withDecryptionPath(String jsonPathIn, String jsonPathOut) {
        this.decryptionPaths.put(jsonPathIn, jsonPathOut);
        return this;
    }



    public JweConfigBuilder withEncryptedValueFieldName(String encryptedValueFieldName) {
        this.encryptedValueFieldName = encryptedValueFieldName;
        return this;
    }

    public JweConfigBuilder withEncryptionKeyFingerprint(String encryptionKeyFingerprint) {
        this.encryptionKeyFingerprint = encryptionKeyFingerprint;
        return this;
    }

    /**
     * See: {@link EncryptionConfig#ivSize}.
     */
    public JweConfigBuilder withEncryptionIVSize(Integer ivSize) {
        if (ivSize == 12 || ivSize == 16) {
            this.ivSize = ivSize;
            return this;
        }
        throw new IllegalArgumentException("Supported IV Sizes are either 12 or 16!");
    }

    private void checkParameterValues() {
        if (decryptionKey == null && encryptionCertificate == null && encryptionKey == null) {
            throw new IllegalArgumentException("You must include at least an encryption key/certificate or a decryption key");
        }
    }
 
    public JweConfigBuilder withSymmetricKeySpec(SecretKeySpec secretKeySpec) {
        this.symmetricKeySpec = secretKeySpec;
        return this;
    }
    
}
