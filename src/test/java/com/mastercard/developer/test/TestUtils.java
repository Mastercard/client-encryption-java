package com.mastercard.developer.test;

import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfigBuilder;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import static com.mastercard.developer.utils.EncryptionUtils.loadDecryptionKey;
import static com.mastercard.developer.utils.EncryptionUtils.loadEncryptionCertificate;

public class TestUtils {

    private TestUtils() {
    }

    public static Certificate getTestEncryptionCertificate() throws Exception {
        return loadEncryptionCertificate("./src/test/resources/test_certificate.cert");
    }

    public static PrivateKey getTestDecryptionKey() throws Exception {
        return loadDecryptionKey("./src/test/resources/test_key.der");
    }

    public static FieldLevelEncryptionConfigBuilder getFieldLevelEncryptionConfigBuilder() throws Exception {
        return FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .withOaepPaddingDigestAlgorithmFieldName("oaepHashingAlgorithm")
                .withEncryptionCertificateFingerprintFieldName("encryptionCertificateFingerprint")
                .withEncryptionCertificateFingerprint("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279")
                .withEncryptionKeyFingerprintFieldName("encryptionKeyFingerprint")
                .withEncryptionKeyFingerprint("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79")
                .withFieldValueEncoding(FieldLevelEncryptionConfig.FieldValueEncoding.HEX);
    }
}
