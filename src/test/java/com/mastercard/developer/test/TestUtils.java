package com.mastercard.developer.test;

import com.mastercard.developer.encryption.FieldLevelEncryption;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfigBuilder;
import org.skyscreamer.jsonassert.JSONAssert;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static com.mastercard.developer.utils.EncryptionUtils.loadDecryptionKey;
import static com.mastercard.developer.utils.EncryptionUtils.loadEncryptionCertificate;
import static org.mockito.Mockito.mock;

public class TestUtils {

    private TestUtils() {
    }

    public static Certificate getTestEncryptionCertificate() throws Exception {
        return loadEncryptionCertificate("./src/test/resources/certificates/test_certificate-2048.pem");
    }

    public static Certificate getTestInvalidEncryptionCertificate() {
        return mock(X509Certificate.class); // Will throw "java.security.InvalidKeyException: Key must not be null"
    }

    public static PrivateKey getTestDecryptionKey() throws Exception {
        return loadDecryptionKey("./src/test/resources/keys/pkcs8/test_key_pkcs8-2048.der");
    }

    public static FieldLevelEncryptionConfigBuilder getTestFieldLevelEncryptionConfigBuilder() throws Exception {
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

    public static void assertDecryptedPayloadEquals(String expectedPayload, String encryptedPayload, FieldLevelEncryptionConfig config) throws Exception {
        String payloadString = FieldLevelEncryption.decryptPayload(encryptedPayload, config);
        assertPayloadEquals(expectedPayload, payloadString);
    }

    public static void assertPayloadEquals(String expectedPayload, String payload) {
        JSONAssert.assertEquals(expectedPayload, payload, true);
    }
}
