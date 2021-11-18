package com.mastercard.developer.test;

import com.mastercard.developer.encryption.*;
import com.mastercard.developer.encryption.jwe.JweObject;
import com.mastercard.developer.json.JsonEngine;
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

    public static JweConfigBuilder getTestJweConfigBuilder() throws Exception {
        return JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey());
    }

    public static JweObject getTestCbcJweObject() {
        return JweObject.parse("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ", JsonEngine.getDefault());
    }

    public static JweObject getTestGcmJweObject() {
        return JweObject.parse("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA", JsonEngine.getDefault());
    }

    public static void assertDecryptedPayloadEquals(String expectedPayload, String encryptedPayload, FieldLevelEncryptionConfig config) throws Exception {
        String payloadString = FieldLevelEncryption.decryptPayload(encryptedPayload, config);
        assertPayloadEquals(expectedPayload, payloadString);
    }

    public static void assertDecryptedJweEquals(String expectedPayload, String encryptedPayload, JweConfig config) throws Exception {
        String payloadString = JweEncryption.decryptPayload(encryptedPayload, config);
        assertPayloadEquals(expectedPayload, payloadString);
    }

    public static void assertPayloadEquals(String expectedPayload, String payload) {
        JSONAssert.assertEquals(expectedPayload, payload, true);
    }
}
