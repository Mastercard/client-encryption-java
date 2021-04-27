package com.mastercard.developer.encryption;

import com.mastercard.developer.test.TestUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Collections;

public class JweEncryptionConfigBuilderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testBuild_Nominal() throws Exception {
        JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .withEncryptionPath("$", "$")
                .withDecryptionPath("$.encryptedPayload", "$")
                .withEncryptedValueFieldName("encryptedPayload")
                .build();
        Assert.assertNotNull(config);
        Assert.assertEquals(EncryptionConfig.Scheme.JWE, config.getScheme());
        Assert.assertEquals(TestUtils.getTestDecryptionKey(), config.getDecryptionKey());
        Assert.assertEquals(TestUtils.getTestEncryptionCertificate(), config.getEncryptionCertificate());
        Assert.assertEquals("encryptedPayload", config.getEncryptedValueFieldName());
        Assert.assertEquals(Collections.singletonMap("$.encryptedPayload", "$"), config.getDecryptionPaths());
        Assert.assertEquals(Collections.singletonMap("$", "$"), config.getEncryptionPaths());
    }

    @Test
    public void testBuild_ResultShouldBeAssignableToGenericEncryptionConfig() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
        Assert.assertNotNull(config);
    }

    @Test
    public void testBuild_ShouldComputeCertificateKeyFingerprints_WhenFingerprintsNotSet() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
        Assert.assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", config.getEncryptionKeyFingerprint());
    }

    @Test
    public void testIntercept_ShouldThrowIOException_WhenEncryptionFails() throws Exception {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Failed to compute encryption key fingerprint!");
        JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .withEncryptionCertificate(TestUtils.getTestInvalidEncryptionCertificate()) // Invalid certificate
                .build();
    }

    @Test
    public void testBuild_ShouldAutoPopulateEncryptionAndDecryptionPaths() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
        Assert.assertEquals(Collections.singletonMap("$.encryptedData", "$"), config.decryptionPaths);
        Assert.assertEquals(Collections.singletonMap("$", "$"), config.encryptionPaths);
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingDecryptionKey() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("You must include at least an encryption certificate or a decryption key");
        JweConfigBuilder.aJweEncryptionConfig()
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenNotDefiniteDecryptionPath() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for decryption must point to a single item!");
        JweConfigBuilder.aJweEncryptionConfig()
                .withDecryptionPath("$.encryptedPayloads[*]", "$.payload")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenNotDefiniteEncryptionPath() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for encryption must point to a single item!");
        JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionPath("$.payloads[*]", "$.encryptedPayload")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .build();
    }
}
