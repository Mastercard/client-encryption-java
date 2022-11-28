package com.mastercard.developer.encryption;

import com.mastercard.developer.test.TestUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Collections;

public class JweConfigBuilderTest {

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
    public void testBuild_EncryptionKeyFromCertificate() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
        Assert.assertEquals(TestUtils.getTestEncryptionCertificate().getPublicKey(), config.getEncryptionKey());
    }

    @Test
    public void testBuild_EncryptionKeyFromEncryptionKey() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionKey(TestUtils.getTestEncryptionCertificate().getPublicKey())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
        Assert.assertEquals(TestUtils.getTestEncryptionCertificate().getPublicKey(), config.getEncryptionKey());
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
    public void testBuild_ShouldBuild_WhenHavingWildcardPaths() throws Exception {
        JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .withEncryptionPath("$.encryptedPayloads[*]", "$.payload[*]")
                .withDecryptionPath("$.encryptedPayloads[*]", "$.payload[*]")
                .withEncryptedValueFieldName("encryptedPayload")
                .build();
        Assert.assertNotNull(config);
    }

    @Test
    public void testBuild_ShouldComputeCertificateKeyFingerprint_WhenFingerprintNotSet() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
        Assert.assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", config.getEncryptionKeyFingerprint());
    }

    @Test
    public void testIntercept_ShouldThrowEncryptionException_WhenInvalidEncryptionCertificate() throws Exception {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Failed to compute encryption key fingerprint!");
        JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .withEncryptionCertificate(TestUtils.getTestInvalidEncryptionCertificate()) // Invalid certificate
                .build();
    }

    @Test
    public void testBuild_ShouldFallbackToDefaults() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .build();
        Assert.assertEquals(Collections.singletonMap("$.encryptedData", "$"), config.decryptionPaths);
        Assert.assertEquals(Collections.singletonMap("$", "$"), config.encryptionPaths);
        Assert.assertEquals("encryptedData", config.encryptedValueFieldName);
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingDecryptionKey() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("You must include at least an encryption certificate or a decryption key");
        JweConfigBuilder.aJweEncryptionConfig()
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenNotHavingWildcardOnBothDecryptionPaths() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for decryption with wildcard must both contain a wildcard!");
        JweConfigBuilder.aJweEncryptionConfig()
                .withDecryptionPath("$.encryptedPayloads[*]", "$.payload")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMultipleWildcardsOnDecryptionPaths() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for decryption with can only contain one wildcard!");
        JweConfigBuilder.aJweEncryptionConfig()
                .withDecryptionPath("$.encryptedPayloads[*]field1[*]subField", "$.payload[*]field1[*]encryptedSubField")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenNotHavingWildcardOnBothEncryptionPaths() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for encryption with wildcard must both contain a wildcard!");
        JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionPath("$.encryptedPayloads[*]", "$.payload")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMultipleWildcardsOnEncryptionPaths() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for encryption with can only contain one wildcard!");
        JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionPath("$.encryptedPayloads[*]field1[*]subField", "$.payload[*]field1[*]encryptedSubField")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .build();
    }

    @Test
    public void testBuild_ShouldComputeCertificateKeyFingerprin() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
        Assert.assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", config.getEncryptionKeyFingerprint());
    }

    @Test
    public void testBuild_ShouldComputeEncryptionKeyFingerprin() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionKey(TestUtils.getTestEncryptionCertificate().getPublicKey())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
        Assert.assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", config.getEncryptionKeyFingerprint());
    }

    @Test
    public void testBuild_ShouldNotComputeCertificateKeyFingerprint_WhenFingerprintSet() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .withEncryptionKeyFingerprint("2f4lvi26vJWzkzAIaiR2G0YsJAQ=")
                .build();
        Assert.assertEquals("2f4lvi26vJWzkzAIaiR2G0YsJAQ=", config.getEncryptionKeyFingerprint());
    }

    @Test
    public void testBuild_ShouldNotComputeEncryptionKeyFingerprint_WhenFingerprintSet() throws Exception {
        EncryptionConfig config = JweConfigBuilder.aJweEncryptionConfig()
                .withEncryptionKey(TestUtils.getTestEncryptionCertificate().getPublicKey())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .withEncryptionKeyFingerprint("2f4lvi26vJWzkzAIaiR2G0YsJAQ=")
                .build();
        Assert.assertEquals("2f4lvi26vJWzkzAIaiR2G0YsJAQ=", config.getEncryptionKeyFingerprint());
    }
}
