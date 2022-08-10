package com.mastercard.developer.encryption;

import com.mastercard.developer.test.TestUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static com.mastercard.developer.encryption.FieldLevelEncryptionConfig.FieldValueEncoding.HEX;

public class FieldLevelEncryptionConfigBuilderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testBuild_Nominal() throws Exception {
        FieldLevelEncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionPath("$.payload", "$.encryptedPayload")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withEncryptionCertificateFingerprint("97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B")
                .withEncryptionKeyFingerprint("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810")
                .withEncryptionCertificateFingerprintFieldName("publicCertificateFingerprint")
                .withEncryptionCertificateFingerprintHeaderName("x-public-certificate-fingerprint")
                .withEncryptionKeyFingerprintFieldName("publicKeyFingerprint")
                .withEncryptionKeyFingerprintHeaderName("x-public-key-fingerprint")
                .withDecryptionPath("$.encryptedPayload", "$.payload")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm")
                .withOaepPaddingDigestAlgorithmHeaderName("x-oaep-padding-digest-algorithm")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withIvFieldName("iv")
                .withIvHeaderName("x-iv")
                .withFieldValueEncoding(HEX)
                .build();
        Assert.assertNotNull(config);
        Assert.assertEquals(1, config.encryptionPaths.size());
        Assert.assertNotNull(config.encryptionCertificate);
        Assert.assertEquals("97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B", config.encryptionCertificateFingerprint);
        Assert.assertEquals("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810", config.encryptionKeyFingerprint);
        Assert.assertEquals("publicCertificateFingerprint", config.encryptionCertificateFingerprintFieldName);
        Assert.assertEquals("x-public-certificate-fingerprint", config.encryptionCertificateFingerprintHeaderName);
        Assert.assertEquals("publicKeyFingerprint", config.encryptionKeyFingerprintFieldName);
        Assert.assertEquals("x-public-key-fingerprint", config.encryptionKeyFingerprintHeaderName);
        Assert.assertEquals(1, config.decryptionPaths.size());
        Assert.assertNotNull(config.decryptionKey);
        Assert.assertEquals("SHA-512", config.oaepPaddingDigestAlgorithm);
        Assert.assertEquals("encryptedValue", config.encryptedValueFieldName);
        Assert.assertEquals("encryptedKey", config.encryptedKeyFieldName);
        Assert.assertEquals("x-encrypted-key", config.encryptedKeyHeaderName);
        Assert.assertEquals("iv", config.ivFieldName);
        Assert.assertEquals("x-iv", config.ivHeaderName);
        Assert.assertEquals("oaepPaddingDigestAlgorithm", config.oaepPaddingDigestAlgorithmFieldName);
        Assert.assertEquals("x-oaep-padding-digest-algorithm", config.oaepPaddingDigestAlgorithmHeaderName);
        Assert.assertEquals(HEX, config.fieldValueEncoding);
    }

    @Test
    public void testBuild_ResultShouldBeAssignableToGenericEncryptionConfig() throws Exception {
        EncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionPath("$.payload", "$.encryptedPayload")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withEncryptionCertificateFingerprint("97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B")
                .withEncryptionKeyFingerprint("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810")
                .withEncryptionCertificateFingerprintFieldName("publicCertificateFingerprint")
                .withEncryptionCertificateFingerprintHeaderName("x-public-certificate-fingerprint")
                .withEncryptionKeyFingerprintFieldName("publicKeyFingerprint")
                .withEncryptionKeyFingerprintHeaderName("x-public-key-fingerprint")
                .withDecryptionPath("$.encryptedPayload", "$.payload")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm")
                .withOaepPaddingDigestAlgorithmHeaderName("x-oaep-padding-digest-algorithm")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withIvFieldName("iv")
                .withIvHeaderName("x-iv")
                .withFieldValueEncoding(HEX)
                .build();
        Assert.assertNotNull(config);
    }

    @Test
    public void testBuild_ShouldComputeCertificateAndKeyFingerprints_WhenFingerprintsNotSet() throws Exception {
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionCertificateFingerprint(null)
                .withEncryptionKeyFingerprint(null)
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
        Assert.assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", config.encryptionKeyFingerprint);
        Assert.assertEquals("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", config.encryptionCertificateFingerprint);
    }

    @Test
    public void testBuild_ShouldBuild_WhenHavingWildcardPaths() throws Exception {
        FieldLevelEncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionPath("$.encryptedPayloads[*]", "$.payload[*]")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withEncryptionCertificateFingerprint("97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B")
                .withEncryptionKeyFingerprint("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810")
                .withEncryptionCertificateFingerprintFieldName("publicCertificateFingerprint")
                .withEncryptionCertificateFingerprintHeaderName("x-public-certificate-fingerprint")
                .withEncryptionKeyFingerprintFieldName("publicKeyFingerprint")
                .withEncryptionKeyFingerprintHeaderName("x-public-key-fingerprint")
                .withDecryptionPath("$.encryptedPayloads[*]", "$.payload[*]")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm")
                .withOaepPaddingDigestAlgorithmHeaderName("x-oaep-padding-digest-algorithm")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withIvFieldName("iv")
                .withIvHeaderName("x-iv")
                .withFieldValueEncoding(HEX)
                .build();
        Assert.assertNotNull(config);
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenNotHavingWildcardOnBothDecryptionPaths() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for decryption with wildcard must both contain a wildcard!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withDecryptionPath("$.encryptedPayloads[*]", "$.payload")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMultipleWildcardsOnDecryptionPaths() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for decryption with can only contain one wildcard!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withDecryptionPath("$.encryptedPayloads[*]field1[*]subField", "$.payload[*]field1[*]encryptedSubField")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingDecryptionKey() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Can't decrypt without decryption key!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withDecryptionPath("$.encryptedPayload", "$.payload")
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .withFieldValueEncoding(HEX)
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenNotHavingWildcardOnBothEncryptionPaths() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for encryption with wildcard must both contain a wildcard!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionPath("$.encryptedPayloads[*]", "$.payload")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMultipleWildcardsOnEncryptionPaths() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for encryption with can only contain one wildcard!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionPath("$.encryptedPayloads[*]field1[*]subField", "$.payload[*]field1[*]encryptedSubField")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingEncryptionCertificate() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Can't encrypt without encryption key!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionPath("$.payload", "$.encryptedPayload")
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .withFieldValueEncoding(HEX)
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingOaepPaddingDigestAlgorithm() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("The digest algorithm for OAEP cannot be null!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .withFieldValueEncoding(HEX)
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenUnsupportedOaepPaddingDigestAlgorithm() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Unsupported OAEP digest algorithm: SHA-720!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-720")
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingEncryptedValueFieldName() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Encrypted value field name cannot be null!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .withFieldValueEncoding(HEX)
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingBothEncryptedKeyFieldNameAndHeaderName() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("At least one of encrypted key field name or encrypted key header name must be set!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withIvFieldName("iv")
                .withFieldValueEncoding(HEX)
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingBothIvFieldNameAndHeaderName() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("At least one of IV field name or IV header name must be set!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withFieldValueEncoding(HEX)
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingFieldValueEncoding() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Value encoding for fields and headers cannot be null!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenEncryptedKeyAndIvHeaderNamesNotBothSetOrUnset() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("IV header name and encrypted key header name must be both set or both unset!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .withFieldValueEncoding(HEX)
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenEncryptedKeyAndIvFieldNamesNotBothSetOrUnset() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("IV field name and encrypted key field name must be both set or both unset!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withIvHeaderName("x-iv")
                .withFieldValueEncoding(HEX)
                .build();
    }
}
