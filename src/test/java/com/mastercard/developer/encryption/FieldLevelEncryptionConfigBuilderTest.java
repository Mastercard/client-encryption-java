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
    public void testBuild_ShouldThrowIllegalArgumentException_WhenNotDefiniteDecryptionPath() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for decryption must point to a single item!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withDecryptionPath("$.encryptedPayloads[*]", "$.payload")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingDecryptionKey() {
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
    public void testBuild_ShouldThrowIllegalArgumentException_WhenNotDefiniteEncryptionPath() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON paths for encryption must point to a single item!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionPath("$.payloads[*]", "$.encryptedPayload")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingEncryptionCertificate() {
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
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingOaepPaddingDigestAlgorithm() {
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
    public void testBuild_ShouldThrowIllegalArgumentException_WhenUnsupportedOaepPaddingDigestAlgorithm() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Unsupported OAEP digest algorithm: SHA-720!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-720")
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingEncryptedValueFieldName() {
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
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingEncryptedKeyFieldName() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Encrypted key field name cannot be null!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withIvFieldName("iv")
                .withFieldValueEncoding(HEX)
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingIvFieldName() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("IV field name cannot be null");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withFieldValueEncoding(HEX)
                .build();
    }

    @Test
    public void testBuild_ShouldThrowIllegalArgumentException_WhenMissingFieldValueEncoding() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Value encoding for fields cannot be null!");
        FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .build();
    }

    @Test
    public void testBuild_Nominal() throws Exception {
        FieldLevelEncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionPath("$.payload", "$.encryptedPayload")
                .withEncryptionCertificate(TestUtils.getTestEncryptionCertificate())
                .withEncryptionCertificateFingerprint("97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B")
                .withEncryptionKeyFingerprint("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810")
                .withEncryptionCertificateFingerprintFieldName("publicCertificateFingerprint")
                .withEncryptionKeyFingerprintFieldName("publicKeyFingerprint")
                .withDecryptionPath("$.encryptedPayload", "$.payload")
                .withDecryptionKey(TestUtils.getTestDecryptionKey())
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .withFieldValueEncoding(HEX)
                .build();
        Assert.assertNotNull(config);
        Assert.assertEquals(1, config.encryptionPaths.size());
        Assert.assertNotNull(config.encryptionCertificate);
        Assert.assertEquals("97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B", config.encryptionCertificateFingerprint);
        Assert.assertEquals("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810", config.encryptionKeyFingerprint);
        Assert.assertEquals("publicCertificateFingerprint", config.encryptionCertificateFingerprintFieldName);
        Assert.assertEquals("publicKeyFingerprint", config.encryptionKeyFingerprintFieldName);
        Assert.assertEquals(1, config.decryptionPaths.size());
        Assert.assertNotNull(config.decryptionKey);
        Assert.assertEquals("SHA-512", config.oaepPaddingDigestAlgorithm);
        Assert.assertEquals("encryptedValue", config.encryptedValueFieldName);
        Assert.assertEquals("encryptedKey", config.encryptedKeyFieldName);
        Assert.assertEquals("iv", config.ivFieldName);
        Assert.assertEquals(HEX, config.fieldValueEncoding);
    }
}
