package com.mastercard.developer.encryption;

import com.mastercard.developer.test.TestUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class FieldLevelEncryptionParamsTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testGenerate_Nominal() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder().build();

        // WHEN
        FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);

        // THEN
        assertNotNull(params.getIvValue());
        assertNotNull(params.getIvSpec());
        assertNotNull(params.getEncryptedKeyValue());
        assertNotNull(params.getSecretKey());
        assertEquals("SHA256", params.getOaepPaddingDigestAlgorithmValue());
    }

    @Test
    public void testGetIvSpec_ShouldThrowEncryptionException_WhenFailsToDecodeIV() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder().build();
        FieldLevelEncryptionParams params = new FieldLevelEncryptionParams("INVALID VALUE", null, null, config);
        // THEN
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Failed to decode the provided IV value!");
        expectedException.expectCause(isA(IllegalArgumentException.class));

        // WHEN
        params.getIvSpec();
    }

    @Test
    public void testGetSecretKey_ShouldThrowEncryptionException_WhenFailsToReadEncryptedKey() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder().build();
        FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(null, "INVALID VALUE", null, config);

        // THEN
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Failed to decode and unwrap the provided secret key value!");
        expectedException.expectCause(isA(IllegalArgumentException.class));

        // WHEN
        params.getSecretKey();
    }
}
