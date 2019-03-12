package com.mastercard.developer.encryption;

import com.mastercard.developer.test.TestUtils;
import org.apache.commons.codec.DecoderException;
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
        assertEquals("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", params.getEncryptionCertificateFingerprintValue());
        assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", params.getEncryptionKeyFingerprintValue());
        assertEquals("SHA256", params.getOaepPaddingDigestAlgorithmValue());
    }

    @Test
    public void testGetIvSpec_ShouldThrowEncryptionException_WhenFailsToDecodeIV() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder().build();
        FieldLevelEncryptionParams params = new FieldLevelEncryptionParams("INVALID VALUE", null,
                                                                           null, null,
                                                                           null,config);

        // THEN
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Failed to decode the provided IV value!");
        expectedException.expectCause(isA(DecoderException.class));

        // WHEN
        params.getIvSpec();
    }

    @Test
    public void testGetSecretKey_ShouldThrowEncryptionException_WhenFailsToEncryptedKey() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder().build();
        FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(null, "INVALID VALUE",
                                                                           null, null,
                                                                           null,config);

        // THEN
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Failed to decode and unwrap the provided secret key value!");
        expectedException.expectCause(isA(DecoderException.class));

        // WHEN
        params.getSecretKey();
    }
}
