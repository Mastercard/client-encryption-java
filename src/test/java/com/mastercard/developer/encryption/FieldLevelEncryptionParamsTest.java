package com.mastercard.developer.encryption;

import com.mastercard.developer.test.TestUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

import static com.mastercard.developer.encryption.FieldLevelEncryptionParams.SYMMETRIC_KEY_TYPE;
import static com.mastercard.developer.utils.EncodingUtils.base64Decode;
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

    @Test
    public void testWrapUnwrapSecretKey_ShouldReturnTheOriginalKey() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder().build();
        byte[] originalKeyBytes = base64Decode("mZzmzoURXI3Vk0vdsPkcFw==");
        SecretKey originalKey = new SecretKeySpec(originalKeyBytes, 0, originalKeyBytes.length, SYMMETRIC_KEY_TYPE);

        // WHEN
        byte[] wrappedKeyBytes = FieldLevelEncryptionParams.wrapSecretKey(config, originalKey);
        Key unwrappedKey = FieldLevelEncryptionParams.unwrapSecretKey(config, wrappedKeyBytes, config.oaepPaddingDigestAlgorithm);

        // THEN
        Assert.assertArrayEquals(originalKey.getEncoded(), unwrappedKey.getEncoded());
    }

    @Test
    public void testUnwrapSecretKey_InteroperabilityTest_OaepSha256() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder()
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();
        String wrappedKey = "ZLB838BRWW2/BtdFFAWBRYShw/gBxXSwItpxEZ9zaSVEDHo7n+SyVYU7mayd+9vHkR8OdpqwpXM68t0VOrWI8LD8A2pRaYx8ICyhVFya4OeiWlde05Rhsk+TNwwREPbiw1RgjT8aedRJJYbAZdLb9XEI415Kb/UliHyvsdHMb6vKyYIjUHB/pSGAAmgds56IhIJGfvnBLPZfSHmGgiBT8WXLRuuf1v48aIadH9S0FfoyVGTaLYr+2eznSTAFC0ZBnzebM3mQI5NGQNviTnEJ0y+uZaLE/mthiKgkv1ZybyDPx2xJK2n05sNzfIWKmnI/SOb65RZLlo1Q+N868l2m9g==";
        byte[] wrappedKeyBytes = base64Decode(wrappedKey);

        // WHEN
        Key unwrappedKey = FieldLevelEncryptionParams.unwrapSecretKey(config, wrappedKeyBytes, config.oaepPaddingDigestAlgorithm);

        // THEN
        byte[] expectedKeyBytes = base64Decode("mZzmzoURXI3Vk0vdsPkcFw==");
        Assert.assertArrayEquals(expectedKeyBytes, unwrappedKey.getEncoded());
    }

    @Test
    public void testUnwrapSecretKey_InteroperabilityTest_OaepSha512() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder()
                .withOaepPaddingDigestAlgorithm("SHA-512")
                .build();
        String wrappedKey = "RuruMYP5rG6VP5vS4kVznIrSOjUzXyOhtD7bYlVqwniWTvxxZC73UDluwDhpLwX5QJCsCe8TcwGiQRX1u+yWpBveHDRmDa03hrc3JRJALEKPyN5tnt5w7aI4dLRnLuNoXbYoTSc4V47Z3gaaK6q2rEjydx2sQ/SyVmeUJN7NgxkhtHTyVWTymEM1ythL+AaaQ5AaXedhpWKhG06XYZIX4KV7T9cHEn+See6RVGGB2RUPHBJjrxJo5JoVSfnWN0gkTMyuwbmVaTWfsowbvh8GFibFT7h3uXyI3b79NiauyB7scXp9WidGues3MrTx4dKZrSbs3uHxzPKmCDZimuKfwg==";
        byte[] wrappedKeyBytes = base64Decode(wrappedKey);

        // WHEN
        Key unwrappedKey = FieldLevelEncryptionParams.unwrapSecretKey(config, wrappedKeyBytes, config.oaepPaddingDigestAlgorithm);

        // THEN
        byte[] expectedKeyBytes = base64Decode("mZzmzoURXI3Vk0vdsPkcFw==");
        Assert.assertArrayEquals(expectedKeyBytes, unwrappedKey.getEncoded());
    }
}
