package com.mastercard.developer.encryption.rsa;

import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.test.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

import static com.mastercard.developer.utils.EncodingUtils.base64Decode;

public class RSATest {

    private static final String SYMMETRIC_KEY_TYPE = "AES";

    @Test
    public void testWrapUnwrapSecretKey_ShouldReturnTheOriginalKey() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder().build();
        byte[] originalKeyBytes = base64Decode("mZzmzoURXI3Vk0vdsPkcFw==");
        SecretKey originalKey = new SecretKeySpec(originalKeyBytes, 0, originalKeyBytes.length, SYMMETRIC_KEY_TYPE);

        // WHEN
        byte[] wrappedKeyBytes = RSA.wrapSecretKey(config.getEncryptionKey(), originalKey, "SHA-256");
        Key unwrappedKey = RSA.unwrapSecretKey(config.getDecryptionKey(), wrappedKeyBytes, "SHA-256");

        // THEN
        Assert.assertArrayEquals(originalKey.getEncoded(), unwrappedKey.getEncoded());
    }

    @Test
    public void testUnwrapSecretKey_InteroperabilityTest_OaepSha256() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder()
                .build();
        String wrappedKey = "ZLB838BRWW2/BtdFFAWBRYShw/gBxXSwItpxEZ9zaSVEDHo7n+SyVYU7mayd+9vHkR8OdpqwpXM68t0VOrWI8LD8A2pRaYx8ICyhVFya4OeiWlde05Rhsk+TNwwREPbiw1RgjT8aedRJJYbAZdLb9XEI415Kb/UliHyvsdHMb6vKyYIjUHB/pSGAAmgds56IhIJGfvnBLPZfSHmGgiBT8WXLRuuf1v48aIadH9S0FfoyVGTaLYr+2eznSTAFC0ZBnzebM3mQI5NGQNviTnEJ0y+uZaLE/mthiKgkv1ZybyDPx2xJK2n05sNzfIWKmnI/SOb65RZLlo1Q+N868l2m9g==";
        byte[] wrappedKeyBytes = base64Decode(wrappedKey);

        // WHEN
        Key unwrappedKey = RSA.unwrapSecretKey(config.getDecryptionKey(), wrappedKeyBytes, "SHA-256");

        // THEN
        byte[] expectedKeyBytes = base64Decode("mZzmzoURXI3Vk0vdsPkcFw==");
        Assert.assertArrayEquals(expectedKeyBytes, unwrappedKey.getEncoded());
    }

    @Test
    public void testUnwrapSecretKey_InteroperabilityTest_OaepSha512() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = TestUtils.getTestFieldLevelEncryptionConfigBuilder()
                .build();
        String wrappedKey = "RuruMYP5rG6VP5vS4kVznIrSOjUzXyOhtD7bYlVqwniWTvxxZC73UDluwDhpLwX5QJCsCe8TcwGiQRX1u+yWpBveHDRmDa03hrc3JRJALEKPyN5tnt5w7aI4dLRnLuNoXbYoTSc4V47Z3gaaK6q2rEjydx2sQ/SyVmeUJN7NgxkhtHTyVWTymEM1ythL+AaaQ5AaXedhpWKhG06XYZIX4KV7T9cHEn+See6RVGGB2RUPHBJjrxJo5JoVSfnWN0gkTMyuwbmVaTWfsowbvh8GFibFT7h3uXyI3b79NiauyB7scXp9WidGues3MrTx4dKZrSbs3uHxzPKmCDZimuKfwg==";
        byte[] wrappedKeyBytes = base64Decode(wrappedKey);

        // WHEN
        Key unwrappedKey = RSA.unwrapSecretKey(config.getDecryptionKey(), wrappedKeyBytes, "SHA-512");

        // THEN
        byte[] expectedKeyBytes = base64Decode("mZzmzoURXI3Vk0vdsPkcFw==");
        Assert.assertArrayEquals(expectedKeyBytes, unwrappedKey.getEncoded());
    }
}
