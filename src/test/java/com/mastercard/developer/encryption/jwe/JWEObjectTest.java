package com.mastercard.developer.encryption.jwe;

import com.mastercard.developer.test.TestUtils;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class JWEObjectTest {

    @Test
    public void testDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIsCbcEncrypted() throws Exception {
        JweObject jweObject = TestUtils.getTestCbcJweObject();
        String decryptedPayload = jweObject.decrypt(TestUtils.getTestJweConfigBuilder().build());

        assertEquals("{\"foo\":\"bar\"}", decryptedPayload);
    }

    @Test
    public void testDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIsGcmEncrypted() throws Exception {
        JweObject jweObject = TestUtils.getTestGcmJweObject();
        String decryptedPayload = jweObject.decrypt(TestUtils.getTestJweConfigBuilder().build());

        assertEquals("bar", decryptedPayload);
    }
}
