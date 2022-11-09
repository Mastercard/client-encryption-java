package com.mastercard.developer.encryption.jwe;

import com.google.common.collect.ImmutableList;
import com.mastercard.developer.test.TestUtils;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;

public class JWEObjectTest {

    @Test
    public void testDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIsCbcEncrypted() throws Exception {
        JweObject jweObject = TestUtils.getTestCbcJweObject();
        String decryptedPayload = jweObject.decrypt(TestUtils.getTestJweConfigBuilder().build());

        assertEquals("bar", decryptedPayload);
    }

    private static Stream<Arguments> aesGcmJweObjects() {
        return ImmutableList.of(
                        TestUtils.getTestAes128GcmJweObject(),
                        TestUtils.getTestAes192GcmJweObject(),
                        TestUtils.getTestAes256GcmJweObject())
                .stream()
                .map(jweObject -> Arguments.of(jweObject.getHeader().getEnc(), jweObject));
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("aesGcmJweObjects")
    public void testDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIsGcmEncrypted(String name, JweObject jweObject) throws Exception {
        String decryptedPayload = jweObject.decrypt(TestUtils.getTestJweConfigBuilder().build());

        assertEquals("{\"foo\":\"bar\"}", decryptedPayload);
    }
}
