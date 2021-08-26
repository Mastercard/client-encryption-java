package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import feign.Response;
import feign.Util;
import feign.codec.DecodeException;
import feign.codec.Decoder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

import static com.mastercard.developer.test.TestUtils.assertPayloadEquals;
import static com.mastercard.developer.test.TestUtils.getTestJweConfigBuilder;
import static com.mastercard.developer.utils.FeignUtils.readHeader;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class OpenFeignJweDecoderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testFrom_ShouldReturnTheCorrectInterceptor() throws Exception {
        // GIVEN
        EncryptionConfig config = getTestJweConfigBuilder()
                .build();
        Decoder delegate = mock(Decoder.class);

        OpenFeignDecoderExecutor executor = OpenFeignDecoderExecutor.from(config, delegate);
        assertTrue(executor instanceof OpenFeignJweDecoder);
    }

    @Test
    public void testDecode_ShouldDecryptResponsePayloadAndUpdateContentLengthHeader() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$")
                .build();

        Type type = mock(Type.class);
        HashMap<String, Collection<String>> headers = new HashMap<String, Collection<String>>() {
            {
                put("content-length", Collections.singleton("100"));
            }
        };
        Response response = Response.builder()
                .status(200)
                .headers(headers)
                .body(encryptedPayload, StandardCharsets.UTF_8)
                .build();
        Decoder delegate = mock(Decoder.class);

        // WHEN
        OpenFeignJweDecoder instanceUnderTest = new OpenFeignJweDecoder(config, delegate);
        instanceUnderTest.decode(response, type);

        // THEN
        ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
        verify(delegate).decode(responseCaptor.capture(), any(Type.class));
        Response responseValue = responseCaptor.getValue();
        String payload = Util.toString(responseValue.body().asReader());
        assertPayloadEquals("{\"foo\":\"bar\"}", payload);
        assertEquals(String.valueOf(payload.length()), readHeader(responseValue, "Content-Length"));
    }

    @Test
    public void testDecode_ShouldDecryptWithA128CBC_HS256Encryption() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$.foo")
                .build();

        Type type = mock(Type.class);
        HashMap<String, Collection<String>> headers = new HashMap<String, Collection<String>>() {
            {
                put("content-length", Collections.singleton("100"));
            }
        };
        Response response = Response.builder()
                .status(200)
                .headers(headers)
                .body(encryptedPayload, StandardCharsets.UTF_8)
                .build();
        Decoder delegate = mock(Decoder.class);

        // WHEN
        OpenFeignJweDecoder instanceUnderTest = new OpenFeignJweDecoder(config, delegate);
        instanceUnderTest.decode(response, type);

        // THEN
        ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
        verify(delegate).decode(responseCaptor.capture(), any(Type.class));
        Response responseValue = responseCaptor.getValue();
        String payload = Util.toString(responseValue.body().asReader());
        assertPayloadEquals("{\"foo\":\"bar\"}", payload);
        assertEquals(String.valueOf(payload.length()), readHeader(responseValue, "Content-Length"));
    }

    @Test
    public void testDecode_ShouldDoNothing_WhenNoPayload() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder().build();
        Type type = mock(Type.class);
        Response response = mock(Response.class);
        Decoder delegate = mock(Decoder.class);
        when(response.body()).thenReturn(null);

        // WHEN
        OpenFeignJweDecoder instanceUnderTest = new OpenFeignJweDecoder(config, delegate);
        instanceUnderTest.decode(response, type);

        // THEN
        verify(delegate).decode(any(Response.class), any(Type.class));
        verify(response).body();
        verifyNoMoreInteractions(response);
    }

    @Test
    public void testDecode_ShouldDoNothing_WhenEmptyPayload() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder().build();
        Type type = mock(Type.class);
        Response response = mock(Response.class);
        when(response.body()).thenReturn(buildResponseBody(""));
        Decoder delegate = mock(Decoder.class);

        // WHEN
        OpenFeignJweDecoder instanceUnderTest = new OpenFeignJweDecoder(config, delegate);
        instanceUnderTest.decode(response, type);

        // THEN
        verify(delegate).decode(any(Response.class), any(Type.class));
        verify(response).body();
        verifyNoMoreInteractions(response);
    }

    @Test
    public void testDecode_ShouldThrowDecodeException_WhenDecryptionFails() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"NOT-VALID\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$.data")
                .build();

        Type type = mock(Type.class);
        Response response = mock(Response.class);
        when(response.body()).thenReturn(buildResponseBody(encryptedPayload));
        Decoder delegate = mock(Decoder.class);

        // THEN
        expectedException.expect(DecodeException.class);
        expectedException.expectMessage("Failed to intercept and decrypt response!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        OpenFeignJweDecoder instanceUnderTest = new OpenFeignJweDecoder(config, delegate);
        instanceUnderTest.decode(response, type);
    }

    private static Response.Body buildResponseBody(String payload) {
        Response response = Response.builder()
                .status(200)
                .headers(new HashMap<>())
                .body(payload, StandardCharsets.UTF_8)
                .build();
        return response.body();
    }
}
