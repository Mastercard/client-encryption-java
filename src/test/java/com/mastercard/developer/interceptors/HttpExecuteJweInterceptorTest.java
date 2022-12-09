package com.mastercard.developer.interceptors;

import com.google.api.client.http.*;
import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import static com.mastercard.developer.test.TestUtils.assertPayloadEquals;
import static com.mastercard.developer.test.TestUtils.getTestJweConfigBuilder;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class HttpExecuteJweInterceptorTest {

    private static final String JSON_TYPE = "application/json; charset=utf-8";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testFrom_ShouldReturnTheCorrectInterceptor() throws Exception {
        // GIVEN
        EncryptionConfig config = getTestJweConfigBuilder()
                .build();

        HttpExecuteEncryptionInterceptor interceptor = HttpExecuteEncryptionInterceptor.from(config);
        assertTrue(interceptor instanceof HttpExecuteJweInterceptor);
    }

    @Test
    public void testIntercept_ShouldEncryptRequestPayloadAndUpdateContentLengthHeader() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$", "$")
                .withEncryptedValueFieldName("encryptedPayload")
                .build();
        HttpRequest request = mock(HttpRequest.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        when(request.getContent()).thenReturn(new ByteArrayContent(JSON_TYPE, "{\"foo\":\"bar\"}".getBytes()));
        when(request.getHeaders()).thenReturn(httpHeaders);

        // WHEN
        HttpExecuteJweInterceptor instanceUnderTest = new HttpExecuteJweInterceptor(config);
        instanceUnderTest.intercept(request);

        // THEN
        ArgumentCaptor<HttpContent> contentCaptor = ArgumentCaptor.forClass(HttpContent.class);
        verify(request).setContent(contentCaptor.capture());
        ByteArrayOutputStream encryptedPayloadStream = new ByteArrayOutputStream();
        contentCaptor.getValue().writeTo(encryptedPayloadStream);
        String encryptedPayload = encryptedPayloadStream.toString(StandardCharsets.UTF_8.name());
        Assert.assertFalse(encryptedPayload.contains("foo"));
        Assert.assertTrue(encryptedPayload.contains("encryptedPayload"));
        assertEquals(encryptedPayload.length(), httpHeaders.getContentLength().intValue());
    }

    @Test
    public void testIntercept_ShouldDoNothing_WhenNoPayload() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder()
                .build();

        HttpRequest request = mock(HttpRequest.class);
        when(request.getContent()).thenReturn(null);

        // WHEN
        HttpExecuteJweInterceptor instanceUnderTest = new HttpExecuteJweInterceptor(config);
        instanceUnderTest.intercept(request);

        // THEN
        verify(request).getContent();
        verifyNoMoreInteractions(request);
    }

    @Test
    public void testInterceptResponse_ShouldDecryptResponsePayloadAndUpdateContentLengthHeader() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$")
                .build();
        HttpResponse response = mock(HttpResponse.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentLength(100L);
        when(response.parseAsString()).thenReturn(encryptedPayload);
        when(response.getHeaders()).thenReturn(httpHeaders);

        // WHEN
        HttpExecuteJweInterceptor instanceUnderTest = new HttpExecuteJweInterceptor(config);
        instanceUnderTest.interceptResponse(response);

        // THEN
        Field contentField = response.getClass().getDeclaredField("content");
        contentField.setAccessible(true);
        InputStream payloadInputStream = (InputStream) contentField.get(response);
        String payload = IOUtils.toString(payloadInputStream, StandardCharsets.UTF_8);
        assertPayloadEquals("{\"foo\":\"bar\"}", payload);
        assertEquals(payload.length(), httpHeaders.getContentLength().intValue());
    }

    @Test
    public void testInterceptResponse_ShouldDecryptWithA128CBC_HS256Encryption() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$.foo")
                .build();
        HttpResponse response = mock(HttpResponse.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentLength(100L);
        when(response.parseAsString()).thenReturn(encryptedPayload);
        when(response.getHeaders()).thenReturn(httpHeaders);

        // WHEN
        HttpExecuteJweInterceptor instanceUnderTest = new HttpExecuteJweInterceptor(config);
        instanceUnderTest.interceptResponse(response);

        // THEN
        Field contentField = response.getClass().getDeclaredField("content");
        contentField.setAccessible(true);
        InputStream payloadInputStream = (InputStream) contentField.get(response);
        String payload = IOUtils.toString(payloadInputStream, StandardCharsets.UTF_8);
        assertPayloadEquals("{\"foo\":\"bar\"}", payload);
        assertEquals(payload.length(), httpHeaders.getContentLength().intValue());
    }

    @Test
    public void testInterceptResponse_ShouldThrowAnExceptionWhenEncryptionNotSupported() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJlbmMiOiJYQzIwUCIsImFsZyI6IlJTQS1PQUVQLTI1NiJ9.7CF3JQoFw9BBsbDVX4TFcDBsrfSp1cUl1V6VsKqoXwappcidYKUlgaSfqnRi3u1MAQimqQ8DpoImXICmZtGwhA4TeUzR16HJvW2W-0OQ9MC9oWW7b00U8Whds1jomOGaI4Hbs3gqvLieXEbl05UtpLbK8vqSbiN1kxyftKIGZvNQS0PvHoZMdVAROiMbG0-T8GY1NfOgAumZvATNBZHL-FaV25_pZhIIkhMBfDDBlRL5abn1Zc_IM1WzaZbLXVpggfTSFbKQEKMnGdDc9LXP_MCUcfvdjdD3NApuq_7tbUvEpEyNzGCnL9KD_1iyz2RFQZUfx1aHXJ3tpO4Gvk7rXg.haTi4wWtgKvvEi8yXToc0UUuBBhMLING.wP9pmYHOZxkmKD_H9A.6Ir2s-8s9vF75BxuLl26hw\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$.foo")
                .build();
        HttpResponse response = mock(HttpResponse.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentLength(100L);
        when(response.parseAsString()).thenReturn(encryptedPayload);
        when(response.getHeaders()).thenReturn(httpHeaders);

        // THEN
        expectedException.expect(IOException.class);
        expectedException.expectCause(isA(EncryptionException.class));
        HttpExecuteJweInterceptor instanceUnderTest = new HttpExecuteJweInterceptor(config);
        instanceUnderTest.interceptResponse(response);
    }

    @Test
    public void testInterceptResponse_ShouldDoNothing_WhenNoPayload() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder().build();
        HttpResponse response = mock(HttpResponse.class);
        when(response.parseAsString()).thenReturn(null);

        // WHEN
        HttpExecuteJweInterceptor instanceUnderTest = new HttpExecuteJweInterceptor(config);
        instanceUnderTest.interceptResponse(response);

        // THEN
        verify(response).parseAsString();
        verifyNoMoreInteractions(response);
    }

    @Test
    public void testInterceptResponse_ShouldThrowIOException_WhenDecryptionFails() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"NOT-VALID\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$")
                .build();
        HttpResponse response = mock(HttpResponse.class);
        when(response.parseAsString()).thenReturn(encryptedPayload);

        // THEN
        expectedException.expect(IOException.class);
        expectedException.expectMessage("Failed to intercept and decrypt response!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        HttpExecuteJweInterceptor instanceUnderTest = new HttpExecuteJweInterceptor(config);
        instanceUnderTest.interceptResponse(response);
    }
}
