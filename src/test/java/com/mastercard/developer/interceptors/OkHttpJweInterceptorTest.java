package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import okhttp3.*;
import okio.Buffer;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import java.io.IOException;

import static com.mastercard.developer.test.TestUtils.assertPayloadEquals;
import static com.mastercard.developer.test.TestUtils.getTestJweConfigBuilder;
import static okhttp3.Interceptor.Chain;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class OkHttpJweInterceptorTest {

    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testFrom_ShouldReturnTheCorrectInterceptor() throws Exception {
        // GIVEN
        EncryptionConfig config = getTestJweConfigBuilder()
                .build();

        OkHttpEncryptionInterceptor interceptor = OkHttpEncryptionInterceptor.from(config);
        assertTrue(interceptor instanceof OkHttpJweInterceptor);
    }

    @Test
    public void testIntercept_ShouldEncryptRequestPayloadAndUpdateContentLengthHeader() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        Request request = new Request.Builder()
                .url("https://sandbox.api.mastercard.com/service")
                .post(RequestBody.create(JSON_MEDIA_TYPE, "{\"foo\":\"bar\"}"))
                .build();
        Chain chain = mock(Chain.class);
        Response response = mock(Response.class);
        when(chain.request()).thenReturn(request);
        when(response.body()).thenReturn(null);
        when(chain.proceed(any(Request.class))).thenReturn(response);

        // WHEN
        OkHttpJweInterceptor instanceUnderTest = new OkHttpJweInterceptor(config);
        instanceUnderTest.intercept(chain);

        // THEN
        ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);
        verify(chain).proceed(requestCaptor.capture());
        Request encryptedRequest = requestCaptor.getAllValues().get(0);
        Buffer buffer = new Buffer();
        encryptedRequest.body().writeTo(buffer);
        String encryptedPayload = buffer.readUtf8();
        assertFalse(encryptedPayload.contains("foo"));
        assertTrue(encryptedPayload.contains("encryptedFoo"));
        assertEquals(encryptedPayload.length(), encryptedRequest.body().contentLength());
    }

    @Test
    public void testIntercept_ShouldDoNothing_WhenRequestWithoutPayload() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        Request request = mock(Request.class);
        Chain chain = mock(Chain.class);
        Response response = mock(Response.class);
        when(request.body()).thenReturn(null);
        when(response.body()).thenReturn(null);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenReturn(response);

        // WHEN
        OkHttpJweInterceptor instanceUnderTest = new OkHttpJweInterceptor(config);
        instanceUnderTest.intercept(chain);

        // THEN
        verify(request).body();
        verifyNoMoreInteractions(request);
    }

    @Test
    public void testIntercept_ShouldDecryptResponsePayloadAndUpdateContentLengthHeader() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$")
                .build();
        Request request = mock(Request.class);
        Response encryptedResponse = new Response.Builder()
                .body(ResponseBody.create(JSON_MEDIA_TYPE, encryptedPayload))
                .request(request)
                .code(200)
                .protocol(Protocol.HTTP_1_1)
                .message("")
                .build();
        Chain chain = mock(Chain.class);
        when(request.body()).thenReturn(null);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenReturn(encryptedResponse);

        // WHEN
        OkHttpJweInterceptor instanceUnderTest = new OkHttpJweInterceptor(config);
        Response response = instanceUnderTest.intercept(chain);

        // THEN
        String payload = response.body().string();
        assertPayloadEquals("{\"foo\":\"bar\"}", payload);
        assertEquals(payload.length(), response.body().contentLength());
    }

    @Test
    public void testInterceptResponse_ShouldDecryptWithA128CBC_HS256Encryption() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$.foo")
                .build();
        Request request = mock(Request.class);
        Response encryptedResponse = new Response.Builder()
                .body(ResponseBody.create(JSON_MEDIA_TYPE, encryptedPayload))
                .request(request)
                .code(200)
                .protocol(Protocol.HTTP_1_1)
                .message("")
                .build();
        Chain chain = mock(Chain.class);
        when(request.body()).thenReturn(null);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenReturn(encryptedResponse);

        // WHEN
        OkHttpJweInterceptor instanceUnderTest = new OkHttpJweInterceptor(config);
        Response response = instanceUnderTest.intercept(chain);

        // THEN
        String payload = response.body().string();
        assertPayloadEquals("{\"foo\":\"bar\"}", payload);
        assertEquals(payload.length(), response.body().contentLength());
    }

    @Test
    public void testIntercept_ShouldDoNothing_WhenResponseWithoutPayload() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder().build();
        Request request = mock(Request.class);
        Chain chain = mock(Chain.class);
        Response response = mock(Response.class);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenReturn(response);
        when(response.body()).thenReturn(null);

        // WHEN
        OkHttpJweInterceptor instanceUnderTest = new OkHttpJweInterceptor(config);
        instanceUnderTest.intercept(chain);

        // THEN
        verify(response).body();
        verifyNoMoreInteractions(response);
    }

    @Test
    public void testIntercept_ShouldDoNothing_WhenResponseWithEmptyPayload() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder().build();
        Request request = mock(Request.class);
        Chain chain = mock(Chain.class);
        Response response = mock(Response.class);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenReturn(response);
        when(response.body()).thenReturn(ResponseBody.create(JSON_MEDIA_TYPE, ""));

        // WHEN
        OkHttpJweInterceptor instanceUnderTest = new OkHttpJweInterceptor(config);
        instanceUnderTest.intercept(chain);

        // THEN
        verify(response).body();
        verifyNoMoreInteractions(response);
    }

    @Test
    public void testIntercept_ShouldThrowIOException_WhenDecryptionFails() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "\"encryptedPayload\":\"NOT-VALID\"}";

        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedPayload", "$.data")
                .build();

        Request request = mock(Request.class);
        Chain chain = mock(Chain.class);
        Response response = mock(Response.class);
        when(request.body()).thenReturn(null);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenReturn(response);
        when(response.body()).thenReturn(ResponseBody.create(JSON_MEDIA_TYPE, encryptedPayload));

        // THEN
        expectedException.expect(IOException.class);
        expectedException.expectMessage("Failed to intercept and decrypt response!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        OkHttpJweInterceptor instanceUnderTest = new OkHttpJweInterceptor(config);
        instanceUnderTest.intercept(chain);
    }
}
