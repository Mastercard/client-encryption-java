package com.mastercard.developer.interceptor;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.interceptors.OkHttpFieldLevelEncryptionInterceptor;
import okhttp3.*;
import okio.Buffer;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import sun.security.x509.X509CertImpl;

import java.io.IOException;

import static com.mastercard.developer.test.TestUtils.getTestFieldLevelEncryptionConfigBuilder;
import static okhttp3.Interceptor.Chain;
import static org.hamcrest.core.Is.isA;
import static org.mockito.Mockito.*;

public class OkHttpFieldLevelEncryptionInterceptorTest {

    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testIntercept_ShouldEncryptRequestPayload() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        OkHttpFieldLevelEncryptionInterceptor instanceUnderTest = new OkHttpFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(chain);

        // THEN
        ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);
        verify(chain).proceed(requestCaptor.capture());
        Request encryptedRequest = requestCaptor.getAllValues().get(0);
        Buffer buffer = new Buffer();
        encryptedRequest.body().writeTo(buffer);
        String encryptedPayload = buffer.readUtf8();
        Assert.assertFalse(encryptedPayload.contains("foo"));
        Assert.assertTrue(encryptedPayload.contains("encryptedFoo"));
        Assert.assertEquals(868, encryptedRequest.body().contentLength());
    }

    @Test
    public void testIntercept_ShouldDoNothing_WhenRequestWithoutPayload() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        OkHttpFieldLevelEncryptionInterceptor instanceUnderTest = new OkHttpFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(chain);

        // THEN
        verify(request).body();
        verifyNoMoreInteractions(request);
    }

    @Test
    public void testIntercept_ShouldThrowIOException_WhenEncryptionFails() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .withEncryptionCertificate(new X509CertImpl()) // Certificate without key
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

        // THEN
        expectedException.expect(IOException.class);
        expectedException.expectMessage("Failed to encrypt request!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        OkHttpFieldLevelEncryptionInterceptor instanceUnderTest = new OkHttpFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(chain);
    }

    @Test
    public void testIntercept_ShouldDecryptResponsePayload() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"a2c494ca28dec4f3d6ce7d68b1044cfe\"," +
                "        \"encryptedKey\": \"038c65f154a2b07f6c788aaddc13ecead05fdeb11eca0bf576cab7185df66349d2cba4ba51a5304d45995e915bb1de462f0f66acd05026b21340b567d141653a2175ccfe2030b3b49261c6750381421cf0e29bd67840bcdc8092a44691c6c74dcdf620d5a744832fce3b45b8e3f8ad1af6c919195eb7f878c7435143e328e8b858dd232dbfacf7bb2f73981a80a09dc7c6dcd49ad95df527d415438958700b48994d7f6207f03d974a5cf50181205ac0a301a91e94b35ad162c8cf39475d2505d8ae7b1d4ed6f170091ab523f037a75eddb5ca46db9328c10395b69f8b798c280fa0e76f8385a64fe37b67e8578f3f9572dfb87d71e80a97323753030966901b\"," +
                "        \"encryptedValue\": \"0672589113046bf692265b6ea6088184\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$.encryptedData", "$.data")
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
        OkHttpFieldLevelEncryptionInterceptor instanceUnderTest = new OkHttpFieldLevelEncryptionInterceptor(config);
        Response response = instanceUnderTest.intercept(chain);

        // THEN
        String expectedPayload = "{\"data\":\"string\"}";
        Assert.assertEquals(expectedPayload, response.body().string());
        Assert.assertEquals(expectedPayload.length(), response.body().contentLength());
    }

    @Test
    public void testIntercept_ShouldDoNothing_WhenResponseWithout() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder().build();
        Request request = mock(Request.class);
        Chain chain = mock(Chain.class);
        Response response = mock(Response.class);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenReturn(response);
        when(response.body()).thenReturn(null);

        // WHEN
        OkHttpFieldLevelEncryptionInterceptor instanceUnderTest = new OkHttpFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(chain);

        // THEN
        verify(response).body();
        verifyNoMoreInteractions(response);
    }

    @Test
    public void testIntercept_ShouldThrowIOException_WhenDecryptionFails() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"a2c494ca28dec4f3d6ce7d68b1044cfe\"," +
                "        \"encryptedKey\": \"NOT A VALID KEY!\"," +
                "        \"encryptedValue\": \"0672589113046bf692265b6ea6088184\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$.encryptedData", "$.data")
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
        expectedException.expectMessage("Failed to decrypt response!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        OkHttpFieldLevelEncryptionInterceptor instanceUnderTest = new OkHttpFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(chain);
    }
}
