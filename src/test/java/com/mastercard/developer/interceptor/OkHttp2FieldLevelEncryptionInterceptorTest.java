package com.mastercard.developer.interceptor;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.interceptors.OkHttp2FieldLevelEncryptionInterceptor;
import com.squareup.okhttp.*;
import okio.Buffer;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

import static com.mastercard.developer.test.TestUtils.getFieldLevelEncryptionConfigBuilder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class OkHttp2FieldLevelEncryptionInterceptorTest {

    private final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");

    @Test
    public void testIntercept_Nominal() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .withDecryptionPath("$.encryptedFoo", "$.foo")
                .build();
        OkHttpClient client = new OkHttpClient();
        client.interceptors().add(new OkHttp2FieldLevelEncryptionInterceptor(config));
        client.interceptors().add(new MockServiceInterceptor());

        // WHEN
        String payload = "{\"foo\":\"bar\"}";
        RequestBody body = RequestBody.create(JSON_MEDIA_TYPE, payload);
        Request request = new Request.Builder()
                .url("https://sandbox.api.mastercard.com/service")
                .post(body)
                .build();
        Response response = client.newCall(request).execute();

        // THEN
        Assert.assertEquals(201, response.code());
        String responsePayload = new String(response.body().bytes());
        JsonObject payloadObject = new Gson().fromJson(responsePayload, JsonObject.class);
        assertNull(payloadObject.get("encryptedFoo"));
        assertEquals("\"bar\"", payloadObject.get("foo").toString());
    }

    @Test
    public void testIntercept_ShouldDoNothing_WhenNoPayloads() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .withDecryptionPath("$.encryptedFoo", "$.foo")
                .build();
        OkHttpClient client = new OkHttpClient();
        client.interceptors().add(new OkHttp2FieldLevelEncryptionInterceptor(config));
        client.interceptors().add(new MockServiceInterceptor());

        // WHEN
        Request request = new Request.Builder()
                .url("https://sandbox.api.mastercard.com/service")
                .build();
        Response response = client.newCall(request).execute();

        // THEN
        Assert.assertEquals(201, response.code());
    }

    private class MockServiceInterceptor implements Interceptor {

        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            RequestBody requestBody = request.body();
            if (null != requestBody && requestBody.contentLength() > 0) {
                // Check the request contains encrypted fields
                String payload;
                try (Buffer buffer = new Buffer()) {
                    request.body().writeTo(buffer);
                    payload = buffer.readUtf8();
                }
                Assert.assertFalse(payload.contains("foo"));
                Assert.assertTrue(payload.contains("encryptedFoo"));

                // Return a payload with encrypted fields
                try (ResponseBody responseBody = ResponseBody.create(JSON_MEDIA_TYPE, payload)) {
                    return new Response.Builder()
                            .body(responseBody)
                            .protocol(Protocol.HTTP_1_1)
                            .code(201)
                            .request(request)
                            .build();
                }
            } else {
                // Return a response without payload
                return new Response.Builder()
                        .protocol(Protocol.HTTP_1_1)
                        .code(201)
                        .request(request)
                        .build();
            }
        }
    }
}
