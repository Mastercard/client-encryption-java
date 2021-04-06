package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.ResponseBody;
import com.squareup.okhttp.Interceptor;
import okio.Buffer;
import java.io.IOException;
import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;

public abstract class OkHttp2EncryptionInterceptor implements Interceptor {

    protected abstract String encryptPayload(Request request, Request.Builder newBuilder, String requestPayload) throws EncryptionException;

    protected abstract String decryptPayload(com.squareup.okhttp.Response response, com.squareup.okhttp.Response.Builder newBuilder, String responsePayload) throws EncryptionException;

    public static OkHttp2EncryptionInterceptor from(EncryptionConfig config) {
        return config.getScheme().equals(EncryptionConfig.Scheme.JWE) ? new OkHttp2JweInterceptor(config) : new OkHttp2FieldLevelEncryptionInterceptor(config);
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request encryptedRequest = handleRequest(chain.request());
        Response encryptedResponse = chain.proceed(encryptedRequest);
        return handleResponse(encryptedResponse);
    }

    private Request handleRequest(Request request) throws IOException {
        try {
            // Check request actually has a payload
            RequestBody requestBody = request.body();
            if (null == requestBody || requestBody.contentLength() == 0) {
                // Nothing to encrypt
                return request;
            }

            // Read request payload
            String requestPayload;
            try (Buffer buffer = new Buffer()) {
                request.body().writeTo(buffer);
                requestPayload = buffer.readUtf8();
            }

            // Encrypt fields & update headers
            Request.Builder requestBuilder = request.newBuilder();
            String encryptedPayload = encryptPayload(request, requestBuilder, requestPayload);

            RequestBody encryptedBody = RequestBody.create(requestBody.contentType(), encryptedPayload);
            return requestBuilder
                    .method(request.method(), encryptedBody)
                    .header("Content-Length", String.valueOf(encryptedBody.contentLength()))
                    .build();

        } catch (EncryptionException e) {
            throw new IOException("Failed to intercept and encrypt request!", e);
        }
    }

    private Response handleResponse(Response response) throws IOException {
        try {
            // Check response actually has a payload
            ResponseBody responseBody = response.body();
            if (null == responseBody) {
                // Nothing to decrypt
                return response;
            }

            // Read response payload
            String responsePayload = responseBody.string();
            if (isNullOrEmpty(responsePayload)) {
                // Nothing to decrypt
                return response;
            }

            // Decrypt fields & update headers
            Response.Builder responseBuilder = response.newBuilder();
            String decryptedPayload = decryptPayload(response, responseBuilder, responsePayload);

            try (ResponseBody decryptedBody = ResponseBody.create(responseBody.contentType(), decryptedPayload)) {
                return responseBuilder
                        .body(decryptedBody)
                        .header("Content-Length", String.valueOf(decryptedBody.contentLength()))
                        .build();
            }
        } catch (EncryptionException e) {
            throw new IOException("Failed to intercept and decrypt response!", e);
        }
    }
}
