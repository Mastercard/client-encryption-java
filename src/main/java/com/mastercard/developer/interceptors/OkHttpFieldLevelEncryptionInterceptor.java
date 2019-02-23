package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryption;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import okhttp3.*;
import okio.Buffer;

import java.io.IOException;

/**
 * An OkHttp3 interceptor for encrypting/decrypting parts of HTTP payloads.
 * See: https://github.com/square/okhttp/wiki/Interceptors
 */
public class OkHttpFieldLevelEncryptionInterceptor implements Interceptor {

    private final FieldLevelEncryptionConfig config;

    public OkHttpFieldLevelEncryptionInterceptor(FieldLevelEncryptionConfig config) {
        this.config = config;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request encryptedRequest = handleRequest(chain.request(), config);
        Response encryptedResponse = chain.proceed(encryptedRequest);
        return handleResponse(encryptedResponse, config);
    }

    private static Request handleRequest(Request request, FieldLevelEncryptionConfig config) throws IOException {
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

            // Encrypt fields
            String encryptedPayload = FieldLevelEncryption.encryptPayload(requestPayload, config);
            RequestBody encryptedBody = RequestBody.create(requestBody.contentType(), encryptedPayload);
            return request.newBuilder()
                    .method(request.method(), encryptedBody)
                    .header("Content-Length", String.valueOf(encryptedBody.contentLength()))
                    .build();

        } catch (EncryptionException e) {
            throw new IOException("Failed to encrypt request!", e);
        }
    }

    private static Response handleResponse(Response response, FieldLevelEncryptionConfig config) throws IOException {
        try {
            // Check response actually has a payload
            ResponseBody responseBody = response.body();
            if (null == responseBody) {
                // Nothing to decrypt
                return response;
            }

            // Read response payload
            String responsePayload = responseBody.string();
            if (null == responsePayload || responsePayload.length() == 0) {
                // Nothing to decrypt
                return response;
            }

            // Decrypt fields
            String decryptedPayload = FieldLevelEncryption.decryptPayload(responsePayload, config);
            try (ResponseBody decryptedBody = ResponseBody.create(responseBody.contentType(), decryptedPayload)) {
                return response.newBuilder()
                        .body(decryptedBody)
                        .header("Content-Length", String.valueOf(decryptedBody.contentLength()))
                        .build();
            }
        } catch (EncryptionException e) {
            throw new IOException("Failed to decrypt response!", e);
        }
    }
}
