package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryption;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.encryption.FieldLevelEncryptionParams;
import okhttp3.*;
import okio.Buffer;

import java.io.IOException;

import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;

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

            // Encrypt fields & update headers
            String encryptedPayload;
            Request.Builder requestBuilder = request.newBuilder();
            if (config.useHttpHeaders()) {
                // Generate encryption params and add them as HTTP headers
                FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);
                updateHeader(requestBuilder, config.getIvHeaderName(), params.getIvValue());
                updateHeader(requestBuilder, config.getEncryptedKeyHeaderName(), params.getEncryptedKeyValue());
                updateHeader(requestBuilder, config.getEncryptionCertificateFingerprintHeaderName(), config.getEncryptionCertificateFingerprint());
                updateHeader(requestBuilder, config.getEncryptionKeyFingerprintHeaderName(), config.getEncryptionKeyFingerprint());
                updateHeader(requestBuilder, config.getOaepPaddingDigestAlgorithmHeaderName(), params.getOaepPaddingDigestAlgorithmValue());
                encryptedPayload = FieldLevelEncryption.encryptPayload(requestPayload, config, params);
            } else {
                // Encryption params will be stored in the payload
                encryptedPayload = FieldLevelEncryption.encryptPayload(requestPayload, config);
            }

            RequestBody encryptedBody = RequestBody.create(requestBody.contentType(), encryptedPayload);
            return requestBuilder
                    .method(request.method(), encryptedBody)
                    .header("Content-Length", String.valueOf(encryptedBody.contentLength()))
                    .build();

        } catch (EncryptionException e) {
            throw new IOException("Failed to intercept and encrypt request!", e);
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
            if (isNullOrEmpty(responsePayload)) {
                // Nothing to decrypt
                return response;
            }

            // Decrypt fields & update headers
            String decryptedPayload;
            Response.Builder responseBuilder = response.newBuilder();
            if (config.useHttpHeaders()) {
                // Read encryption params from HTTP headers and delete headers
                String ivValue = response.header(config.getIvHeaderName(), null);
                String oaepPaddingDigestAlgorithmValue = response.header(config.getOaepPaddingDigestAlgorithmHeaderName(), null);
                String encryptedKeyValue = response.header(config.getEncryptedKeyHeaderName(), null);
                removeHeader(responseBuilder, config.getIvHeaderName());
                removeHeader(responseBuilder, config.getEncryptedKeyHeaderName());
                removeHeader(responseBuilder, config.getOaepPaddingDigestAlgorithmHeaderName());
                removeHeader(responseBuilder, config.getEncryptionCertificateFingerprintHeaderName());
                removeHeader(responseBuilder, config.getEncryptionKeyFingerprintHeaderName());
                FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivValue, encryptedKeyValue, oaepPaddingDigestAlgorithmValue, config);
                decryptedPayload = FieldLevelEncryption.decryptPayload(responsePayload, config, params);
            } else {
                // Encryption params are stored in the payload
                decryptedPayload = FieldLevelEncryption.decryptPayload(responsePayload, config);
            }

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

    private static void removeHeader(Response.Builder responseBuilder, String name) {
        if (name == null) {
            // Do nothing
            return;
        }
        responseBuilder.removeHeader(name);
    }

    private static void updateHeader(Request.Builder requestBuilder, String name, String value) {
        if (name == null) {
            // Do nothing
            return;
        }
        requestBuilder.header(name, value);
    }
}
