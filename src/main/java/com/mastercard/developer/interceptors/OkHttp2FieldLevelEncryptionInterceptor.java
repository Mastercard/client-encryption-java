package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.*;
import com.squareup.okhttp.*;

/**
 * An OkHttp2 interceptor for encrypting/decrypting parts of HTTP payloads.
 * See: https://github.com/square/okhttp/wiki/Interceptors
 */
public class OkHttp2FieldLevelEncryptionInterceptor extends OkHttp2EncryptionInterceptor {

    private final FieldLevelEncryptionConfig config;

    public OkHttp2FieldLevelEncryptionInterceptor(EncryptionConfig config) {
        this.config = (FieldLevelEncryptionConfig) config;
    }

    @Override
    protected String encryptPayload(Request request, Request.Builder requestBuilder, String requestPayload) throws EncryptionException {
        if (config.useHttpHeaders()) {
            // Generate encryption params and add them as HTTP headers
            FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);
            updateHeader(requestBuilder, config.getIvHeaderName(), params.getIvValue());
            updateHeader(requestBuilder, config.getEncryptedKeyHeaderName(), params.getEncryptedKeyValue());
            updateHeader(requestBuilder, config.getEncryptionCertificateFingerprintHeaderName(), config.getEncryptionCertificateFingerprint());
            updateHeader(requestBuilder, config.getEncryptionKeyFingerprintHeaderName(), config.getEncryptionKeyFingerprint());
            updateHeader(requestBuilder, config.getOaepPaddingDigestAlgorithmHeaderName(), params.getOaepPaddingDigestAlgorithmValue());
            return FieldLevelEncryption.encryptPayload(requestPayload, config, params);
        } else {
            // Encryption params will be stored in the payload
            return FieldLevelEncryption.encryptPayload(requestPayload, config);
        }
    }

    @Override
    protected String decryptPayload(Response response, Response.Builder responseBuilder, String responsePayload) throws EncryptionException {
        if (config.useHttpHeaders()) {
            // Read encryption params from HTTP headers and delete headers
            String ivValue = response.header(config.getIvHeaderName());
            String oaepPaddingDigestAlgorithmValue = response.header(config.getOaepPaddingDigestAlgorithmHeaderName());
            String encryptedKeyValue = response.header(config.getEncryptedKeyHeaderName());
            removeHeader(responseBuilder, config.getIvHeaderName());
            removeHeader(responseBuilder, config.getEncryptedKeyHeaderName());
            removeHeader(responseBuilder, config.getOaepPaddingDigestAlgorithmHeaderName());
            removeHeader(responseBuilder, config.getEncryptionCertificateFingerprintHeaderName());
            removeHeader(responseBuilder, config.getEncryptionKeyFingerprintHeaderName());
            FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivValue, encryptedKeyValue, oaepPaddingDigestAlgorithmValue, config);
            return FieldLevelEncryption.decryptPayload(responsePayload, config, params);
        } else {
            // Encryption params are stored in the payload
            return FieldLevelEncryption.decryptPayload(responsePayload, config);
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
