package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import com.mastercard.developer.encryption.JweEncryption;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

/**
 * An OkHttp2 JWE interceptor for encrypting/decrypting parts of HTTP payloads.
 */
public class OkHttp2JweInterceptor extends OkHttp2EncryptionInterceptor {

    private final JweConfig config;

    public OkHttp2JweInterceptor(EncryptionConfig config) {
        this.config = (JweConfig) config;
    }

    @Override
    protected String encryptPayload(Request request, Request.Builder requestBuilder, String requestPayload) throws EncryptionException {
        return JweEncryption.encryptPayload(requestPayload, config);
    }

    @Override
    protected String decryptPayload(Response response, Response.Builder responseBuilder, String responsePayload) throws EncryptionException {
        return JweEncryption.decryptPayload(responsePayload, config);
    }
}
