package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import com.mastercard.developer.encryption.JweEncryption;
import okhttp3.Request;
import okhttp3.Response;

/**
 * An OkHttp3 JWE interceptor for encrypting/decrypting parts of HTTP payloads.
 */
public class OkHttpJweInterceptor extends OkHttpEncryptionInterceptor {

    private final JweConfig config;

    public OkHttpJweInterceptor(EncryptionConfig config) {
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
