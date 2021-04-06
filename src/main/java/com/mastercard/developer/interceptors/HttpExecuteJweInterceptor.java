package com.mastercard.developer.interceptors;

import com.google.api.client.http.HttpHeaders;
import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import com.mastercard.developer.encryption.JweEncryption;

/**
 * A Google Client API JWE interceptor for encrypting/decrypting parts of HTTP payloads.
 */
public class HttpExecuteJweInterceptor extends HttpExecuteEncryptionInterceptor {

    private final JweConfig config;

    public HttpExecuteJweInterceptor(EncryptionConfig config) {
        this.config = (JweConfig) config;
    }

    @Override
    protected String encryptPayload(HttpHeaders headers, String requestPayload) throws EncryptionException {
        return JweEncryption.encryptPayload(requestPayload, config);
    }

    @Override
    protected String decryptPayload(HttpHeaders headers, String responsePayload) throws EncryptionException {
        return JweEncryption.decryptPayload(responsePayload, config);
    }
}
