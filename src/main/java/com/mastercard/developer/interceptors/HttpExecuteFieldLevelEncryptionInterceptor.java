package com.mastercard.developer.interceptors;

import com.google.api.client.http.HttpHeaders;
import com.mastercard.developer.encryption.*;

/**
 * A Google Client API interceptor for encrypting/decrypting parts of HTTP payloads.
 * See also:
 * - {@link com.google.api.client.http.HttpExecuteInterceptor}
 * - {@link com.google.api.client.http.HttpResponseInterceptor}
 */
public class HttpExecuteFieldLevelEncryptionInterceptor extends HttpExecuteEncryptionInterceptor {

    private final FieldLevelEncryptionConfig config;

    public HttpExecuteFieldLevelEncryptionInterceptor(EncryptionConfig config) {
        this.config = (FieldLevelEncryptionConfig) config;
    }

    @Override
    protected String encryptPayload(HttpHeaders headers, String requestPayload) throws EncryptionException {
        if (config.useHttpHeaders()) {
            // Generate encryption params and add them as HTTP headers
            FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);
            updateHeader(headers, config.getIvHeaderName(), params.getIvValue());
            updateHeader(headers, config.getEncryptedKeyHeaderName(), params.getEncryptedKeyValue());
            updateHeader(headers, config.getEncryptionCertificateFingerprintHeaderName(), config.getEncryptionCertificateFingerprint());
            updateHeader(headers, config.getEncryptionKeyFingerprintHeaderName(), config.getEncryptionKeyFingerprint());
            updateHeader(headers, config.getOaepPaddingDigestAlgorithmHeaderName(), params.getOaepPaddingDigestAlgorithmValue());
            return FieldLevelEncryption.encryptPayload(requestPayload, config, params);
        } else {
            // Encryption params will be stored in the payload
            return FieldLevelEncryption.encryptPayload(requestPayload, config);
        }
    }

    @Override
    protected String decryptPayload(HttpHeaders headers, String responsePayload) throws EncryptionException {
        if (config.useHttpHeaders()) {
            // Read encryption params from HTTP headers and delete headers
            String ivValue = headers.getFirstHeaderStringValue(config.getIvHeaderName());
            String oaepPaddingDigestAlgorithmValue = headers.getFirstHeaderStringValue(config.getOaepPaddingDigestAlgorithmHeaderName());
            String encryptedKeyValue = headers.getFirstHeaderStringValue(config.getEncryptedKeyHeaderName());
            removeHeader(headers, config.getIvHeaderName());
            removeHeader(headers, config.getEncryptedKeyHeaderName());
            removeHeader(headers, config.getOaepPaddingDigestAlgorithmHeaderName());
            removeHeader(headers, config.getEncryptionCertificateFingerprintHeaderName());
            removeHeader(headers, config.getEncryptionKeyFingerprintHeaderName());
            FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivValue, encryptedKeyValue, oaepPaddingDigestAlgorithmValue, config);
            return FieldLevelEncryption.decryptPayload(responsePayload, config, params);
        } else {
            // Encryption params are stored in the payload
            return FieldLevelEncryption.decryptPayload(responsePayload, config);
        }
    }
}
