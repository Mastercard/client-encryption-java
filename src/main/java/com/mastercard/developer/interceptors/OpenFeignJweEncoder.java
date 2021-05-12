package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import com.mastercard.developer.encryption.JweEncryption;
import feign.RequestTemplate;
import feign.codec.Encoder;

/**
 * A Feign JWE encoder for encrypting parts of HTTP payloads.
 */
public class OpenFeignJweEncoder extends OpenFeignEncoderExecutor {

    private final JweConfig config;

    public OpenFeignJweEncoder(EncryptionConfig config, Encoder delegate) {
        super(delegate);
        this.config = (JweConfig) config;
    }

    @Override
    protected String encryptPayload(RequestTemplate requestTemplate, String requestPayload) throws EncryptionException {
        return JweEncryption.encryptPayload(requestPayload, config);
    }
}
