package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import com.mastercard.developer.encryption.JweEncryption;
import feign.Response;
import feign.codec.Decoder;

/**
 * A Feign JWE decoder for decrypting parts of HTTP payloads.
 */
public class OpenFeignJweDecoder extends OpenFeignDecoderExecutor {

    private final JweConfig config;

    public OpenFeignJweDecoder(EncryptionConfig config, Decoder delegate) {
        super(delegate);
        this.config = (JweConfig) config;
    }

    @Override
    protected String decryptPayload(Response response, String responsePayload) throws EncryptionException {
        return JweEncryption.decryptPayload(responsePayload, config);
    }
}
