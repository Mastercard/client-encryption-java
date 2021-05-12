package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import feign.RequestTemplate;
import feign.codec.EncodeException;
import feign.codec.Encoder;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

import static com.mastercard.developer.utils.FeignUtils.updateHeader;

/**
 * A Feign encoder for encrypting parts of HTTP payloads.
 */
public abstract class OpenFeignEncoderExecutor implements Encoder {

    public static OpenFeignEncoderExecutor from(EncryptionConfig config, Encoder delegate) {
        return config.getScheme().equals(EncryptionConfig.Scheme.JWE) ?
                new OpenFeignJweEncoder(config, delegate) : new OpenFeignFieldLevelEncryptionEncoder(config, delegate);
    }

    private final Encoder delegate;

    OpenFeignEncoderExecutor(Encoder delegate) {
        this.delegate = delegate;
    }

    protected abstract String encryptPayload(RequestTemplate requestTemplate, String requestPayload) throws EncryptionException;

    @Override
    public void encode(Object object, Type type, RequestTemplate requestTemplate) {
        // Call the regular encoder
        delegate.encode(object, type, requestTemplate);

        try {
            // Check request actually has a payload
            byte[] bodyBytes = requestTemplate.body();
            if (null == bodyBytes || bodyBytes.length <= 0) {
                // Nothing to encrypt
                return;
            }

            // Read request payload
            String payload = new String(bodyBytes, StandardCharsets.UTF_8);

            // Encrypt fields & update headers
            String encryptedPayload = encryptPayload(requestTemplate, payload);

            requestTemplate.body(encryptedPayload);
            updateHeader(requestTemplate, "Content-Length", String.valueOf(encryptedPayload.length()));

        } catch (EncryptionException e) {
            throw new EncodeException("Failed to intercept and encrypt request!", e);
        }
    }
}
