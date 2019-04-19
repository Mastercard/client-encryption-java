package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionParams;
import com.mastercard.developer.encryption.FieldLevelEncryption;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import feign.RequestTemplate;
import feign.codec.EncodeException;
import feign.codec.Encoder;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

import static com.mastercard.developer.utils.FeignUtils.updateHeader;

/**
 * A Feign encoder for encrypting parts of HTTP payloads.
 */
public class OpenFeignFieldLevelEncryptionEncoder implements Encoder {

    private final FieldLevelEncryptionConfig config;
    private final Encoder delegate;

    public OpenFeignFieldLevelEncryptionEncoder(FieldLevelEncryptionConfig config, Encoder delegate) {
        this.config = config;
        this.delegate = delegate;
    }

    @Override
    public void encode(Object object, Type type, RequestTemplate requestTemplate) {
        // Call the regular encoder
        delegate.encode(object, type, requestTemplate);

        try {
            // Check request actually has a payload
            byte[] bodyBytes = requestTemplate.body();
            if (null == bodyBytes || bodyBytes.length <= 0) {
                // Nothing to encrypt
                return ;
            }

            // Read request payload
            String payload = new String(bodyBytes, StandardCharsets.UTF_8);

            // Encrypt fields & update headers
            String encryptedPayload;
            if (config.useHttpHeaders()) {
                // Generate encryption params and add them as HTTP headers
                FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);
                updateHeader(requestTemplate, config.getIvHeaderName(), params.getIvValue());
                updateHeader(requestTemplate, config.getEncryptedKeyHeaderName(), params.getEncryptedKeyValue());
                updateHeader(requestTemplate, config.getEncryptionCertificateFingerprintHeaderName(), config.getEncryptionCertificateFingerprint());
                updateHeader(requestTemplate, config.getEncryptionKeyFingerprintHeaderName(), config.getEncryptionKeyFingerprint());
                updateHeader(requestTemplate, config.getOaepPaddingDigestAlgorithmHeaderName(), params.getOaepPaddingDigestAlgorithmValue());
                encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config, params);
            } else {
                // Encryption params will be stored in the payload
                encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);
            }
            requestTemplate.body(encryptedPayload);
            updateHeader(requestTemplate, "Content-Length", String.valueOf(encryptedPayload.length()));

        } catch (EncryptionException e) {
            throw new EncodeException("Failed to intercept and encrypt request!", e);
        }
    }
}
