package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.*;
import feign.RequestTemplate;
import feign.codec.Encoder;

import static com.mastercard.developer.utils.FeignUtils.updateHeader;

/**
 * A Feign encoder for encrypting parts of HTTP payloads.
 */
public class OpenFeignFieldLevelEncryptionEncoder extends OpenFeignEncoderExecutor {

    private final FieldLevelEncryptionConfig config;

    public OpenFeignFieldLevelEncryptionEncoder(EncryptionConfig config, Encoder delegate) {
        super(delegate);
        this.config = (FieldLevelEncryptionConfig) config;
    }

    @Override
    protected String encryptPayload(RequestTemplate requestTemplate, String requestPayload) throws EncryptionException {
        if (config.useHttpHeaders()) {
            // Generate encryption params and add them as HTTP headers
            FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);
            updateHeader(requestTemplate, config.getIvHeaderName(), params.getIvValue());
            updateHeader(requestTemplate, config.getEncryptedKeyHeaderName(), params.getEncryptedKeyValue());
            updateHeader(requestTemplate, config.getEncryptionCertificateFingerprintHeaderName(), config.getEncryptionCertificateFingerprint());
            updateHeader(requestTemplate, config.getEncryptionKeyFingerprintHeaderName(), config.getEncryptionKeyFingerprint());
            updateHeader(requestTemplate, config.getOaepPaddingDigestAlgorithmHeaderName(), params.getOaepPaddingDigestAlgorithmValue());
            return FieldLevelEncryption.encryptPayload(requestPayload, config, params);
        } else {
            // Encryption params will be stored in the payload
            return FieldLevelEncryption.encryptPayload(requestPayload, config);
        }
    }
}
