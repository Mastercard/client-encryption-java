package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.*;
import feign.Response;
import feign.codec.Decoder;

import static com.mastercard.developer.utils.FeignUtils.readHeader;
import static com.mastercard.developer.utils.FeignUtils.removeHeader;

/**
 * A Feign decoder for decrypting parts of HTTP payloads.
 */
public class OpenFeignFieldLevelEncryptionDecoder extends OpenFeignDecoderExecutor {

    private final FieldLevelEncryptionConfig config;

    public OpenFeignFieldLevelEncryptionDecoder(EncryptionConfig config, Decoder delegate) {
        super(delegate);
        this.config = (FieldLevelEncryptionConfig) config;
    }

    @Override
    protected String decryptPayload(Response response, String responsePayload) throws EncryptionException {
        if (config.useHttpHeaders()) {
            // Read encryption params from HTTP headers and delete headers
            String ivValue = readHeader(response, config.getIvHeaderName());
            String oaepPaddingDigestAlgorithmValue = readHeader(response, config.getOaepPaddingDigestAlgorithmHeaderName());
            String encryptedKeyValue = readHeader(response, config.getEncryptedKeyHeaderName());
            FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivValue, encryptedKeyValue, oaepPaddingDigestAlgorithmValue, config);
            return FieldLevelEncryption.decryptPayload(responsePayload, config, params);
        } else {
            // Encryption params are stored in the payload
            return FieldLevelEncryption.decryptPayload(responsePayload, config);
        }
    }

    @Override
    protected Response removeHeaders(Response response) {
        if (config.useHttpHeaders()) {
            response = removeHeader(response, config.getIvHeaderName());
            response = removeHeader(response, config.getOaepPaddingDigestAlgorithmHeaderName());
            response = removeHeader(response, config.getEncryptedKeyHeaderName());
            response = removeHeader(response, config.getEncryptionCertificateFingerprintHeaderName());
            return removeHeader(response, config.getEncryptionKeyFingerprintHeaderName());
        }
        return response;
    }
}
