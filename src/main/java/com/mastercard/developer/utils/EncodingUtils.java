package com.mastercard.developer.utils;

import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;

import java.util.Base64;

public class EncodingUtils {

    private EncodingUtils() {
    }

    public static String encodeBytes(byte[] bytes, FieldLevelEncryptionConfig.FieldValueEncoding encoding) {
        return encoding == FieldLevelEncryptionConfig.FieldValueEncoding.HEX ? hexEncode(bytes) : base64Encode(bytes);
    }

    public static byte[] decodeValue(String value, FieldLevelEncryptionConfig.FieldValueEncoding encoding) {
        return encoding == FieldLevelEncryptionConfig.FieldValueEncoding.HEX ? hexDecode(value) : base64Decode(value);
    }

    static String hexEncode(byte[] bytes) {
        if (null == bytes) {
            throw new IllegalArgumentException("Can't hex encode a null value!");
        }
        StringBuilder stringBuilder = new StringBuilder(bytes.length * 2);
        for (byte b: bytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    static byte[] hexDecode(String value) {
        if (null == value) {
            throw new IllegalArgumentException("Can't hex decode a null value!");
        }
        if ("".equals(value)) {
            return new byte[0];
        }
        if (!value.matches("\\p{XDigit}+")) {
            throw new IllegalArgumentException("The provided value is not an hex string!");
        }
        int length = value.length();
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(value.charAt(i),16) << 4) + Character.digit(value.charAt(i + 1),16));
        }
        return bytes;
    }

    public static byte[] base64Decode(String value) {
        if (null == value) {
            throw new IllegalArgumentException("Can't base64 decode a null value!");
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (Exception ex) {
            return Base64.getUrlDecoder().decode(value);
        }
    }

    static String base64Encode(byte[] bytes) {
        if (null == bytes) {
            throw new IllegalArgumentException("Can't base64 encode a null value!");
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * BASE64URL as per https://datatracker.ietf.org/doc/html/rfc7515#appendix-C
     */
    public static String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
