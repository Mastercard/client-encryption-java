package com.mastercard.developer.encryption.jwe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

class ByteUtils {
    static byte[] concat(byte[]... byteArrays) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            for (byte[] bytes : byteArrays) {
                if (bytes != null) {
                    baos.write(bytes);
                }
            }

            return baos.toByteArray();
        } catch (IOException var6) {
            throw new IllegalStateException(var6.getMessage(), var6);
        }
    }

    static byte[] subArray(byte[] byteArray, int beginIndex, int length) {
        byte[] subArray = new byte[length];
        System.arraycopy(byteArray, beginIndex, subArray, 0, subArray.length);
        return subArray;
    }

    static int byteLength(int bitLength) {
        return bitLength / 8;
    }
}
