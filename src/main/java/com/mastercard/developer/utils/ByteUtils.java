package com.mastercard.developer.utils;

import java.nio.ByteBuffer;

public class ByteUtils {

    private ByteUtils() {
        // Nothing to do here
    }

    public static byte[] concat(byte[] array1, byte[] array2) {
        return ByteBuffer.allocate(array1.length + array2.length)
                .put(array1)
                .put(array2)
                .array();
    }

    public static byte[] subArray(byte[] byteArray, int beginIndex, int length) {
        byte[] subArray = new byte[length];
        System.arraycopy(byteArray, beginIndex, subArray, 0, subArray.length);
        return subArray;
    }

    public static int byteLength(int bitLength) {
        return bitLength / 8;
    }
}
