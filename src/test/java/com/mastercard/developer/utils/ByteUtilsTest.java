package com.mastercard.developer.utils;

import org.junit.Assert;
import org.junit.Test;

public class ByteUtilsTest {

    @Test
    public void testConcat() {
        Assert.assertEquals(2, ByteUtils.concat(new byte[1], new byte[1]).length);
        Assert.assertEquals("AAA=", EncodingUtils.base64Encode(ByteUtils.concat(new byte[1], new byte[1])));
    }

    @Test
    public void testByteLength() {
        Assert.assertEquals(32, ByteUtils.byteLength(new byte[256].length));
    }

    @Test
    public void testSubArray() {
        Assert.assertEquals(10, ByteUtils.subArray(new byte[20], 10, 10).length);
        Assert.assertEquals("AA==", EncodingUtils.base64Encode(ByteUtils.subArray(new byte[20], 0, 1)));
    }
}
